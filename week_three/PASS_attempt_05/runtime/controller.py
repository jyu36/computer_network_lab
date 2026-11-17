"""OpenFlow 1.3 learning switch with observed state and barrier synchronization."""

import json
import os
import re

from ryu.app.wsgi import ControllerBase, Response, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import arp, ethernet, ether_types, icmp, ipv4, packet
from ryu.ofproto import ofproto_v1_3


class _Synchronization:
    def __init__(self, datapaths):
        self.datapaths = dict(datapaths)
        self.pending = set()
        self.done = hub.Event()
        self.failure = None
        self.complete = False


class LearningController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}
    SYNC_TIMEOUT = 10.0
    FORWARDING_COOKIE = 1

    def __init__(self, *args, **kwargs):
        super(LearningController, self).__init__(*args, **kwargs)
        configured = json.loads(os.environ.get("RAIN_BLOCKED", "[]"))
        if not isinstance(configured, list) or any(
                not isinstance(mac, str) or
                re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", mac) is None
                for mac in configured):
            raise ValueError("RAIN_BLOCKED must be a JSON array of MAC addresses")
        self._blocked = frozenset(mac.lower() for mac in configured)
        self._lock = hub.Semaphore(1)
        self._switches = {}
        self._learned = {}
        self._errors = []
        self._syncs = set()
        self._barriers = {}
        self._switch_policies = {}
        self._policy_lock = hub.Semaphore(1)
        kwargs["wsgi"].register(RainAPI, {"controller": self})

    def _finish_locked(self, synchronization, failure=None):
        if synchronization.complete or synchronization.failure is not None:
            return
        synchronization.failure = failure
        synchronization.complete = failure is None
        for key in synchronization.pending:
            self._barriers.pop(key, None)
        synchronization.pending.clear()
        self._syncs.discard(synchronization)
        synchronization.done.set()

    def _fail_switch_syncs_locked(self, datapath):
        for synchronization in list(self._syncs):
            if synchronization.datapaths.get(datapath.id) is datapath:
                self._finish_locked(synchronization, "switch disconnected")

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def switch_state(self, event):
        datapath = event.datapath
        with self._lock:
            if event.state == MAIN_DISPATCHER:
                old = self._switches.get(datapath.id)
                if old is not datapath:
                    if old is not None:
                        self._fail_switch_syncs_locked(old)
                    # Reconcile a policy changed between FEATURES and MAIN.
                    self._apply_policy_locked(datapath, self._blocked)
                    self._switches[datapath.id] = datapath
                    self._learned[datapath.id] = {}
            elif self._switches.get(datapath.id) is datapath:
                del self._switches[datapath.id]
                self._learned.pop(datapath.id, None)
                self._fail_switch_syncs_locked(datapath)
            if event.state == DEAD_DISPATCHER:
                self._switch_policies.pop(datapath, None)

    def _flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        instructions = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        arguments = dict(datapath=datapath, priority=priority,
                         cookie=(self.FORWARDING_COOKIE if priority == 1 else 0),
                         match=match, instructions=instructions,
                         idle_timeout=0, hard_timeout=0)
        if buffer_id is not None:
            arguments["buffer_id"] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**arguments))

    def _invalidate_destination(self, datapath, destination):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        # Limit deletion to this application's cached forwarding entries.
        # Destination policy drops and the table-miss rule keep their cookies.
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=0, command=ofproto.OFPFC_DELETE,
            cookie=self.FORWARDING_COOKIE, cookie_mask=0xffffffffffffffff,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            match=parser.OFPMatch(eth_dst=destination)))

    def _apply_policy_locked(self, datapath, blocked):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        previous = self._switch_policies.get(datapath, frozenset())
        for destination in sorted(blocked - previous):
            self._flow(datapath, 2,
                       parser.OFPMatch(eth_dst=destination), [])
        for destination in sorted(previous - blocked):
            # Delete only the destination-only policy entry, preserving cached
            # forwarding entries and the table-miss rule for unblocked traffic.
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath, table_id=0,
                command=ofproto.OFPFC_DELETE_STRICT, priority=2,
                cookie=0, cookie_mask=0xffffffffffffffff,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                match=parser.OFPMatch(eth_dst=destination)))
        self._switch_policies[datapath] = blocked

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, event):
        datapath = event.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        with self._lock:
            # Destination-only drops override every learned forwarding rule.
            # Queue policy before table-miss traffic can reach the controller.
            self._apply_policy_locked(datapath, self._blocked)
            self._flow(datapath, 0, parser.OFPMatch(), [
                parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                       ofproto.OFPCML_NO_BUFFER)])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, event):
        message = event.msg
        datapath = message.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        try:
            if not message.data or len(message.data) < 14:
                return
            decoded = packet.Packet(message.data)
            frame = decoded.get_protocol(ethernet.ethernet)
            if frame is None or frame.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            if frame.ethertype == ether_types.ETH_TYPE_ARP:
                if decoded.get_protocol(arp.arp) is None:
                    return
            elif frame.ethertype == ether_types.ETH_TYPE_IP:
                ip = decoded.get_protocol(ipv4.ipv4)
                if ip is None or ip.proto != 1:
                    return
                if decoded.get_protocol(icmp.icmp) is None:
                    return
            else:
                return
            in_port = message.match.get("in_port")
            if in_port is None:
                return
        except Exception:
            # Packet decoding is an untrusted-input boundary.
            return

        with self._lock:
            if self._switches.get(datapath.id) is not datapath:
                return
            locations = self._learned[datapath.id]
            previous_port = locations.get(frame.src)
            if previous_port is not None and previous_port != int(in_port):
                # Queue invalidation before status can expose the observation,
                # so a subsequent sync barrier covers every movement update.
                self._invalidate_destination(datapath, frame.src)
            locations[frame.src] = int(in_port)
            # Learn observed sources even when this frame's destination is blocked.
            if frame.dst.lower() in self._blocked:
                return
            destination_port = locations.get(frame.dst)

            out_port = (ofproto.OFPP_FLOOD if destination_port is None
                        else destination_port)
            actions = [parser.OFPActionOutput(out_port)]
            if destination_port is not None and destination_port != in_port:
                match = parser.OFPMatch(in_port=in_port, eth_dst=frame.dst)
                if message.buffer_id != ofproto.OFP_NO_BUFFER:
                    self._flow(datapath, 1, match, actions, message.buffer_id)
                    return
                self._flow(datapath, 1, match, actions)

            data = (message.data if message.buffer_id == ofproto.OFP_NO_BUFFER
                    else None)
            datapath.send_msg(parser.OFPPacketOut(
                datapath=datapath, buffer_id=message.buffer_id,
                in_port=in_port, actions=actions, data=data))

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER])
    def openflow_error(self, event):
        message = event.msg
        with self._lock:
            self._errors.append({"type": int(message.type),
                                 "code": int(message.code),
                                 "xid": int(message.xid)})
            # Errors are retained: a later sync cannot certify failed updates.
            for synchronization in list(self._syncs):
                self._finish_locked(synchronization, "OpenFlow error")

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply(self, event):
        message = event.msg
        key = (message.datapath.id, message.xid)
        with self._lock:
            synchronization = self._barriers.get(key)
            if synchronization is None:
                return
            if synchronization.datapaths.get(message.datapath.id) is not message.datapath:
                return
            self._barriers.pop(key, None)
            synchronization.pending.discard(key)
            if not synchronization.pending:
                self._finish_locked(synchronization)

    def status(self):
        with self._lock:
            return {
                "switches": sorted(self._switches),
                "learned": {str(dpid): dict(self._learned[dpid])
                            for dpid in sorted(self._switches)},
                "blocked": sorted(self._blocked),
                "errors": [dict(error) for error in self._errors],
            }

    def _start_sync_locked(self):
        # Register every expected reply before sending any request. Holding the
        # state lock orders barriers after the updates they are acknowledging.
        synchronization = _Synchronization(self._switches)
        requests = []
        for dpid, datapath in synchronization.datapaths.items():
            request = datapath.ofproto_parser.OFPBarrierRequest(datapath)
            datapath.set_xid(request)
            key = (dpid, request.xid)
            synchronization.pending.add(key)
            self._barriers[key] = synchronization
            requests.append((datapath, request))
        self._syncs.add(synchronization)
        try:
            for datapath, request in requests:
                datapath.send_msg(request)
        except Exception:
            self._finish_locked(synchronization, "barrier request failed")
        return synchronization

    def _wait_sync(self, synchronization):
        # Only the WSGI greenlet waits, with no state lock held. OpenFlow event
        # handlers remain free to process errors, disconnects and barrier replies.
        try:
            synchronization.done.wait(timeout=self.SYNC_TIMEOUT)
        except Exception:
            with self._lock:
                self._finish_locked(synchronization, "barrier wait failed")

        with self._lock:
            if not synchronization.complete and synchronization.failure is None:
                self._finish_locked(synchronization, "barrier reply timeout")
            if synchronization.failure is not None:
                return 503, {"complete": False,
                             "error": synchronization.failure}
            if self._errors:
                return 503, {"complete": False, "error": "OpenFlow error"}
            if any(self._switches.get(dpid) is not datapath
                   for dpid, datapath in synchronization.datapaths.items()):
                return 503, {"complete": False, "error": "switch disconnected"}
            return 200, {"complete": True}

    def synchronize(self):
        with self._lock:
            if not self._switches:
                return 503, {"complete": False, "error": "no switch connected"}
            synchronization = self._start_sync_locked()
        return self._wait_sync(synchronization)

    def replace_policy(self, blocked):
        # Serialize replacements through completion, without holding the state
        # lock while waiting for replies. Packet-In sends also hold that lock.
        with self._policy_lock:
            with self._lock:
                if not self._switches:
                    return 503, {"complete": False,
                                 "error": "no switch connected"}
                if self._errors:
                    return 503, {"complete": False, "error": "OpenFlow error"}
                self._blocked = blocked
                try:
                    for datapath in self._switches.values():
                        self._apply_policy_locked(datapath, blocked)
                except Exception:
                    # Keep the requested active policy on failure; partial
                    # switch updates cannot truthfully be acknowledged or undone.
                    return 503, {"complete": False,
                                 "error": "policy update failed"}
                synchronization = self._start_sync_locked()
            return self._wait_sync(synchronization)


class RainAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RainAPI, self).__init__(req, link, data, **config)
        self.controller = data["controller"]

    @staticmethod
    def _json(status, body):
        return Response(status=status, content_type="application/json",
                        body=json.dumps(body).encode("utf-8"))

    @route("rain_status", "/rain/status", methods=["GET"])
    def get_status(self, req, **kwargs):
        return self._json(200, self.controller.status())

    @route("rain_sync", "/rain/sync", methods=["POST"])
    def post_sync(self, req, **kwargs):
        status, body = self.controller.synchronize()
        return self._json(status, body)

    @route("rain_policy", "/rain/policy", methods=["PUT"])
    def put_policy(self, req, **kwargs):
        try:
            body = json.loads(req.body)
            if (not isinstance(body, dict) or set(body) != {"blocked"}
                    or not isinstance(body["blocked"], list)):
                raise ValueError("expected an object containing only blocked")
            if any(not isinstance(mac, str) or
                   re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", mac)
                   is None for mac in body["blocked"]):
                raise ValueError("blocked must contain MAC address strings")
            blocked = frozenset(mac.lower() for mac in body["blocked"])
        except (ValueError, TypeError, UnicodeError):
            return self._json(400, {"complete": False,
                                    "error": "invalid policy JSON or MAC list"})
        status, body = self.controller.replace_policy(blocked)
        return self._json(status, body)
