"""OpenFlow 1.3 learning switch with observed state and barrier synchronization."""

import json

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

    def __init__(self, *args, **kwargs):
        super(LearningController, self).__init__(*args, **kwargs)
        self._lock = hub.Semaphore(1)
        self._switches = {}
        self._learned = {}
        self._errors = []
        self._syncs = set()
        self._barriers = {}
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
                    self._switches[datapath.id] = datapath
                    self._learned[datapath.id] = {}
            elif self._switches.get(datapath.id) is datapath:
                del self._switches[datapath.id]
                self._learned.pop(datapath.id, None)
                self._fail_switch_syncs_locked(datapath)

    def _flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        instructions = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        arguments = dict(datapath=datapath, priority=priority,
                         match=match, instructions=instructions,
                         idle_timeout=0, hard_timeout=0)
        if buffer_id is not None:
            arguments["buffer_id"] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**arguments))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, event):
        datapath = event.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
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
            locations[frame.src] = int(in_port)
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
                "blocked": [],
                "errors": [dict(error) for error in self._errors],
            }

    def synchronize(self):
        # Register every expected reply before sending any request. The WSGI
        # greenlet waits cooperatively; OpenFlow handlers never wait for replies.
        with self._lock:
            if not self._switches:
                return 503, {"complete": False, "error": "no switch connected"}
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
            synchronization.done.wait(timeout=self.SYNC_TIMEOUT)
        except Exception:
            with self._lock:
                self._finish_locked(synchronization, "barrier request failed")

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
