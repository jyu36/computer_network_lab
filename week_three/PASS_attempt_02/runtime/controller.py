"""OpenFlow 1.3 learning switch with observable state and barrier sync."""

import json
import os
import re

from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, packet
from ryu.ofproto import ofproto_v1_3
from webob import Response


class _Synchronization:
    def __init__(self, switches):
        self.switches = switches
        self.pending = set()
        self.event = hub.Event()
        self.signalled = False
        self.failure = None

    def wake(self):
        if not self.signalled:
            self.signalled = True
            self.event.set()

    def fail(self, status, message):
        self.failure = (status, message)
        self.wake()


class RainController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}
    SYNC_TIMEOUT = 10.0
    FORWARDING_COOKIE = 1
    POLICY_COOKIE = 2

    def _invalidate_destination(self, datapath, destination):
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        # Only cached forwarding entries carry this cookie. A non-strict
        # destination match covers every ingress port without touching the
        # higher-priority policy drops or the table-miss entry.
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=0, command=ofp.OFPFC_DELETE,
            cookie=self.FORWARDING_COOKIE, cookie_mask=0xffffffffffffffff,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            match=parser.OFPMatch(eth_dst=destination)))

    def __init__(self, *args, **kwargs):
        super(RainController, self).__init__(*args, **kwargs)
        self._lock = hub.Semaphore(1)
        self._policy_lock = hub.Semaphore(1)
        self._connection_policy = {}
        self._switches = {}
        self._learned = {}
        configured = json.loads(os.environ.get('RAIN_BLOCKED', '[]'))
        if not isinstance(configured, list) or any(
                not isinstance(mac, str) or
                re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac)
                is None for mac in configured):
            raise ValueError('RAIN_BLOCKED must be a JSON array of MAC strings')
        self._blocked = frozenset(mac.lower() for mac in configured)
        self._errors = []
        self._syncs = set()
        self._barriers = {}
        kwargs['wsgi'].register(RainHTTP, {'rain': self})

    def _fail_connection_syncs(self, datapath):
        for sync in self._syncs:
            if sync.switches.get(datapath.id) is datapath:
                sync.fail(503, 'A required switch disconnected')

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change(self, ev):
        datapath = ev.datapath
        with self._lock:
            if ev.state == MAIN_DISPATCHER:
                previous = self._switches.get(datapath.id)
                if previous is not None and previous is not datapath:
                    self._fail_connection_syncs(previous)
                if previous is not datapath:
                    # Features may have run before a concurrent policy update.
                    # Reconcile before exposing this connection as ready.
                    self._apply_policy(datapath, self._blocked)
                    self._switches[datapath.id] = datapath
                    self._learned[datapath.id] = {}
            elif ev.state == DEAD_DISPATCHER:
                self._fail_connection_syncs(datapath)
                self._connection_policy.pop(datapath, None)
                if self._switches.get(datapath.id) is datapath:
                    del self._switches[datapath.id]
                    self._learned.pop(datapath.id, None)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                         ofp.OFPCML_NO_BUFFER)]
        instructions = [parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        with self._lock:
            # Drops outrank all forwarding entries. Remember the policy on
            # this connection so MAIN can reconcile updates made during setup.
            self._apply_policy(datapath, self._blocked)
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath, table_id=0, priority=0,
                match=parser.OFPMatch(), instructions=instructions,
                idle_timeout=0, hard_timeout=0))

    def _apply_policy(self, datapath, blocked):
        """Queue a policy delta while holding the controller state lock."""
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        previous = self._connection_policy.get(datapath, frozenset())
        for destination in sorted(blocked - previous):
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath, table_id=0, priority=2,
                cookie=self.POLICY_COOKIE,
                match=parser.OFPMatch(eth_dst=destination),
                instructions=[], idle_timeout=0, hard_timeout=0))
        for destination in sorted(previous - blocked):
            # Strict deletion removes only our destination drop. Cached
            # forwarding survives unblocking, including movement invalidations.
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath, table_id=0, priority=2,
                command=ofp.OFPFC_DELETE_STRICT,
                cookie=self.POLICY_COOKIE, cookie_mask=0xffffffffffffffff,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                match=parser.OFPMatch(eth_dst=destination)))
        self._connection_policy[datapath] = blocked

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        try:
            if not msg.data or len(msg.data) < 14:
                return
            decoded = packet.Packet(msg.data)
            eth = decoded.get_protocol(ethernet.ethernet)
            if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            if eth.ethertype not in (ether_types.ETH_TYPE_ARP,
                                     ether_types.ETH_TYPE_IP):
                return
            in_port = msg.match.get('in_port')
            if in_port is None:
                return
        except (ValueError, TypeError, IndexError, KeyError, AttributeError):
            return

        with self._lock:
            if self._switches.get(datapath.id) is not datapath:
                return
            learned = self._learned[datapath.id]
            source = eth.src.lower()
            previous_port = learned.get(source)
            if previous_port is not None and previous_port != int(in_port):
                # Queue invalidation under the same lock as the observation.
                # A sync requested after status exposes the new location will
                # therefore put its barrier after this required switch update.
                self._invalidate_destination(datapath, source)
            learned[source] = int(in_port)
            destination = eth.dst.lower()
            # Learn the observed source even if the destination is blocked,
            # but never release a blocked frame or cache a forwarding rule.
            if destination in self._blocked:
                return
            out_port = learned.get(destination, ofp.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofp.OFPP_FLOOD and out_port != in_port:
                instructions = [parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS, actions)]
                datapath.send_msg(parser.OFPFlowMod(
                    datapath=datapath, table_id=0, priority=1,
                    cookie=self.FORWARDING_COOKIE,
                    match=parser.OFPMatch(in_port=in_port, eth_dst=destination),
                    instructions=instructions, idle_timeout=0, hard_timeout=0))
            # The flow modification never consumes the Packet-In buffer. The
            # Packet-Out alone consumes it, or carries bytes for NO_BUFFER.
            data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
            datapath.send_msg(parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=data))

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def openflow_error(self, ev):
        msg = ev.msg
        with self._lock:
            self._errors.append({'type': int(msg.type),
                                 'code': int(msg.code),
                                 'xid': int(msg.xid)})
            for sync in self._syncs:
                sync.fail(500, 'An OpenFlow error was recorded')
        self.logger.error('OpenFlow error: type=%s code=%s xid=%s',
                          msg.type, msg.code, msg.xid)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply(self, ev):
        msg = ev.msg
        key = (msg.datapath, msg.xid)
        with self._lock:
            sync = self._barriers.pop(key, None)
            if sync is None:
                return
            sync.pending.discard(key)
            if not sync.pending:
                sync.wake()

    def status(self):
        with self._lock:
            return {
                'switches': sorted(self._switches),
                'learned': {str(dpid): dict(locations)
                            for dpid, locations in self._learned.items()},
                'blocked': sorted(self._blocked),
                'errors': [dict(error) for error in self._errors],
            }

    def _start_sync(self):
        """Register and queue barriers under the state lock."""
        sync = _Synchronization(dict(self._switches))
        self._syncs.add(sync)
        requests = []
        for datapath in sync.switches.values():
            request = datapath.ofproto_parser.OFPBarrierRequest(datapath)
            datapath.set_xid(request)
            key = (datapath, request.xid)
            sync.pending.add(key)
            self._barriers[key] = sync
            requests.append((datapath, request))
        try:
            for datapath, request in requests:
                datapath.send_msg(request)
        except Exception:
            self.logger.exception('Could not send synchronization barrier')
            sync.fail(503, 'Could not send a required barrier')
        if self._errors:
            sync.fail(500, 'An OpenFlow error was recorded')
        return sync

    def synchronize(self):
        with self._lock:
            if not self._switches:
                return 503, {'complete': False, 'error': 'No switch connected'}
            sync = self._start_sync()
        return self._wait_sync(sync)

    def replace_policy(self, blocked):
        # Serialize replacements through their acknowledgments, but release the
        # state lock while waiting so OpenFlow handlers continue processing.
        with self._policy_lock:
            with self._lock:
                if not self._switches:
                    return 503, {'complete': False,
                                 'error': 'No switch connected'}
                self._blocked = blocked
                try:
                    for datapath in self._switches.values():
                        self._apply_policy(datapath, blocked)
                except Exception:
                    self.logger.exception('Could not send policy update')
                    return 503, {'complete': False,
                                 'error': 'Could not send policy update'}
                # The policy decision, Flow-Mods, and barriers are ordered in
                # one critical section shared with Packet-In and movement.
                sync = self._start_sync()
            return self._wait_sync(sync)

    def _wait_sync(self, sync):
        # WSGI greenlets yield here; OpenFlow event handlers never wait on us.
        try:
            sync.event.wait(timeout=self.SYNC_TIMEOUT)
            with self._lock:
                for dpid, datapath in sync.switches.items():
                    if self._switches.get(dpid) is not datapath:
                        sync.fail(503, 'A required switch disconnected')
                        break
                if sync.failure is not None:
                    status, message = sync.failure
                    return status, {'complete': False, 'error': message}
                if self._errors:
                    return 500, {'complete': False,
                                 'error': 'An OpenFlow error was recorded'}
                if sync.pending:
                    return 504, {'complete': False,
                                 'error': 'Timed out waiting for Barrier Replies'}
                return 200, {'complete': True}
        finally:
            with self._lock:
                self._syncs.discard(sync)
                for key in sync.pending:
                    if self._barriers.get(key) is sync:
                        del self._barriers[key]


class RainHTTP(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RainHTTP, self).__init__(req, link, data, **config)
        self.rain = data['rain']

    @staticmethod
    def _json(status, body):
        return Response(status=status, content_type='application/json',
                        body=json.dumps(body).encode('utf-8'))

    @route('rain_status', '/rain/status', methods=['GET'])
    def status(self, req, **kwargs):
        return self._json(200, self.rain.status())

    @route('rain_sync', '/rain/sync', methods=['POST'])
    def sync(self, req, **kwargs):
        status, body = self.rain.synchronize()
        return self._json(status, body)

    @route('rain_policy', '/rain/policy', methods=['PUT'])
    def policy(self, req, **kwargs):
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError('Duplicate JSON key')
                result[key] = value
            return result

        try:
            body = json.loads(req.body, object_pairs_hook=unique_object)
            if not isinstance(body, dict) or set(body) != {'blocked'}:
                raise ValueError('Expected exactly the blocked key')
            addresses = body['blocked']
            if not isinstance(addresses, list) or any(
                    not isinstance(mac, str) or
                    re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac)
                    is None for mac in addresses):
                raise ValueError('Expected a list of MAC address strings')
            blocked = frozenset(mac.lower() for mac in addresses)
        except (ValueError, TypeError, UnicodeError):
            return self._json(400, {'complete': False,
                                    'error': 'Invalid destination policy'})
        status, body = self.rain.replace_policy(blocked)
        return self._json(status, body)
