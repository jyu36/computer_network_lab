"""OpenFlow 1.3 learning switch with observable state and barrier sync."""

import json
import os
import re
import time

from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import arp, ethernet, ether_types, icmp, ipv4, packet
from ryu.ofproto import ofproto_v1_3


class LearningController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}
    SYNC_TIMEOUT = 10.0
    FORWARDING_COOKIE = 1
    POLICY_COOKIE = 2

    def __init__(self, *args, **kwargs):
        super(LearningController, self).__init__(*args, **kwargs)
        configured = json.loads(os.environ.get('RAIN_BLOCKED', '[]'))
        if not isinstance(configured, list) or any(
                not isinstance(mac, str) or re.fullmatch(
                    r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac) is None
                for mac in configured):
            raise ValueError('RAIN_BLOCKED must be a JSON array of MAC strings')
        self._blocked = frozenset(mac.lower() for mac in configured)
        self._lock = hub.Semaphore(1)
        self._policy_lock = hub.Semaphore(1)
        self._initializing = {}
        self._switches = {}
        self._learned = {}
        self._errors = []
        self._syncs = []
        kwargs['wsgi'].register(RainAPI, {'controller': self})

    def _fail_syncs_for(self, datapath, reason):
        # Caller holds the state lock. Match connection identity, not just DPID.
        for job in self._syncs:
            if job['required'].get(datapath.id) is datapath:
                job['failure'] = reason

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                         ofp.OFPCML_NO_BUFFER)]
        instructions = [parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        with self._lock:
            # Destination-only drops take precedence over cached forwarding.
            # Queue policy updates on this connection before its table miss;
            # subsequent synchronization barriers cover these updates too.
            self._update_policy_rules(dp, frozenset(), self._blocked)
            self._initializing[dp] = self._blocked
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, table_id=0, priority=0,
                match=parser.OFPMatch(), instructions=instructions,
                idle_timeout=0, hard_timeout=0))

    def _update_policy_rules(self, dp, previous, current):
        # Caller holds the state lock. Strict deletion cannot remove cached
        # forwarding or table-miss rules. Existing caches are usable on unblock.
        parser, ofp = dp.ofproto_parser, dp.ofproto
        for destination in sorted(current - previous):
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, table_id=0, priority=2,
                cookie=self.POLICY_COOKIE,
                match=parser.OFPMatch(eth_dst=destination), instructions=[],
                idle_timeout=0, hard_timeout=0))
        for destination in sorted(previous - current):
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, table_id=0, command=ofp.OFPFC_DELETE_STRICT,
                priority=2, cookie=self.POLICY_COOKIE,
                cookie_mask=0xffffffffffffffff,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                match=parser.OFPMatch(eth_dst=destination)))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def switch_state(self, ev):
        dp = ev.datapath
        with self._lock:
            if ev.state == MAIN_DISPATCHER:
                previous = self._switches.get(dp.id)
                if previous is not dp:
                    if previous is not None:
                        self._fail_syncs_for(previous, 'switch connection replaced')
                    # A PUT may have occurred between Features and MAIN.
                    # Reconcile before exposing this connection to requests.
                    previous_policy = self._initializing.pop(dp, frozenset())
                    self._update_policy_rules(dp, previous_policy, self._blocked)
                    self._switches[dp.id] = dp
                    self._learned[dp.id] = {}
            elif ev.state == DEAD_DISPATCHER:
                self._initializing.pop(dp, None)
                self._fail_syncs_for(dp, 'required switch disconnected')
                if self._switches.get(dp.id) is dp:
                    del self._switches[dp.id]
                    self._learned.pop(dp.id, None)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        try:
            if not msg.data or len(msg.data) < 14:
                return
            parsed = packet.Packet(msg.data)
            eth = parsed.get_protocol(ethernet.ethernet)
            if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            if eth.ethertype not in (ether_types.ETH_TYPE_ARP,
                                     ether_types.ETH_TYPE_IP):
                return
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                if parsed.get_protocol(arp.arp) is None:
                    return
            else:
                ip = parsed.get_protocol(ipv4.ipv4)
                if (ip is None or ip.version != 4 or ip.header_length < 5
                        or ip.total_length < ip.header_length * 4
                        or len(msg.data) < 14 + ip.total_length):
                    return
                if ip.proto == 1 and parsed.get_protocol(icmp.icmp) is None:
                    return
            in_port = msg.match.get('in_port')
            if in_port is None:
                return
        except Exception:
            # Parsing untrusted bytes must not terminate event processing.
            return

        parser, ofp = dp.ofproto_parser, dp.ofproto
        with self._lock:
            if self._switches.get(dp.id) is not dp:
                return
            locations = self._learned[dp.id]
            old_port = locations.get(eth.src)
            if old_port is not None and old_port != int(in_port):
                # Invalidate every cached destination path to this source.
                # The cookie confines deletion to forwarding rules, preserving
                # destination policy and table miss rules. Queue the update
                # under the state lock before publishing the new observation,
                # so a later sync barrier covers the movement update.
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp, table_id=0, command=ofp.OFPFC_DELETE,
                    cookie=self.FORWARDING_COOKIE,
                    cookie_mask=0xffffffffffffffff,
                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                    match=parser.OFPMatch(eth_dst=eth.src)))
            locations[eth.src] = int(in_port)
            # Learn observed sources even when either endpoint is blocked.
            # Never forward a blocked destination via Packet-Out or a cache rule.
            if eth.dst.lower() in self._blocked:
                return
            out_port = locations.get(eth.dst, ofp.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofp.OFPP_FLOOD and out_port != in_port:
                instructions = [parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS, actions)]
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp, table_id=0, priority=1,
                    cookie=self.FORWARDING_COOKIE,
                    match=parser.OFPMatch(in_port=in_port, eth_dst=eth.dst),
                    instructions=instructions, idle_timeout=0, hard_timeout=0))
            # The flow update does not consume a buffer. Packet-Out forwards
            # the triggering packet using either its real buffer or its bytes.
            data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
            dp.send_msg(parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions, data=data))

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER])
    def openflow_error(self, ev):
        msg = ev.msg
        with self._lock:
            self._errors.append({'type': int(msg.type), 'code': int(msg.code),
                                 'xid': int(msg.xid)})
            for job in self._syncs:
                job['failure'] = 'OpenFlow error recorded'
        self.logger.error('OpenFlow error: dpid=%s type=%s code=%s xid=%s',
                          msg.datapath.id, msg.type, msg.code, msg.xid)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply(self, ev):
        msg = ev.msg
        with self._lock:
            for job in self._syncs:
                expected = job['pending'].get(msg.datapath.id)
                if expected is not None:
                    dp, xid = expected
                    if dp is msg.datapath and xid == msg.xid:
                        del job['pending'][dp.id]

    def status(self):
        with self._lock:
            return {
                'switches': sorted(self._switches),
                'learned': {str(dpid): dict(self._learned[dpid])
                            for dpid in sorted(self._switches)},
                'blocked': sorted(self._blocked),
                'errors': [dict(error) for error in self._errors],
            }

    def _begin_sync(self, policy=None):
        # Caller holds the state lock, ordering policy changes and barriers
        # with Packet-In decisions and connection state changes.
        required = dict(self._switches)
        job = {'required': required, 'pending': {}, 'failure': None}
        if self._errors:
            job['failure'] = 'OpenFlow error recorded'
        self._syncs.append(job)
        if policy is not None:
            previous = self._blocked
            self._blocked = policy
            for dp in required.values():
                try:
                    self._update_policy_rules(dp, previous, policy)
                except Exception:
                    job['failure'] = 'could not send policy updates'
        for dpid, dp in required.items():
            try:
                request = dp.ofproto_parser.OFPBarrierRequest(dp)
                dp.set_xid(request)
                job['pending'][dpid] = (dp, request.xid)
                dp.send_msg(request)
            except Exception:
                job['failure'] = 'could not send required barrier'
        return job

    def synchronize(self):
        with self._lock:
            if not self._switches:
                return 503, {'complete': False, 'error': 'no switch connected'}
            job = self._begin_sync()
        return self._wait_sync(job)

    def replace_policy(self, blocked):
        # Serialize replacements through their acknowledgments. Only HTTP
        # greenlets take this lock; event handlers remain free to process replies.
        with self._policy_lock:
            with self._lock:
                if not self._switches:
                    return 503, {'complete': False,
                                 'error': 'no switch connected'}
                if self._errors:
                    return 503, {'complete': False,
                                 'error': 'OpenFlow error recorded'}
                job = self._begin_sync(blocked)
            return self._wait_sync(job)

    def _wait_sync(self, job):
        # Run in the WSGI greenlet and yield for asynchronous OpenFlow events.
        required = job['required']
        deadline = time.monotonic() + self.SYNC_TIMEOUT
        try:
            while True:
                with self._lock:
                    if job['failure'] is not None:
                        return 503, {'complete': False,
                                     'error': job['failure']}
                    if any(self._switches.get(dpid) is not dp
                           for dpid, dp in required.items()):
                        return 503, {'complete': False,
                                     'error': 'required switch disconnected'}
                    if not job['pending']:
                        return 200, {'complete': True}
                    if time.monotonic() >= deadline:
                        return 503, {'complete': False,
                                     'error': 'barrier reply timeout'}
                hub.sleep(0.01)
        finally:
            with self._lock:
                # Concurrent sync requests have independent barrier XIDs.
                self._syncs = [active for active in self._syncs
                               if active is not job]


class RainAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RainAPI, self).__init__(req, link, data, **config)
        self.controller = data['controller']

    @staticmethod
    def _json(status, body):
        return Response(status=status, content_type='application/json',
                        charset='utf-8', body=json.dumps(body).encode('utf-8'))

    @route('rain_status', '/rain/status', methods=['GET'])
    def status(self, req, **kwargs):
        return self._json(200, self.controller.status())

    @route('rain_sync', '/rain/sync', methods=['POST'])
    def sync(self, req, **kwargs):
        status, body = self.controller.synchronize()
        return self._json(status, body)

    @route('rain_policy', '/rain/policy', methods=['PUT'])
    def policy(self, req, **kwargs):
        try:
            body = json.loads(req.body)
            if (not isinstance(body, dict) or set(body) != {'blocked'}
                    or not isinstance(body['blocked'], list)
                    or any(not isinstance(mac, str) or re.fullmatch(
                        r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac) is None
                        for mac in body['blocked'])):
                raise ValueError('invalid destination policy')
            blocked = frozenset(mac.lower() for mac in body['blocked'])
        except (ValueError, TypeError, UnicodeError):
            return self._json(400, {'complete': False,
                                    'error': 'expected an object containing only '
                                             'blocked, a list of MAC strings'})
        status, body = self.controller.replace_policy(blocked)
        return self._json(status, body)
