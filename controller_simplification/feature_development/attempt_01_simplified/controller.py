"""OpenFlow 1.3 learning switch with status and synchronization interfaces."""

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
    FORWARD_COOKIE = 0x5241494e00000001
    POLICY_COOKIE = 0x5241494e00000002

    @staticmethod
    def _normalize_blocked(value):
        if not isinstance(value, list):
            raise ValueError('blocked must be a list')
        normalized = set()
        for address in value:
            if (not isinstance(address, str) or
                    re.fullmatch(r'[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}',
                                 address) is None):
                raise ValueError('invalid destination MAC address')
            normalized.add(address.lower())
        return normalized

    def __init__(self, *args, **kwargs):
        super(LearningController, self).__init__(*args, **kwargs)
        self._blocked = self._normalize_blocked(
            json.loads(os.environ.get('RAIN_BLOCKED', '[]')))
        self._policy_lock = hub.Semaphore(1)
        self._lock = hub.Semaphore(1)
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

    def _install_flow(self, dp, priority, match, actions, cookie=0):
        # Caller holds the state lock to order flow updates with barriers.
        parser, ofp = dp.ofproto_parser, dp.ofproto
        instructions = [parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, table_id=0, priority=priority, match=match,
            cookie=cookie,
            instructions=instructions, idle_timeout=0, hard_timeout=0))

    def _delete_flows(self, dp, cookie, match):
        # Cookie filtering keeps movement invalidation away from policy drops.
        parser, ofp = dp.ofproto_parser, dp.ofproto
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, table_id=0, command=ofp.OFPFC_DELETE,
            cookie=cookie, cookie_mask=0xffffffffffffffff,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, match=match))

    def _install_policy(self, dp, addresses):
        for address in sorted(addresses):
            self._install_flow(dp, 2,
                               dp.ofproto_parser.OFPMatch(eth_dst=address),
                               [], cookie=self.POLICY_COOKIE)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        parser, ofp = dp.ofproto_parser, dp.ofproto
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                         ofp.OFPCML_NO_BUFFER)]
        with self._lock:
            self._install_flow(dp, 0, parser.OFPMatch(), actions)
            self._install_policy(dp, self._blocked)

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
                    self._switches[dp.id] = dp
                    self._learned[dp.id] = {}
                    # Refresh on MAIN too: a PUT may have occurred between
                    # features negotiation and registration of this connection.
                    self._delete_flows(dp, self.FORWARD_COOKIE,
                                       dp.ofproto_parser.OFPMatch())
                    self._delete_flows(dp, self.POLICY_COOKIE,
                                       dp.ofproto_parser.OFPMatch())
                    self._install_policy(dp, self._blocked)
            elif ev.state == DEAD_DISPATCHER:
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
            source, destination = eth.src.lower(), eth.dst.lower()
            previous_port = locations.get(source)
            locations[source] = int(in_port)
            if previous_port is not None and previous_port != in_port:
                self._delete_flows(dp, self.FORWARD_COOKIE,
                                   parser.OFPMatch(eth_dst=source))
            if destination in self._blocked:
                return
            out_port = locations.get(destination, ofp.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofp.OFPP_FLOOD and out_port != in_port:
                self._install_flow(
                    dp, 1, parser.OFPMatch(in_port=in_port, eth_dst=destination),
                    actions, cookie=self.FORWARD_COOKIE)
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

    def _start_sync(self):
        # Caller holds the state lock, ordering barriers after all flow updates.
        required = dict(self._switches)
        job = {'required': required, 'pending': {}, 'failure': None}
        if self._errors:
            job['failure'] = 'OpenFlow error recorded'
        self._syncs.append(job)
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
            job = self._start_sync()
        return self._wait_sync(job)

    def replace_policy(self, blocked):
        # Serialize replacements through acknowledgment so a later PUT cannot
        # undo an earlier policy before its response has completed.
        with self._policy_lock:
            with self._lock:
                if not self._switches:
                    return 503, {'complete': False,
                                 'error': 'no switch connected'}
                old = self._blocked
                self._blocked = set(blocked)
                failure = None
                try:
                    for dp in self._switches.values():
                        self._install_policy(dp, self._blocked - old)
                        for address in sorted(old - self._blocked):
                            self._delete_flows(
                                dp, self.POLICY_COOKIE,
                                dp.ofproto_parser.OFPMatch(eth_dst=address))
                except Exception:
                    failure = 'could not send required policy update'
                job = self._start_sync()
                if failure is not None:
                    job['failure'] = failure
            return self._wait_sync(job)

    def _wait_sync(self, job):
        # Only WSGI request greenlets wait; OpenFlow handlers stay available.
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
            # Reject duplicate object keys rather than silently discard input.
            def unique_object(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError('duplicate JSON key')
                    result[key] = value
                return result

            document = json.loads(req.body.decode('utf-8'),
                                  object_pairs_hook=unique_object)
            if not isinstance(document, dict) or set(document) != {'blocked'}:
                raise ValueError('expected an object with only blocked')
            blocked = self.controller._normalize_blocked(document['blocked'])
        except (ValueError, TypeError, UnicodeError):
            return self._json(400, {'complete': False,
                                    'error': 'invalid policy document'})
        status, body = self.controller.replace_policy(blocked)
        return self._json(status, body)
