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
    FORWARD_COOKIE = 0x5241494e01
    POLICY_PRIORITY = 100
    MAC_PATTERN = re.compile(r'[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}')

    def __init__(self, *args, **kwargs):
        super(LearningController, self).__init__(*args, **kwargs)
        self._lock = hub.Semaphore(1)
        self._policy_lock = hub.Semaphore(1)
        self._blocked = self._validate_addresses(
            json.loads(os.environ.get('RAIN_BLOCKED', '[]')))
        self._switches = {}
        self._learned = {}
        self._errors = []
        self._syncs = []
        kwargs['wsgi'].register(RainAPI, {'controller': self})

    @classmethod
    def _validate_addresses(cls, addresses):
        if not isinstance(addresses, list):
            raise ValueError('blocked must be a list of MAC strings')
        if any(not isinstance(address, str)
               or cls.MAC_PATTERN.fullmatch(address) is None
               for address in addresses):
            raise ValueError('each destination must be a six-byte MAC address')
        return {address.lower() for address in addresses}

    def _policy_rule(self, dp, address, remove=False):
        parser, ofp = dp.ofproto_parser, dp.ofproto
        if remove:
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, table_id=0, command=ofp.OFPFC_DELETE_STRICT,
                priority=self.POLICY_PRIORITY,
                match=parser.OFPMatch(eth_dst=address),
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))
        else:
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, table_id=0, priority=self.POLICY_PRIORITY,
                match=parser.OFPMatch(eth_dst=address), instructions=[],
                idle_timeout=0, hard_timeout=0))

    def _forget_destination(self, dp, address):
        # Restrict deletion to our forwarding rules; retain policy and miss rules.
        parser, ofp = dp.ofproto_parser, dp.ofproto
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, table_id=0, command=ofp.OFPFC_DELETE,
            cookie=self.FORWARD_COOKIE, cookie_mask=0xffffffffffffffff,
            match=parser.OFPMatch(eth_dst=address),
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))

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
            dp.send_msg(parser.OFPFlowMod(
                datapath=dp, table_id=0, priority=0,
                match=parser.OFPMatch(), instructions=instructions,
                idle_timeout=0, hard_timeout=0))

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
                    for address in sorted(self._blocked):
                        self._policy_rule(dp, address)
                    # Include a joining connection in policy acknowledgement.
                    for job in self._syncs:
                        if job.get('policy'):
                            job['required'][dp.id] = dp
                            self._send_barrier(job, dp)
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
                self._forget_destination(dp, source)
            # Observe sources even when the destination policy drops the frame.
            if destination in self._blocked:
                return
            out_port = locations.get(destination, ofp.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofp.OFPP_FLOOD and out_port != in_port:
                instructions = [parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS, actions)]
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp, table_id=0, priority=1,
                    cookie=self.FORWARD_COOKIE,
                    match=parser.OFPMatch(in_port=in_port, eth_dst=destination),
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

    def _send_barrier(self, job, dp):
        # Caller holds the state lock.
        try:
            request = dp.ofproto_parser.OFPBarrierRequest(dp)
            dp.set_xid(request)
            job['pending'][dp.id] = (dp, request.xid)
            dp.send_msg(request)
        except Exception:
            job['failure'] = 'could not send required barrier'

    def _start_sync(self, policy=False):
        # Caller holds the state lock, including across preceding Flow-Mods.
        job = {'required': dict(self._switches), 'pending': {},
               'failure': None, 'policy': policy}
        if self._errors:
            job['failure'] = 'OpenFlow error recorded'
        self._syncs.append(job)
        for dp in job['required'].values():
            self._send_barrier(job, dp)
        return job

    def synchronize(self):
        with self._lock:
            if not self._switches:
                return 503, {'complete': False, 'error': 'no switch connected'}
            job = self._start_sync()
        return self._wait_sync(job)

    def replace_policy(self, blocked):
        # Serialize replacements through acknowledgement, while yielding the
        # state lock to OpenFlow handlers and read-only HTTP requests.
        with self._policy_lock:
            with self._lock:
                if not self._switches:
                    return 503, {'complete': False, 'error': 'no switch connected'}
                previous = self._blocked
                self._blocked = set(blocked)
                failure = None
                try:
                    for dp in self._switches.values():
                        for address in sorted(blocked - previous):
                            self._policy_rule(dp, address)
                        for address in sorted(previous - blocked):
                            self._policy_rule(dp, address, remove=True)
                except Exception:
                    failure = 'could not send policy updates'
                job = self._start_sync(policy=True)
                if failure:
                    job['failure'] = failure
            return self._wait_sync(job)

    def _wait_sync(self, job):
        # WSGI greenlet only: never wait inside an OpenFlow event handler.
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
            if not isinstance(body, dict) or set(body) != {'blocked'}:
                raise ValueError('expected exactly the blocked key')
            blocked = self.controller._validate_addresses(body['blocked'])
        except (ValueError, TypeError, UnicodeError):
            return self._json(400, {'complete': False,
                                    'error': 'invalid destination policy'})
        status, body = self.controller.replace_policy(blocked)
        return self._json(status, body)
