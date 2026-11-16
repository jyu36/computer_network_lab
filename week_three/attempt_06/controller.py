"""OpenFlow 1.3 learning switch with observed status and barrier synchronization."""

import json

from webob import Response
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, packet
from ryu.ofproto import ofproto_v1_3


class _Synchronization:
    def __init__(self, datapaths):
        self.datapaths = dict(datapaths)
        self.pending = set()
        self.event = hub.Event()
        self.failure = None
        self.complete = False


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}
    SYNC_TIMEOUT = 10

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        # Both WSGI greenlets and OpenFlow handlers use this cooperative lock.
        self._lock = hub.Semaphore(1)
        self._switches = {}
        self._learned = {}
        self._errors = []
        self._syncs = set()
        self._barriers = {}
        kwargs['wsgi'].register(RainAPI, {'switch_app': self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                         ofp.OFPCML_NO_BUFFER)]
        instructions = [parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(
            datapath=dp, priority=0, match=parser.OFPMatch(),
            idle_timeout=0, hard_timeout=0, instructions=instructions))

    def _fail_sync(self, sync, status):
        # Called only with the state lock held. Failure cannot be undone by replies.
        if sync.failure is None:
            sync.failure = status
        sync.complete = False
        for key in list(sync.pending):
            if self._barriers.get(key) is sync:
                del self._barriers[key]
        sync.pending.clear()
        sync.event.set()

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change(self, ev):
        dp = ev.datapath
        with self._lock:
            if ev.state == MAIN_DISPATCHER:
                old = self._switches.get(dp.id)
                if old is not dp:
                    if old is not None:
                        for sync in list(self._syncs):
                            if sync.datapaths.get(dp.id) is old:
                                self._fail_sync(sync, 503)
                    self._switches[dp.id] = dp
                    self._learned[dp.id] = {}
            elif self._switches.get(dp.id) is dp:
                del self._switches[dp.id]
                self._learned.pop(dp.id, None)
                for sync in list(self._syncs):
                    if sync.datapaths.get(dp.id) is dp:
                        self._fail_sync(sync, 503)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        # Packet parsing may reject malformed frames. Never learn from LLDP.
        try:
            if not msg.data or len(msg.data) < 14:
                return
            frame = packet.Packet(msg.data)
            eth = frame.get_protocol(ethernet.ethernet)
            in_port = msg.match.get('in_port')
            if eth is None or in_port is None:
                return
            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            # A multicast/broadcast source is not a learnable host location.
            if int(eth.src.split(':')[0], 16) & 1:
                return
        except (ValueError, TypeError, IndexError, AttributeError):
            return

        with self._lock:
            if self._switches.get(dp.id) is not dp:
                return
            locations = self._learned[dp.id]
            locations[eth.src] = int(in_port)
            out_port = locations.get(eth.dst, ofp.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            buffered = msg.buffer_id != ofp.OFP_NO_BUFFER

            if out_port != ofp.OFPP_FLOOD and out_port != in_port:
                instructions = [parser.OFPInstructionActions(
                    ofp.OFPIT_APPLY_ACTIONS, actions)]
                flow_args = dict(
                    datapath=dp, priority=1,
                    match=parser.OFPMatch(in_port=in_port, eth_dst=eth.dst),
                    idle_timeout=0, hard_timeout=0,
                    instructions=instructions)
                if buffered:
                    # Applying this FlowMod also forwards the buffered trigger.
                    flow_args['buffer_id'] = msg.buffer_id
                dp.send_msg(parser.OFPFlowMod(**flow_args))
                if buffered:
                    return

            dp.send_msg(parser.OFPPacketOut(
                datapath=dp, buffer_id=msg.buffer_id, in_port=in_port,
                actions=actions, data=None if buffered else msg.data))

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def openflow_error(self, ev):
        msg = ev.msg
        with self._lock:
            self._errors.append({'type': int(msg.type), 'code': int(msg.code),
                                 'xid': int(msg.xid)})
            for sync in list(self._syncs):
                self._fail_sync(sync, 500)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply(self, ev):
        msg = ev.msg
        key = (msg.datapath.id, msg.xid)
        with self._lock:
            sync = self._barriers.get(key)
            if sync is None:
                return
            if sync.datapaths.get(msg.datapath.id) is not msg.datapath:
                return
            del self._barriers[key]
            sync.pending.discard(key)
            if not sync.pending and sync.failure is None:
                sync.complete = True
                sync.event.set()

    def status(self):
        with self._lock:
            return {
                'switches': sorted(self._switches),
                'learned': {str(dpid): dict(self._learned[dpid])
                            for dpid in sorted(self._switches)},
                'blocked': [],
                'errors': [dict(error) for error in self._errors],
            }

    def synchronize(self):
        # This method runs in the WSGI request greenlet, never an OF event handler.
        with self._lock:
            if not self._switches:
                return 503, {'complete': False}
            sync = _Synchronization(self._switches)
            self._syncs.add(sync)
            requests = []
            try:
                # Register every XID before sending any request.
                for dpid, dp in sync.datapaths.items():
                    request = dp.ofproto_parser.OFPBarrierRequest(dp)
                    dp.set_xid(request)
                    key = (dpid, request.xid)
                    sync.pending.add(key)
                    self._barriers[key] = sync
                    requests.append((dp, request))
                for dp, request in requests:
                    dp.send_msg(request)
                # Recorded OF errors remain visible and invalidate synchronization.
                if self._errors:
                    self._fail_sync(sync, 500)
            except Exception:
                self.logger.exception('Unable to send synchronization barriers')
                self._fail_sync(sync, 503)

        try:
            # Waiting yields to the event loop so replies and disconnects can run.
            with hub.Timeout(self.SYNC_TIMEOUT, False):
                sync.event.wait()
            with self._lock:
                if sync.failure is not None:
                    return sync.failure, {'complete': False}
                if any(self._switches.get(dpid) is not dp
                       for dpid, dp in sync.datapaths.items()):
                    return 503, {'complete': False}
                if sync.complete and not sync.pending and not self._errors:
                    return 200, {'complete': True}
                return 504, {'complete': False}
        finally:
            with self._lock:
                self._syncs.discard(sync)
                for key in list(sync.pending):
                    if self._barriers.get(key) is sync:
                        del self._barriers[key]
                sync.pending.clear()


class RainAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RainAPI, self).__init__(req, link, data, **config)
        self.switch_app = data['switch_app']

    @staticmethod
    def _json(status, value):
        return Response(status=status, content_type='application/json',
                        body=json.dumps(value).encode('utf-8'))

    @route('rain_status', '/rain/status', methods=['GET'])
    def get_status(self, req, **kwargs):
        return self._json(200, self.switch_app.status())

    @route('rain_sync', '/rain/sync', methods=['POST'])
    def post_sync(self, req, **kwargs):
        status, result = self.switch_app.synchronize()
        return self._json(status, result)
