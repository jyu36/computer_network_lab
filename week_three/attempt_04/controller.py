"""OpenFlow 1.3 learning switch with observable state and barrier sync."""

import json
import struct

from eventlet.event import Event
from eventlet.semaphore import Semaphore
from eventlet.timeout import Timeout
from webob import Response

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls,
)
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib.packet import ethernet, ether_types, packet
from ryu.ofproto import ofproto_v1_3


class SyncOperation:
    def __init__(self, switches):
        # Keep connection objects, not just DPIDs: reconnecting is not a reply.
        self.switches = dict(switches)
        self.pending = set()
        self.done = Event()
        self.result = None


class LearningController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}
    SYNC_TIMEOUT = 10.0

    def __init__(self, *args, **kwargs):
        super(LearningController, self).__init__(*args, **kwargs)
        self._lock = Semaphore(1)
        self._switches = {}
        self._learned = {}
        self._errors = []
        self._syncs = set()
        self._barriers = {}
        kwargs['wsgi'].register(RainHTTP, {'controller': self})

    def _finish_sync(self, operation, status, body):
        """Caller holds the lock; wake only this operation's HTTP greenlet."""
        if operation.result is not None:
            return
        operation.result = (status, body)
        self._syncs.discard(operation)
        for key in operation.pending:
            self._barriers.pop(key, None)
        operation.pending.clear()
        operation.done.send(operation.result)

    def _fail_connection_syncs(self, datapath):
        for operation in list(self._syncs):
            if operation.switches.get(datapath.id) is datapath:
                self._finish_sync(operation, 503, {
                    'complete': False, 'error': 'Required switch disconnected',
                })

    def _connect(self, datapath):
        previous = self._switches.get(datapath.id)
        if previous is datapath:
            return
        if previous is not None:
            self._fail_connection_syncs(previous)
        self._switches[datapath.id] = datapath
        self._learned[datapath.id] = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        datapath = ev.msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        with self._lock:
            self._connect(datapath)
            actions = [parser.OFPActionOutput(
                ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
            self._add_flow(datapath, 0, parser.OFPMatch(), actions)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change(self, ev):
        datapath = ev.datapath
        with self._lock:
            if ev.state == MAIN_DISPATCHER:
                self._connect(datapath)
            elif ev.state == DEAD_DISPATCHER:
                self._fail_connection_syncs(datapath)
                if self._switches.get(datapath.id) is datapath:
                    del self._switches[datapath.id]
                    self._learned.pop(datapath.id, None)

    @staticmethod
    def _add_flow(datapath, priority, match, actions):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        instructions = [parser.OFPInstructionActions(
            ofp.OFPIT_APPLY_ACTIONS, actions)]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=0, priority=priority,
            idle_timeout=0, hard_timeout=0, match=match,
            instructions=instructions, buffer_id=ofp.OFP_NO_BUFFER))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofp = datapath.ofproto
        parser = datapath.ofproto_parser
        try:
            if not msg.data or len(msg.data) < 14:
                return
            frame = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
            if frame is None or frame.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            in_port = msg.match['in_port']
        except (ValueError, TypeError, KeyError, IndexError, AttributeError,
                struct.error):
            return

        with self._lock:
            if self._switches.get(datapath.id) is not datapath:
                return
            learned = self._learned[datapath.id]
            learned[frame.src] = int(in_port)
            # Broadcast/multicast destinations must retain flood semantics.
            multicast = bool(int(frame.dst.split(':')[0], 16) & 1)
            out_port = (ofp.OFPP_FLOOD if multicast else
                        learned.get(frame.dst, ofp.OFPP_FLOOD))
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofp.OFPP_FLOOD and out_port != in_port:
                self._add_flow(datapath, 1, parser.OFPMatch(
                    in_port=in_port, eth_dst=frame.dst), actions)
            # FlowMod never consumes a buffer here. PacketOut forwards the
            # triggering packet using either its real buffer or its full bytes.
            data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
            datapath.send_msg(parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=data))

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def openflow_error(self, ev):
        msg = ev.msg
        with self._lock:
            self._errors.append({
                'type': int(msg.type), 'code': int(msg.code),
                'xid': int(msg.xid),
            })
            # Errors are persistent: sync cannot certify earlier failed updates.
            for operation in list(self._syncs):
                self._finish_sync(operation, 500, {
                    'complete': False, 'error': 'OpenFlow error recorded',
                })

    @set_ev_cls(ofp_event.EventOFPBarrierReply,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def barrier_reply(self, ev):
        msg = ev.msg
        key = (msg.datapath, msg.xid)
        with self._lock:
            operation = self._barriers.pop(key, None)
            if operation is None:
                return
            operation.pending.discard(key)
            if not operation.pending:
                self._finish_sync(operation, 200, {'complete': True})

    def status(self):
        with self._lock:
            return {
                'switches': sorted(self._switches),
                'learned': {
                    str(dpid): dict(self._learned[dpid])
                    for dpid in sorted(self._switches)
                },
                'blocked': [],
                'errors': [dict(error) for error in self._errors],
            }

    def synchronize(self):
        # This runs in a WSGI greenlet. Event.wait yields, leaving the Ryu
        # event-handler greenlet free to process errors and barrier replies.
        with self._lock:
            if not self._switches:
                return 503, {'complete': False, 'error': 'No switch connected'}
            operation = SyncOperation(self._switches)
            self._syncs.add(operation)
            requests = []
            for datapath in operation.switches.values():
                request = datapath.ofproto_parser.OFPBarrierRequest(datapath)
                datapath.set_xid(request)
                key = (datapath, request.xid)
                operation.pending.add(key)
                self._barriers[key] = operation
                requests.append((datapath, request))
            try:
                for datapath, request in requests:
                    if datapath.send_msg(request) is False:
                        self._finish_sync(operation, 503, {
                            'complete': False,
                            'error': 'Could not send required barrier',
                        })
                if self._errors:
                    self._finish_sync(operation, 500, {
                        'complete': False, 'error': 'OpenFlow error recorded',
                    })
            except Exception:
                self.logger.exception('Failed to send synchronization barriers')
                self._finish_sync(operation, 503, {
                    'complete': False, 'error': 'Barrier transmission failed',
                })

        with Timeout(self.SYNC_TIMEOUT, False):
            operation.done.wait()
        with self._lock:
            if operation.result is None:
                self._finish_sync(operation, 504, {
                    'complete': False, 'error': 'Barrier reply timed out',
                })
            return operation.result


class RainHTTP(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RainHTTP, self).__init__(req, link, data, **config)
        self.controller = data['controller']

    @staticmethod
    def _json(status, body):
        return Response(status=status, content_type='application/json',
                        body=json.dumps(body).encode('utf-8'))

    @route('rain_status', '/rain/status', methods=['GET'])
    def status(self, req, **kwargs):
        return self._json(200, self.controller.status())

    @route('rain_sync', '/rain/sync', methods=['POST'])
    def sync(self, req, **kwargs):
        status, body = self.controller.synchronize()
        return self._json(status, body)
