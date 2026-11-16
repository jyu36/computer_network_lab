"""OpenFlow 1.3 learning switch with observable state and barrier synchronization."""

import json
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls,
)
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import hub
from ryu.lib.packet import ethernet, ether_types, packet
from ryu.ofproto import ofproto_v1_3
from webob import Response


class LearningController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}
    SYNC_TIMEOUT = 10.0

    def __init__(self, *args, **kwargs):
        super(LearningController, self).__init__(*args, **kwargs)
        self._lock = hub.Semaphore(1)
        self._switches = {}
        self._learned = {}
        self._errors = []
        self._syncs = {}
        self._next_sync = 0
        kwargs['wsgi'].register(RainAPI, {'controller': self})

    @staticmethod
    def _flow(datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        arguments = dict(
            datapath=datapath, table_id=0, priority=priority,
            match=match, idle_timeout=0, hard_timeout=0,
            instructions=[parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS, actions)],
        )
        if buffer_id is not None:
            arguments['buffer_id'] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**arguments))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        with self._lock:
            self._flow(
                datapath, 0, parser.OFPMatch(),
                [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                        ofp.OFPCML_NO_BUFFER)],
            )

    def _fail_connection_syncs(self, datapath):
        for transaction in self._syncs.values():
            if transaction['connections'].get(datapath.id) is datapath:
                transaction['failure'] = (503, 'Required switch disconnected')

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def switch_state(self, ev):
        datapath = ev.datapath
        with self._lock:
            current = self._switches.get(datapath.id)
            if ev.state == MAIN_DISPATCHER:
                if current is not datapath:
                    if current is not None:
                        self._fail_connection_syncs(current)
                    self._switches[datapath.id] = datapath
                    self._learned[datapath.id] = {}
            elif current is datapath:
                self._fail_connection_syncs(datapath)
                del self._switches[datapath.id]
                self._learned.pop(datapath.id, None)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        try:
            if not msg.data or len(msg.data) < 14:
                return
            decoded = packet.Packet(msg.data)
            eth = decoded.get_protocol(ethernet.ethernet)
            if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            in_port = msg.match['in_port']
        except Exception:
            # Packet decoders may reject truncated or malformed payloads.
            return

        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        with self._lock:
            if self._switches.get(datapath.id) is not datapath:
                return
            learned = self._learned[datapath.id]
            learned[eth.src] = int(in_port)
            out_port = learned.get(eth.dst, ofp.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            buffered = msg.buffer_id != ofp.OFP_NO_BUFFER
            if out_port != ofp.OFPP_FLOOD and out_port != in_port:
                self._flow(
                    datapath, 1,
                    parser.OFPMatch(in_port=in_port, eth_dst=eth.dst),
                    actions, msg.buffer_id if buffered else None,
                )
                if buffered:
                    # The flow-mod applies its actions to this buffered packet.
                    return
            datapath.send_msg(parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions,
                data=None if buffered else msg.data,
            ))

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def openflow_error(self, ev):
        msg = ev.msg
        with self._lock:
            self._errors.append({
                'type': int(msg.type), 'code': int(msg.code),
                'xid': int(msg.xid),
            })
            for transaction in self._syncs.values():
                transaction['failure'] = (502, 'OpenFlow error recorded')
        self.logger.error('OpenFlow error: type=%s code=%s xid=%s',
                          msg.type, msg.code, msg.xid)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply(self, ev):
        msg = ev.msg
        with self._lock:
            for transaction in self._syncs.values():
                if transaction['connections'].get(msg.datapath.id) is msg.datapath:
                    transaction['pending'].discard((msg.datapath.id, msg.xid))

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
        # WSGI runs in a cooperative greenlet. Only this request waits;
        # OpenFlow event handlers remain free to process barrier replies.
        with self._lock:
            if not self._switches:
                return 503, {'complete': False, 'error': 'No connected switches'}
            self._next_sync += 1
            token = self._next_sync
            transaction = {
                'connections': dict(self._switches),
                'pending': set(),
                'failure': ((502, 'OpenFlow error recorded')
                            if self._errors else None),
            }
            self._syncs[token] = transaction
            for dpid, datapath in transaction['connections'].items():
                try:
                    request = datapath.ofproto_parser.OFPBarrierRequest(datapath)
                    datapath.set_xid(request)
                    transaction['pending'].add((dpid, request.xid))
                    sent = datapath.send_msg(request)
                    if sent is False:
                        transaction['failure'] = (503, 'Barrier could not be sent')
                except Exception:
                    self.logger.exception('Unable to send barrier to switch %s', dpid)
                    transaction['failure'] = (503, 'Barrier could not be sent')

        deadline = time.monotonic() + self.SYNC_TIMEOUT
        try:
            while True:
                with self._lock:
                    failure = transaction['failure']
                    if failure is not None:
                        return failure[0], {'complete': False, 'error': failure[1]}
                    if not transaction['pending']:
                        return 200, {'complete': True}
                    if time.monotonic() >= deadline:
                        return 504, {'complete': False,
                                     'error': 'Timed out waiting for Barrier Replies'}
                hub.sleep(0.01)
        finally:
            with self._lock:
                self._syncs.pop(token, None)


class RainAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(RainAPI, self).__init__(req, link, data, **config)
        self.controller = data['controller']

    @staticmethod
    def _json(status, value):
        return Response(status=status, content_type='application/json',
                        charset='utf-8', body=json.dumps(value).encode('utf-8'))

    @route('rain_status', '/rain/status', methods=['GET'])
    def status(self, req, **kwargs):
        return self._json(200, self.controller.status())

    @route('rain_sync', '/rain/sync', methods=['POST'])
    def sync(self, req, **kwargs):
        status, value = self.controller.synchronize()
        return self._json(status, value)
