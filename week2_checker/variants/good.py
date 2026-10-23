"""Draft control implementation. Never supply this file to generation agents."""
import json
import os
import re
from ryu.base import app_manager
from ryu.controller import event, ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response

def valid_mac(value):
    return isinstance(value, str) and re.fullmatch('(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value) is not None

class Command(event.EventRequestBase):

    def __init__(self, operation, body=None):
        super().__init__()
        self.dst = 'rain_control'
        self.operation = operation
        self.body = body

class Reply(event.EventReplyBase):

    def __init__(self, dst, status, body):
        super().__init__(dst)
        self.status, self.body = (status, body)

class RainControl(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = 'rain_control'
        self.tables, self.switches, self.pending = ({}, {}, {})
        self.blocked = set(json.loads(os.environ.get('RAIN_BLOCKED', '[]')))
        self.errors = []
        kwargs['wsgi'].register(API, {'app': self})

    def add_flow(self, dp, priority, match, actions):
        p, o = (dp.ofproto_parser, dp.ofproto)
        dp.send_msg(p.OFPFlowMod(datapath=dp, priority=priority, match=match, instructions=[p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS, actions)]))

    def delete(self, dp, match, **kwargs):
        p, o = (dp.ofproto_parser, dp.ofproto)
        dp.send_msg(p.OFPFlowMod(datapath=dp, command=o.OFPFC_DELETE, out_port=o.OFPP_ANY, out_group=o.OFPG_ANY, match=match, **kwargs))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features(self, ev):
        dp = ev.msg.datapath
        self.switches[dp.id], self.tables[dp.id] = (dp, {})
        p, o = (dp.ofproto_parser, dp.ofproto)
        self.delete(dp, p.OFPMatch())
        self.add_flow(dp, 0, p.OFPMatch(), [p.OFPActionOutput(o.OFPP_CONTROLLER, o.OFPCML_NO_BUFFER)])
        for mac in self.blocked:
            self.add_flow(dp, 100, p.OFPMatch(eth_dst=mac), [])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg, dp = (ev.msg, ev.msg.datapath)
        p, o = (dp.ofproto_parser, dp.ofproto)
        eth = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        incoming, table = (msg.match['in_port'], self.tables[dp.id])
        old = table.get(eth.src)
        table[eth.src] = incoming
        if old is not None and old != incoming:
            dp.send_msg(p.OFPFlowMod(datapath=dp, command=o.OFPFC_DELETE, cookie=1, cookie_mask=18446744073709551615, out_port=o.OFPP_ANY, out_group=o.OFPG_ANY, match=p.OFPMatch()))
        if eth.dst in self.blocked:
            return
        output = table.get(eth.dst, o.OFPP_FLOOD)
        actions = [p.OFPActionOutput(output)]
        if output != o.OFPP_FLOOD:
            dp.send_msg(p.OFPFlowMod(datapath=dp, cookie=1, priority=1, match=p.OFPMatch(in_port=incoming, eth_dst=eth.dst), instructions=[p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS, actions)]))
        dp.send_msg(p.OFPPacketOut(datapath=dp, buffer_id=o.OFP_NO_BUFFER, in_port=incoming, actions=actions, data=msg.data))

    @set_ev_cls(Command)
    def command(self, req):
        if req.operation == 'status':
            self.send_reply(req, Reply(req.src, 200, {'switches': sorted(self.switches), 'learned': self.tables, 'blocked': sorted(self.blocked), 'errors': self.errors}))
            return
        if req.operation == 'policy':
            body = req.body
            if not isinstance(body, dict) or set(body) != {'blocked'} or (not isinstance(body['blocked'], list)) or (not all((valid_mac(x) for x in body['blocked']))):
                self.send_reply(req, Reply(req.src, 400, {'error': 'Expected blocked: list of MAC addresses'}))
                return
            new = {x.lower() for x in body['blocked']}
            for dp in self.switches.values():
                p, o = (dp.ofproto_parser, dp.ofproto)
                for mac in self.blocked - new:
                    dp.send_msg(p.OFPFlowMod(datapath=dp, command=o.OFPFC_DELETE_STRICT, priority=100, match=p.OFPMatch(eth_dst=mac), out_port=o.OFPP_ANY, out_group=o.OFPG_ANY))
                for mac in new - self.blocked:
                    self.add_flow(dp, 100, p.OFPMatch(eth_dst=mac), [])
            self.blocked = new
        if not self.switches:
            self.send_reply(req, Reply(req.src, 503, {'error': 'No connected switch'}))
            return
        waiting = set()
        for dp in self.switches.values():
            barrier = dp.ofproto_parser.OFPBarrierRequest(dp)
            dp.set_xid(barrier)
            waiting.add((dp.id, barrier.xid))
            dp.send_msg(barrier)
        for key in waiting:
            self.pending[key] = (req, waiting)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier(self, ev):
        key = (ev.msg.datapath.id, ev.msg.xid)
        item = self.pending.pop(key, None)
        if item:
            req, waiting = item
            waiting.remove(key)
            if not waiting:
                self.send_reply(req, Reply(req.src, 500 if self.errors else 200, {'complete': not self.errors, 'errors': self.errors}))

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def of_error(self, ev):
        self.errors.append({'type': ev.msg.type, 'code': ev.msg.code, 'xid': ev.msg.xid})
        self.logger.error('OpenFlow error: %s', self.errors[-1])

class API(ControllerBase):

    def __init__(self, req, link, data, **kwargs):
        super().__init__(req, link, data, **kwargs)
        self.app = data['app']

    def call(self, op, body=None):
        reply = self.app.send_request(Command(op, body))
        return Response(status=reply.status, content_type='application/json', body=json.dumps(reply.body).encode())

    @route('rain', '/rain/status', methods=['GET'])
    def status(self, req, **kwargs):
        return self.call('status')

    @route('rain', '/rain/sync', methods=['POST'])
    def sync(self, req, **kwargs):
        return self.call('sync')

    @route('rain', '/rain/policy', methods=['PUT'])
    def policy(self, req, **kwargs):
        try:
            body = req.json
        except ValueError:
            return Response(status=400)
        return self.call('policy', body)
