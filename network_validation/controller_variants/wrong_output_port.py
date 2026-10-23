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

def is_valid_mac_address(mac_address):
    """Return whether a value is a colon-separated six-byte MAC address."""
    return isinstance(mac_address, str) and re.fullmatch('(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', mac_address) is not None

class ControllerRequest(event.EventRequestBase):
    """Carry a status, synchronization, or policy request on the Ryu event queue."""

    def __init__(self, operation, request_body=None):
        super().__init__()
        self.dst = 'rain_control'
        self.operation = operation
        self.request_body = request_body

class ControllerReply(event.EventReplyBase):
    """Carry an HTTP status and JSON response back to the API request handler."""

    def __init__(self, destination_service, http_status, response_body):
        super().__init__(destination_service)
        self.http_status, self.response_body = (http_status, response_body)

class LearningSwitchController(app_manager.RyuApp):
    """Provide a draft learning switch with movement and destination policy support."""
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.name = 'rain_control'
        self.host_locations_by_switch, self.connected_switches, self.pending_barrier_requests = ({}, {}, {})
        self.blocked_destination_macs = set(json.loads(os.environ.get('RAIN_BLOCKED', '[]')))
        self.openflow_errors = []
        kwargs['wsgi'].register(ControllerHttpApi, {'app': self})

    def install_flow_rule(self, datapath, priority, match, output_actions):
        """Send a Flow-Mod that installs the requested match, priority, and actions."""
        ofproto_parser, ofproto = (datapath.ofproto_parser, datapath.ofproto)
        datapath.send_msg(ofproto_parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=[ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, output_actions)]))

    def delete_flow_rules(self, datapath, match, **kwargs):
        """Delete switch flows matching the supplied OpenFlow match and filters."""
        ofproto_parser, ofproto = (datapath.ofproto_parser, datapath.ofproto)
        datapath.send_msg(ofproto_parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, match=match, **kwargs))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handle_switch_features(self, received_event):
        """Initialize switch state, the table-miss rule, and initial policy drops."""
        datapath = received_event.msg.datapath
        self.connected_switches[datapath.id], self.host_locations_by_switch[datapath.id] = (datapath, {})
        ofproto_parser, ofproto = (datapath.ofproto_parser, datapath.ofproto)
        self.delete_flow_rules(datapath, ofproto_parser.OFPMatch())
        self.install_flow_rule(datapath, 0, ofproto_parser.OFPMatch(), [ofproto_parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)])
        for destination_mac in self.blocked_destination_macs:
            self.install_flow_rule(datapath, 100, ofproto_parser.OFPMatch(eth_dst=destination_mac), [])

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handle_packet_in(self, received_event):
        """Learn the source location and forward or drop the received Ethernet frame."""
        packet_in_message, datapath = (received_event.msg, received_event.msg.datapath)
        ofproto_parser, ofproto = (datapath.ofproto_parser, datapath.ofproto)
        ethernet_header = packet.Packet(packet_in_message.data).get_protocol(ethernet.ethernet)
        if ethernet_header is None or ethernet_header.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        ingress_port, host_locations = (packet_in_message.match['in_port'], self.host_locations_by_switch[datapath.id])
        previous_port = host_locations.get(ethernet_header.src)
        host_locations[ethernet_header.src] = ingress_port
        if previous_port is not None and previous_port != ingress_port:
            datapath.send_msg(ofproto_parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE, cookie=1, cookie_mask=18446744073709551615, out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY, match=ofproto_parser.OFPMatch()))
        if ethernet_header.dst in self.blocked_destination_macs:
            return
        egress_port = host_locations.get(ethernet_header.dst, ofproto.OFPP_FLOOD)
        if egress_port < ofproto.OFPP_MAX:
            egress_port = 3 if egress_port != 3 else 2
        output_actions = [ofproto_parser.OFPActionOutput(egress_port)]
        if egress_port != ofproto.OFPP_FLOOD:
            datapath.send_msg(ofproto_parser.OFPFlowMod(datapath=datapath, cookie=1, priority=1, match=ofproto_parser.OFPMatch(in_port=ingress_port, eth_dst=ethernet_header.dst), instructions=[ofproto_parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, output_actions)]))
        datapath.send_msg(ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ingress_port, actions=output_actions, data=packet_in_message.data))

    @set_ev_cls(ControllerRequest)
    def handle_controller_request(self, controller_request):
        """Process an API request and acknowledge updates after switch barriers."""
        if controller_request.operation == 'status':
            self.send_reply(controller_request, ControllerReply(controller_request.src, 200, {'switches': sorted(self.connected_switches), 'learned': self.host_locations_by_switch, 'blocked': sorted(self.blocked_destination_macs), 'errors': self.openflow_errors}))
            return
        if controller_request.operation == 'policy':
            policy_request_body = controller_request.request_body
            if not isinstance(policy_request_body, dict) or set(policy_request_body) != {'blocked'} or (not isinstance(policy_request_body['blocked'], list)) or (not all((is_valid_mac_address(mac_address) for mac_address in policy_request_body['blocked']))):
                self.send_reply(controller_request, ControllerReply(controller_request.src, 400, {'error': 'Expected blocked: list of MAC addresses'}))
                return
            updated_blocklist = {mac_address.lower() for mac_address in policy_request_body['blocked']}
            for datapath in self.connected_switches.values():
                ofproto_parser, ofproto = (datapath.ofproto_parser, datapath.ofproto)
                for destination_mac in self.blocked_destination_macs - updated_blocklist:
                    datapath.send_msg(ofproto_parser.OFPFlowMod(datapath=datapath, command=ofproto.OFPFC_DELETE_STRICT, priority=100, match=ofproto_parser.OFPMatch(eth_dst=destination_mac), out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY))
                for destination_mac in updated_blocklist - self.blocked_destination_macs:
                    self.install_flow_rule(datapath, 100, ofproto_parser.OFPMatch(eth_dst=destination_mac), [])
            self.blocked_destination_macs = updated_blocklist
        if not self.connected_switches:
            self.send_reply(controller_request, ControllerReply(controller_request.src, 503, {'error': 'No connected switch'}))
            return
        pending_switch_barriers = set()
        for datapath in self.connected_switches.values():
            barrier_request = datapath.ofproto_parser.OFPBarrierRequest(datapath)
            datapath.set_xid(barrier_request)
            pending_switch_barriers.add((datapath.id, barrier_request.xid))
            datapath.send_msg(barrier_request)
        for barrier_key in pending_switch_barriers:
            self.pending_barrier_requests[barrier_key] = (controller_request, pending_switch_barriers)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def handle_barrier_reply(self, received_event):
        """Complete a pending request once every switch barrier has replied."""
        barrier_key = (received_event.msg.datapath.id, received_event.msg.xid)
        pending_request = self.pending_barrier_requests.pop(barrier_key, None)
        if pending_request:
            controller_request, pending_switch_barriers = pending_request
            pending_switch_barriers.remove(barrier_key)
            if not pending_switch_barriers:
                self.send_reply(controller_request, ControllerReply(controller_request.src, 500 if self.openflow_errors else 200, {'complete': not self.openflow_errors, 'errors': self.openflow_errors}))

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def handle_openflow_error(self, received_event):
        """Record OpenFlow errors so updates cannot be acknowledged as successful."""
        self.openflow_errors.append({'type': received_event.msg.type, 'code': received_event.msg.code, 'xid': received_event.msg.xid})
        self.logger.error('OpenFlow error: %s', self.openflow_errors[-1])

class ControllerHttpApi(ControllerBase):
    """Expose the agreed status, synchronization, and runtime policy endpoints."""

    def __init__(self, http_request, route_link, registered_context, **kwargs):
        super().__init__(http_request, route_link, registered_context, **kwargs)
        self.controller_app = registered_context['app']

    def dispatch_controller_request(self, operation, request_body=None):
        """Send an event request to the controller and encode its HTTP response."""
        controller_reply = self.controller_app.send_request(ControllerRequest(operation, request_body))
        return Response(status=controller_reply.http_status, content_type='application/json', body=json.dumps(controller_reply.response_body).encode())

    @route('rain', '/rain/status', methods=['GET'])
    def get_status(self, http_request, **kwargs):
        """Return the current controller state through the HTTP status endpoint."""
        return self.dispatch_controller_request('status')

    @route('rain', '/rain/sync', methods=['POST'])
    def synchronize_updates(self, http_request, **kwargs):
        """Wait for preceding controller flow updates through the HTTP sync endpoint."""
        return self.dispatch_controller_request('sync')

    @route('rain', '/rain/policy', methods=['PUT'])
    def update_policy(self, http_request, **kwargs):
        """Decode a runtime policy request and return the controller response."""
        try:
            policy_request_body = http_request.json
        except ValueError:
            return Response(status=400)
        return self.dispatch_controller_request('policy', policy_request_body)
