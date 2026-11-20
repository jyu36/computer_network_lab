# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""AI-assisted adaptation of the local Ryu example_switch_13.py baseline.

Retains its learning/forwarding algorithm; adds the experiment's status and
barrier interfaces, connection/error bookkeeping and defensive packet parsing.
Adds destination policy replacement and observed host movement repair.
It is a candidate reference, not an independently human-authored implementation.
"""

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
from ryu.lib.packet import ethernet, ether_types, packet
from ryu.ofproto import ofproto_v1_3


MAC_ADDRESS = re.compile(r'[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}')


def normalized_blocklist(value):
    """Validate the whole list before returning any normalized policy."""
    if not isinstance(value, list):
        raise ValueError('blocked must be a list')
    if any(not isinstance(mac, str) or MAC_ADDRESS.fullmatch(mac) is None
           for mac in value):
        raise ValueError('blocked entries must be six-byte MAC strings')
    return {mac.lower() for mac in value}


class BarrierSynchronization:
    """Track one request against a fixed snapshot of switch connections."""

    def __init__(self, connections):
        self.connections = dict(connections)
        self.pending_replies = {}
        self.failure = None


class ExampleSwitch13(app_manager.RyuApp):
    """Public Ryu forwarding logic with experiment observability added."""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}
    SYNCHRONIZATION_TIMEOUT_SECONDS = 10.0
    FORWARDING_COOKIE = 1
    POLICY_COOKIE = 2
    POLICY_PRIORITY = 100

    def __init__(self, *args, **kwargs):
        """Initialize actual learned state and register Ryu's WSGI routes."""
        super(ExampleSwitch13, self).__init__(*args, **kwargs)
        self.blocked = normalized_blocklist(
            json.loads(os.environ.get('RAIN_BLOCKED', '[]')))
        self.policy_update_lock = hub.Semaphore(1)
        self.mac_to_port = {}
        self.connected_switches = {}
        self.openflow_errors = []
        self.active_synchronizations = []
        self.state_lock = hub.Semaphore(1)
        kwargs['wsgi'].register(ReferenceAPI, {'controller': self})

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install the original full-packet, priority-0 table-miss rule."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                         ofproto.OFPCML_NO_BUFFER)]
        with self.state_lock:
            self.add_flow(datapath, 0, match, actions)
            self._install_current_policy(datapath)

    def add_flow(self, datapath, priority, match, actions, cookie=0):
        """Send the original no-timeout forwarding rule; caller holds lock."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        instructions = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        message = parser.OFPFlowMod(
            datapath=datapath, cookie=cookie, priority=priority, match=match,
            instructions=instructions, idle_timeout=0, hard_timeout=0)
        datapath.send_msg(message)

    def _delete_flows(self, datapath, cookie, match):
        """Delete only this application's selected rule kind; lock is held."""
        ofproto = datapath.ofproto
        datapath.send_msg(datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, cookie=cookie, cookie_mask=0xffffffffffffffff,
            table_id=0, command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
            match=match))

    def _add_destination_drop(self, datapath, mac):
        self.add_flow(datapath, self.POLICY_PRIORITY,
                      datapath.ofproto_parser.OFPMatch(eth_dst=mac), [],
                      cookie=self.POLICY_COOKIE)

    def _install_current_policy(self, datapath):
        """Reconcile even if policy changed between FEATURES and MAIN."""
        self._delete_flows(datapath, self.POLICY_COOKIE,
                           datapath.ofproto_parser.OFPMatch())
        for mac in sorted(self.blocked):
            self._add_destination_drop(datapath, mac)

    def _replace_policy(self, blocked):
        """Order switch changes and Packet-In decisions under the state lock."""
        previous = self.blocked
        self.blocked = set(blocked)
        for datapath in self.connected_switches.values():
            # Install new drops first. Existing priority-1 cached forwarding
            # stays available when an old destination drop is removed.
            for mac in sorted(self.blocked - previous):
                self._add_destination_drop(datapath, mac)
            for mac in sorted(previous - self.blocked):
                self._delete_flows(
                    datapath, self.POLICY_COOKIE,
                    datapath.ofproto_parser.OFPMatch(eth_dst=mac))

    def replace_policy(self, blocked):
        """Serialize complete HTTP replacements without blocking OF handlers."""
        with self.policy_update_lock:
            return self.synchronize(blocked=blocked)

    def _fail_connection_waiters(self, datapath, reason):
        """Invalidate requests needing this exact connection; lock is held."""
        for synchronization in self.active_synchronizations:
            if synchronization.connections.get(datapath.id) is datapath:
                synchronization.failure = reason

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def switch_state_handler(self, ev):
        """Track live connections without letting old disconnects erase new ones."""
        datapath = ev.datapath
        with self.state_lock:
            if ev.state == MAIN_DISPATCHER:
                previous = self.connected_switches.get(datapath.id)
                if previous is not datapath:
                    if previous is not None:
                        self._fail_connection_waiters(
                            previous, 'required switch connection replaced')
                    self.connected_switches[datapath.id] = datapath
                    self.mac_to_port[datapath.id] = {}
                    self._install_current_policy(datapath)
            elif ev.state == DEAD_DISPATCHER:
                self._fail_connection_waiters(
                    datapath, 'required switch disconnected')
                if self.connected_switches.get(datapath.id) is datapath:
                    del self.connected_switches[datapath.id]
                    self.mac_to_port.pop(datapath.id, None)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Learn a source, flood or forward, and deliver the triggering packet."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Ignore unusable Ethernet input and LLDP before modifying learned state.
        try:
            if not msg.data or len(msg.data) < 14:
                return
            parsed_packet = packet.Packet(msg.data)
            eth_pkt = parsed_packet.get_protocol(ethernet.ethernet)
            if eth_pkt is None or eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            in_port = msg.match.get('in_port')
            if in_port is None:
                return
        except Exception:
            return

        with self.state_lock:
            if self.connected_switches.get(datapath.id) is not datapath:
                return
            # These are the source-learning and destination decisions from Ryu.
            locations = self.mac_to_port[datapath.id]
            source = eth_pkt.src.lower()
            destination = eth_pkt.dst.lower()
            previous_port = locations.get(source)
            if previous_port is not None and previous_port != in_port:
                # Remove every ingress-specific cached route to the old port,
                # leaving the independently tagged policy rules intact.
                self._delete_flows(datapath, self.FORWARDING_COOKIE,
                                   parser.OFPMatch(eth_dst=source))
            locations[source] = in_port
            if destination in self.blocked:
                return
            out_port = locations.get(destination, ofproto.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofproto.OFPP_FLOOD and out_port != in_port:
                match = parser.OFPMatch(in_port=in_port, eth_dst=destination)
                self.add_flow(datapath, 1, match, actions,
                              cookie=self.FORWARDING_COOKIE)

            # A Flow-Mod above does not consume a buffer. Forward the trigger
            # separately, using its actual switch buffer or the supplied bytes.
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            datapath.send_msg(parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=data))

    @set_ev_cls(ofp_event.EventOFPErrorMsg,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER])
    def openflow_error_handler(self, ev):
        """Record protocol errors and prevent false synchronization success."""
        message = ev.msg
        with self.state_lock:
            self.openflow_errors.append({
                'type': int(message.type), 'code': int(message.code),
                'xid': int(message.xid)})
            for synchronization in self.active_synchronizations:
                synchronization.failure = 'OpenFlow error recorded'
        self.logger.error('OpenFlow error: dpid=%s type=%s code=%s xid=%s',
                          message.datapath.id, message.type,
                          message.code, message.xid)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        """Accept only replies matching both the connection and transaction ID."""
        message = ev.msg
        reply_key = (message.datapath.id, message.xid)
        with self.state_lock:
            for synchronization in self.active_synchronizations:
                if synchronization.pending_replies.get(reply_key) is message.datapath:
                    del synchronization.pending_replies[reply_key]

    def status(self):
        """Return a read-only snapshot of the same mapping used for forwarding."""
        with self.state_lock:
            return {
                'switches': sorted(self.connected_switches),
                'learned': {str(switch_id): dict(self.mac_to_port[switch_id])
                            for switch_id in sorted(self.connected_switches)},
                'blocked': sorted(self.blocked),
                'errors': [dict(error) for error in self.openflow_errors],
            }

    def synchronize(self, blocked=None):
        """Wait in the HTTP greenlet while OpenFlow handlers process replies.

        The state lock orders prior Flow-Mods before barriers. It is released
        while waiting. Errors are retained for this process: after a protocol
        error, a fresh experiment is required before successful synchronization.
        """
        synchronization = None
        try:
            with self.state_lock:
                if not self.connected_switches:
                    return 503, {'complete': False, 'error': 'no switch connected'}
                if self.openflow_errors:
                    return 503, {'complete': False, 'error': 'OpenFlow error recorded'}
                if blocked is not None:
                    self._replace_policy(blocked)
                synchronization = BarrierSynchronization(self.connected_switches)
                self.active_synchronizations.append(synchronization)
                # Register every expected reply before sending any request.
                requests = []
                for datapath in synchronization.connections.values():
                    request = datapath.ofproto_parser.OFPBarrierRequest(datapath)
                    datapath.set_xid(request)
                    synchronization.pending_replies[(datapath.id, request.xid)] = datapath
                    requests.append((datapath, request))
                for datapath, request in requests:
                    datapath.send_msg(request)

            deadline = time.monotonic() + self.SYNCHRONIZATION_TIMEOUT_SECONDS
            while True:
                with self.state_lock:
                    if synchronization.failure:
                        return 503, {'complete': False,
                                     'error': synchronization.failure}
                    if any(self.connected_switches.get(switch_id) is not datapath
                           for switch_id, datapath
                           in synchronization.connections.items()):
                        return 503, {'complete': False,
                                     'error': 'required switch disconnected'}
                    if not synchronization.pending_replies:
                        return 200, {'complete': True}
                    if time.monotonic() >= deadline:
                        return 504, {'complete': False, 'error': 'barrier reply timeout'}
                hub.sleep(0.01)
        except Exception:
            self.logger.exception('Could not synchronize switch connections')
            return 503, {'complete': False, 'error': 'synchronization failed'}
        finally:
            if synchronization is not None:
                with self.state_lock:
                    self.active_synchronizations.remove(synchronization)


class ReferenceAPI(ControllerBase):
    """Expose status, completion and destination-policy replacement."""

    def __init__(self, req, link, data, **config):
        super(ReferenceAPI, self).__init__(req, link, data, **config)
        self.controller = data['controller']

    @staticmethod
    def _response(status, body):
        """Encode the documented JSON response for WebOb."""
        return Response(status=status, content_type='application/json',
                        charset='utf-8', body=json.dumps(body).encode('utf-8'))

    @route('reference_status', '/rain/status', methods=['GET'])
    def status(self, req, **kwargs):
        """Report observed controller state without changing it."""
        return self._response(200, self.controller.status())

    @route('reference_sync', '/rain/sync', methods=['POST'])
    def sync(self, req, **kwargs):
        """Acknowledge earlier switch updates only after barrier completion."""
        status, body = self.controller.synchronize()
        return self._response(status, body)

    @route('reference_policy', '/rain/policy', methods=['PUT'])
    def policy(self, req, **kwargs):
        """Validate a complete replacement before touching controller state."""
        try:
            body = json.loads(req.body)
            if not isinstance(body, dict) or set(body) != {'blocked'}:
                raise ValueError('expected an object containing only blocked')
            blocked = normalized_blocklist(body['blocked'])
        except (ValueError, TypeError, UnicodeError):
            return self._response(400, {'complete': False,
                                        'error': 'invalid policy body'})
        status, body = self.controller.replace_policy(blocked)
        return self._response(status, body)
