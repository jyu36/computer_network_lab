"""Dependency-free checks of reference handler logic, not Ryu/OVS integration.

Execute the actual controller classes with lightweight framework stand-ins.
Real Ryu imports, cooperative scheduling, HTTP and packet delivery must also
be validated in Ubuntu using run_network_tests.py --suite base.
"""

import ast
import logging
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock


SOURCE = Path(__file__).resolve().parents[1] / 'controllers' / 'ryu_reference_baseline.py'
MAIN_DISPATCHER = 'main'
DEAD_DISPATCHER = 'dead'


class FrameworkApp:
    def __init__(self, *args, **kwargs):
        self.logger = Mock(spec=logging.Logger)


class FakeDatapath:
    """Capture outgoing messages and assign per-connection transaction IDs."""

    def __init__(self, switch_id):
        self.id = switch_id
        self.messages = []
        self.next_xid = 0
        self.ofproto = SimpleNamespace(
            OFPP_CONTROLLER=0xfffffffd, OFPCML_NO_BUFFER=0xffff,
            OFPIT_APPLY_ACTIONS=4, OFPP_FLOOD=0xfffffffb,
            OFP_NO_BUFFER=0xffffffff,
        )
        self.ofproto_parser = SimpleNamespace(
            OFPMatch=lambda **fields: fields,
            OFPActionOutput=lambda port, *args: SimpleNamespace(port=port),
            OFPInstructionActions=lambda kind, actions: actions,
            OFPFlowMod=lambda **fields: SimpleNamespace(kind='flow', **fields),
            OFPPacketOut=lambda **fields: SimpleNamespace(kind='packet', **fields),
            OFPBarrierRequest=lambda datapath: SimpleNamespace(
                kind='barrier', datapath=datapath),
        )

    def set_xid(self, message):
        self.next_xid += 1
        message.xid = self.next_xid

    def send_msg(self, message):
        self.messages.append(message)


class ReferenceBaselineTests(unittest.TestCase):
    def setUp(self):
        """Load implementation methods without requiring Ryu on the Mac."""
        tree = ast.parse(SOURCE.read_text())
        classes = [node for node in tree.body if isinstance(node, ast.ClassDef)
                   and node.name in {'BarrierSynchronization', 'ExampleSwitch13'}]
        for cls in classes:
            for method in cls.body:
                if isinstance(method, ast.FunctionDef):
                    method.decorator_list = [decorator for decorator in method.decorator_list
                                             if not isinstance(decorator, ast.Call)]
        self.hub = SimpleNamespace(Semaphore=lambda count: threading.Lock(),
                                   sleep=lambda seconds: time.sleep(0.001))
        self.ethernet = SimpleNamespace(src='00:00:00:00:00:01',
                                        dst='00:00:00:00:00:02', ethertype=0x0800)
        self.parse = Mock(side_effect=lambda data: SimpleNamespace(
            get_protocol=lambda protocol: self.ethernet))
        namespace = {
            'app_manager': SimpleNamespace(RyuApp=FrameworkApp),
            'ofproto_v1_3': SimpleNamespace(OFP_VERSION=4),
            'WSGIApplication': object, 'ReferenceAPI': object,
            'hub': self.hub, 'time': time,
            'MAIN_DISPATCHER': MAIN_DISPATCHER, 'DEAD_DISPATCHER': DEAD_DISPATCHER,
            'ethernet': SimpleNamespace(ethernet=object),
            'ether_types': SimpleNamespace(ETH_TYPE_LLDP=0x88cc),
            'packet': SimpleNamespace(Packet=self.parse),
        }
        exec(compile(ast.Module(body=classes, type_ignores=[]), str(SOURCE), 'exec'), namespace)
        self.controller = namespace['ExampleSwitch13'](wsgi=SimpleNamespace(register=Mock()))
        self.controller.SYNCHRONIZATION_TIMEOUT_SECONDS = 0.03
        self.datapath = FakeDatapath(1)

    def connect(self, datapath=None):
        datapath = datapath or self.datapath
        self.controller.switch_state_handler(SimpleNamespace(
            datapath=datapath, state=MAIN_DISPATCHER))

    def packet_in(self, datapath=None, buffer_id=None, data=b'x' * 14):
        datapath = datapath or self.datapath
        self.controller._packet_in_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=datapath, data=data, match={'in_port': 1},
            buffer_id=datapath.ofproto.OFP_NO_BUFFER if buffer_id is None else buffer_id)))

    def reply(self, datapath, xid):
        self.controller.barrier_reply_handler(SimpleNamespace(
            msg=SimpleNamespace(datapath=datapath, xid=xid)))

    def reply_to_all(self, seconds):
        for synchronization in list(self.controller.active_synchronizations):
            for (_, xid), datapath in list(synchronization.pending_replies.items()):
                self.reply(datapath, xid)

    def test_table_miss_requests_full_packets(self):
        self.controller.switch_features_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=self.datapath)))
        rule = self.datapath.messages[0]
        self.assertEqual((rule.priority, rule.match), (0, {}))
        self.assertEqual(rule.instructions[0][0].port, self.datapath.ofproto.OFPP_CONTROLLER)

    def test_unknown_flood_and_switch_local_learning(self):
        self.connect()
        other = FakeDatapath(2)
        self.connect(other)
        self.packet_in()
        self.assertEqual(self.controller.mac_to_port[1][self.ethernet.src], 1)
        self.assertEqual(self.controller.mac_to_port[2], {})
        message = self.datapath.messages[-1]
        self.assertEqual(message.actions[0].port, self.datapath.ofproto.OFPP_FLOOD)
        self.assertEqual(message.data, b'x' * 14)

    def test_known_destination_and_trigger_buffering(self):
        self.connect()
        self.controller.mac_to_port[1][self.ethernet.dst] = 2
        for buffer_id in (self.datapath.ofproto.OFP_NO_BUFFER, 7):
            with self.subTest(buffer_id=buffer_id):
                self.datapath.messages.clear()
                self.packet_in(buffer_id=buffer_id)
                rule, trigger = self.datapath.messages
                self.assertEqual(rule.priority, 1)
                self.assertEqual(rule.match, {'in_port': 1, 'eth_dst': self.ethernet.dst})
                self.assertEqual((rule.idle_timeout, rule.hard_timeout), (0, 0))
                self.assertEqual(trigger.actions[0].port, 2)
                self.assertEqual(trigger.buffer_id, buffer_id)
                self.assertEqual(trigger.data, b'x' * 14 if buffer_id == 0xffffffff else None)

    def test_unusable_packets_and_lldp_do_not_learn(self):
        self.connect()
        self.packet_in(data=b'bad')
        self.parse.side_effect = ValueError('malformed')
        self.packet_in()
        self.parse.side_effect = None
        self.parse.return_value = SimpleNamespace(get_protocol=lambda protocol: None)
        self.packet_in()
        self.parse.return_value = SimpleNamespace(get_protocol=lambda protocol: self.ethernet)
        self.ethernet.ethertype = 0x88cc
        self.packet_in()
        self.assertEqual(self.controller.mac_to_port[1], {})
        self.assertEqual(self.datapath.messages, [])

    def test_status_is_a_copy_and_baseline_has_no_policy(self):
        self.connect()
        self.packet_in()
        status = self.controller.status()
        status['learned']['1'].clear()
        self.assertTrue(self.controller.mac_to_port[1])
        self.assertEqual(status['blocked'], [])

    def test_no_switch_cannot_synchronize(self):
        self.assertEqual(self.controller.synchronize()[0], 503)

    def test_sync_needs_all_switches_and_ignores_unmatched_replies(self):
        self.connect()
        other = FakeDatapath(2)
        self.connect(other)
        calls = []

        def deliver(seconds):
            pending = self.controller.active_synchronizations[0].pending_replies
            if not calls:
                self.reply(FakeDatapath(1), 1)  # Same DPID, wrong connection.
                self.reply(self.datapath, 999)
                self.assertEqual(len(pending), 2)
                self.reply(self.datapath, 1)
                self.assertEqual(len(pending), 1)
            else:
                self.reply(other, 1)
            calls.append(True)

        self.hub.sleep = deliver
        self.assertEqual(self.controller.synchronize(), (200, {'complete': True}))
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.controller.active_synchronizations, [])

    def test_missing_reply_times_out_and_cleans_up(self):
        self.connect()
        self.assertEqual(self.controller.synchronize()[0], 504)
        self.assertEqual(self.controller.active_synchronizations, [])

    def test_disconnect_and_connection_replacement_fail_sync(self):
        self.connect()
        for state, datapath in [(DEAD_DISPATCHER, self.datapath),
                                (MAIN_DISPATCHER, FakeDatapath(1))]:
            self.connect()
            self.hub.sleep = lambda seconds: self.controller.switch_state_handler(
                SimpleNamespace(datapath=datapath, state=state))
            self.assertEqual(self.controller.synchronize()[0], 503)

    def test_old_disconnect_does_not_remove_replacement(self):
        self.connect()
        replacement = FakeDatapath(1)
        self.connect(replacement)
        self.controller.switch_state_handler(SimpleNamespace(
            datapath=self.datapath, state=DEAD_DISPATCHER))
        self.assertIs(self.controller.connected_switches[1], replacement)

    def test_protocol_error_during_sync_and_before_next_sync(self):
        self.connect()

        def report_error(seconds):
            self.controller.openflow_error_handler(SimpleNamespace(msg=SimpleNamespace(
                datapath=self.datapath, type=1, code=2, xid=3)))
            self.reply_to_all(seconds)

        self.hub.sleep = report_error
        self.assertEqual(self.controller.synchronize()[0], 503)
        self.assertEqual(self.controller.status()['errors'], [{'type': 1, 'code': 2, 'xid': 3}])
        self.assertEqual(self.controller.synchronize()[0], 503)

    def test_barrier_send_failure_cleans_up(self):
        self.connect()
        self.datapath.send_msg = Mock(side_effect=OSError('connection closed'))
        self.assertEqual(self.controller.synchronize()[0], 503)
        self.assertEqual(self.controller.active_synchronizations, [])

    def test_overlapping_sync_requests_have_independent_xids(self):
        self.connect()
        nested_results = []

        def overlap(seconds):
            self.hub.sleep = self.reply_to_all
            nested_results.append(self.controller.synchronize())

        self.hub.sleep = overlap
        self.assertEqual(self.controller.synchronize(), (200, {'complete': True}))
        self.assertEqual(nested_results, [(200, {'complete': True})])
        self.assertEqual([message.xid for message in self.datapath.messages], [1, 2])


if __name__ == '__main__':
    unittest.main()
