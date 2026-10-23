#!/usr/bin/env python3
"""Linux/Mininet integration checker. Each case gets a fresh controller + switch."""
import argparse
import datetime
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

# Mininet is a Linux dependency. Keep these imports optional so listing cases
# and importing checker helpers still work on a Mac without Mininet installed.
try:
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
except ModuleNotFoundError as error:
    if error.name != "mininet":
        raise  # Do not hide a broken installation or a missing dependency inside Mininet.
    Mininet = OVSSwitch = RemoteController = None

VALIDATION_DIRECTORY = Path(__file__).resolve().parent
REQUIREMENT_STAGES = ["base", "blocklist", "movement", "runtime"]
HOST_NAMES = ["h1", "h2", "h3"]


def host_mac_address(host_name):
    """Return the fixed MAC address assigned to a host such as h1 or h2."""
    return "00:00:00:00:00:%02x" % int(host_name[1:])


def load_test_cases(case_file_path, requested_stage):
    """Read unique case IDs and select the requested stage plus earlier stages."""
    test_cases = json.loads(Path(case_file_path).read_text())
    if len({test_case["id"] for test_case in test_cases}) != len(test_cases):
        raise ValueError("Duplicate case IDs")
    return [
        test_case
        for test_case in test_cases
        if REQUIREMENT_STAGES.index(test_case["stage"])
        <= REQUIREMENT_STAGES.index(requested_stage)
    ]


def wait_for_condition(condition, timeout_seconds=8):
    """Poll a condition until it returns a truthy value, or raise on timeout."""
    deadline_seconds = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline_seconds:
        condition_result = condition()
        if condition_result:
            return condition_result
        time.sleep(0.05)
    raise TimeoutError("Readiness/observation deadline exceeded")


def run_command(command_arguments, check=True):
    """Run a command with a timeout and return its standard output as text."""
    return subprocess.run(
        command_arguments, capture_output=True, text=True, timeout=15, check=check
    ).stdout


def stop_process(child_process):
    """Interrupt a running process, then kill it if it does not stop promptly."""
    if child_process.poll() is None:
        child_process.send_signal(signal.SIGINT)
        try:
            child_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child_process.kill()
            child_process.wait()


class NetworkTestEnvironment:
    """Manage one independent test case, its network, processes, and evidence."""

    def __init__(self, options, test_case, evidence_directory):
        """Store case settings and initialize resources without starting the network."""
        self.options, self.test_case, self.evidence_directory = (
            options,
            test_case,
            evidence_directory,
        )
        self.network = self.controller_process = None
        self.packet_identifier = 100
        self.recorded_events = []
        self.capture_processes = []
        self.controller_log_file = None

    def send_controller_request(
        self, method, api_endpoint, json_body=None, expected_http_status=200
    ):
        """Call the controller API, record the exchange, and check the HTTP status."""
        request_body = None if json_body is None else json.dumps(json_body).encode()
        http_request = urllib.request.Request(
            "http://127.0.0.1:%d/rain/%s"
            % (self.options.controller_api_port, api_endpoint),
            data=request_body,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(http_request, timeout=6) as response:
                http_status, response_bytes = response.status, response.read()
        except urllib.error.HTTPError as error:
            http_status, response_bytes = error.code, error.read()
        self.recorded_events.append(
            {
                "method": method,
                "path": api_endpoint,
                "body": json_body,
                "status": http_status,
                "response": response_bytes.decode(errors="replace"),
            }
        )
        assert http_status == expected_http_status, "%s %s returned %s, expected %s" % (
            method,
            api_endpoint,
            http_status,
            expected_http_status,
        )
        return json.loads(response_bytes) if response_bytes else None

    def wait_for_controller_updates(self):
        """Require the API's update-completion signal; skip it in stock-base mode."""
        if self.options.stock_controller_mode:
            return  # Base observations use packet/flow evidence; no invented API acknowledgement.
        completion_response = self.send_controller_request("POST", "sync")
        assert completion_response.get("complete") is True, completion_response

    def get_controller_status(self):
        """Read controller state and reject reported OpenFlow errors."""
        controller_status = self.send_controller_request("GET", "status")
        assert not controller_status.get("errors"), controller_status
        return controller_status

    def start_network_and_controller(self):
        """Launch a fresh controller and three-host network, then wait for readiness."""
        # 1. Set the initial destination blocklist required by this test case.
        # Pass it to the expanded controller through its environment; stock Ryu
        # does not implement this policy interface.
        controller_environment = os.environ.copy()
        initial_blocked_macs = (
            [host_mac_address(self.test_case["blocked"])]
            if self.test_case["scenario"] in {"static", "static_unknown", "move_block"}
            else []
        )
        if "initial_blocked" in self.test_case:
            initial_blocked_macs = [
                host_mac_address(host_name)
                for host_name in self.test_case["initial_blocked"]
            ]
        controller_environment.update(RAIN_BLOCKED=json.dumps(initial_blocked_macs))
        # Select bugs through separate controller files, not an inherited flag.
        controller_environment.pop("RAIN_BUG", None)

        # 3. Open the log used below for both controller stdout and stderr.
        self.controller_log_file = (self.evidence_directory / "controller.log").open(
            "w"
        )
        # 2. Build the Ryu launch command for the selected controller source.
        command_arguments = [
            self.options.ryu_manager,
            "--ofp-listen-host",
            "127.0.0.1",
            "--ofp-tcp-listen-port",
            str(self.options.openflow_port),
            "--wsapi-host",
            "127.0.0.1",
            "--wsapi-port",
            str(self.options.controller_api_port),
            str(Path(self.options.controller_path).resolve()),
        ]
        (self.evidence_directory / "launch.json").write_text(
            json.dumps(
                {"command": command_arguments, "RAIN_BLOCKED": initial_blocked_macs},
                indent=2,
            )
        )
        # 2 and 3. Start Ryu as a background process and redirect output to the log.
        self.controller_process = subprocess.Popen(
            command_arguments,
            env=controller_environment,
            stdout=self.controller_log_file,
            stderr=subprocess.STDOUT,
        )

        def controller_api_is_ready():
            """Report API readiness, retrying connection errors while Ryu starts."""
            if self.controller_process.poll() is not None:
                raise RuntimeError("Controller exited; inspect controller.log")
            try:
                return self.send_controller_request("GET", "status")
            except (OSError, TimeoutError):
                return False

        if not self.options.stock_controller_mode:
            wait_for_condition(controller_api_is_ready, 15)

        # 4. Create one OVS switch using OpenFlow 1.3. RemoteController connects
        # OVS to the Ryu process above; it does not launch a second controller.
        self.network = Mininet(controller=None, switch=OVSSwitch, build=False)
        self.network.addController(
            "c0",
            controller=RemoteController,
            ip="127.0.0.1",
            port=self.options.openflow_port,
        )
        switch_node = self.network.addSwitch(
            "s1", protocols="OpenFlow13", failMode="secure", dpid="0000000000000001"
        )
        for switch_port_number, host_name in enumerate(HOST_NAMES, 1):
            # 5. Create h1, h2, and h3 with fixed IP and MAC addresses.
            host_node = self.network.addHost(
                host_name,
                ip="10.0.0.%s/24" % switch_port_number,
                mac=host_mac_address(host_name),
            )
            # 6. Connect each host to switch port 1, 2, or 3 respectively.
            self.network.addLink(host_node, switch_node, port2=switch_port_number)
        self.network.build()

        # 7. Disable IPv6 in each host because this experiment covers ARP/IPv4.
        for host_node in self.network.hosts:
            host_node.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=1")
            host_node.cmd("sysctl -qw net.ipv6.conf.default.disable_ipv6=1")
        self.network.start()

        # 8. Wait for readiness before sending test traffic. Stock-base mode
        # looks for the table-miss rule; API mode checks switch registration.
        if self.options.stock_controller_mode:

            def switch_is_ready():
                """Check that Ryu is alive and OVS has a controller table-miss rule."""
                if self.controller_process.poll() is not None:
                    raise RuntimeError("Controller exited; inspect controller.log")
                flow_table_dump = run_command(
                    ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"]
                )
                return (
                    "CONTROLLER" in flow_table_dump and "priority=0" in flow_table_dump
                )

            wait_for_condition(switch_is_ready, 15)
        else:
            wait_for_condition(
                lambda: self.get_controller_status().get("switches") == [1]
            )
        # API mode also waits for update completion. Save the starting evidence.
        self.wait_for_controller_updates()
        self.save_network_snapshot("initial")

    def save_network_snapshot(self, snapshot_label):
        """Save labeled switch flow/port dumps and controller status when available."""
        # Save switch evidence even if the controller API has stopped responding.
        for snapshot_kind, command_arguments in [
            ("flows", ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"]),
            ("ports", ["ovs-ofctl", "-O", "OpenFlow13", "show", "s1"]),
        ]:
            try:
                snapshot_text = run_command(command_arguments, check=False)
            except Exception as error:
                snapshot_text = repr(error)
            (
                self.evidence_directory
                / (snapshot_label + "." + snapshot_kind + ".txt")
            ).write_text(snapshot_text)
        if self.options.stock_controller_mode:
            return
        try:
            (self.evidence_directory / (snapshot_label + ".status.json")).write_text(
                json.dumps(self.get_controller_status(), indent=2)
            )
        except Exception as error:
            (self.evidence_directory / (snapshot_label + ".api-error.txt")).write_text(
                repr(error)
            )

    def send_test_packets(
        self,
        source_host_name,
        destination_host_name,
        packet_kind="icmp",
        packet_count=3,
    ):
        """Run send_test_packets.py inside the source host to send tagged ICMP or ARP frames."""
        host_node = self.network.get(source_host_name)
        command_arguments = [
            "python3",
            str(VALIDATION_DIRECTORY / "send_test_packets.py"),
            "--interface",
            str(host_node.defaultIntf()),
            "--src-mac",
            host_mac_address(source_host_name),
            "--dst-mac",
            host_mac_address(destination_host_name),
            "--src-ip",
            host_node.IP(),
            "--dst-ip",
            self.network.get(destination_host_name).IP(),
            "--tag",
            str(self.packet_identifier),
            "--kind",
            packet_kind,
            "--count",
            str(packet_count),
        ]
        child_process = host_node.popen(
            command_arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        probe_stdout, probe_stderr = child_process.communicate(timeout=5)
        if child_process.returncode:
            raise RuntimeError("Probe failed: %s %s" % (probe_stdout, probe_stderr))

    def learn_host_locations(self, host_names=HOST_NAMES):
        """Send ARP traffic so the controller can learn host locations naturally."""
        for host_name in host_names:
            self.send_test_packets(
                host_name, "h1" if host_name != "h1" else "h2", packet_kind="arp"
            )
        if not self.options.stock_controller_mode:
            wait_for_condition(
                lambda: all(
                    host_mac_address(host_name)
                    in self.get_controller_status().get("learned", {}).get("1", {})
                    for host_name in host_names
                )
            )
        self.wait_for_controller_updates()

    def assert_packet_delivery(
        self,
        source_host_name,
        destination_host_name,
        receiver_host_names,
        expected_delivery=True,
        packet_count=3,
    ):
        """Capture tagged requests at receivers and assert their expected counts.

        expected_delivery can be one Boolean for all receivers or a host-to-Boolean map.
        Non-delivery is measured within the configured observation window.
        """
        self.packet_identifier += 1
        receiver_captures = []
        try:
            for receiver_host_name in receiver_host_names:
                host_node = self.network.get(receiver_host_name)
                capture_filename_stem = "%03d_%s_to_%s_at_%s" % (
                    self.packet_identifier,
                    source_host_name,
                    destination_host_name,
                    receiver_host_name,
                )
                capture_path, capture_log_path = self.evidence_directory / (
                    capture_filename_stem + ".pcap"
                ), self.evidence_directory / (capture_filename_stem + ".tcpdump.log")
                capture_log_file = capture_log_path.open("w")
                packet_filter = (
                    "icmp and icmp[0] = 8 and icmp[4:2] = %d and ether dst %s"
                    % (self.packet_identifier, host_mac_address(destination_host_name))
                )
                child_process = host_node.popen(
                    [
                        "tcpdump",
                        "-U",
                        "-n",
                        "-i",
                        str(host_node.defaultIntf()),
                        "-w",
                        str(capture_path),
                        packet_filter,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=capture_log_file,
                )
                receiver_captures.append(
                    (
                        child_process,
                        capture_log_file,
                        capture_path,
                        capture_log_path,
                        receiver_host_name,
                    )
                )
                self.capture_processes.append(child_process)

                def capture_is_ready():
                    """Confirm tcpdump is listening before the sender transmits."""
                    if child_process.poll() is not None:
                        raise RuntimeError(
                            "tcpdump exited: " + capture_log_path.read_text()
                        )
                    return "listening on" in capture_log_path.read_text()

                wait_for_condition(capture_is_ready, 4)
            self.send_test_packets(
                source_host_name, destination_host_name, packet_count=packet_count
            )
            time.sleep(
                self.options.observation_seconds
            )  # Observation bound, not update synchronization.
        finally:
            for child_process, capture_log_file, *_ in receiver_captures:
                stop_process(child_process)
                capture_log_file.close()
        for (
            child_process,
            _,
            capture_path,
            capture_log_path,
            receiver_host_name,
        ) in receiver_captures:
            if child_process.returncode not in (0, -signal.SIGINT):
                raise RuntimeError(
                    "Capture process failed: " + capture_log_path.read_text()
                )
            capture_drop_match = re.search(
                r"(?m)^(\d+) packets dropped by kernel\s*$",
                capture_log_path.read_text(),
            )
            if not capture_drop_match or int(capture_drop_match.group(1)) != 0:
                raise RuntimeError(
                    "Unreliable capture: " + capture_log_path.read_text()
                )
            decoded_packets = run_command(["tcpdump", "-nn", "-r", str(capture_path)])
            capture_path.with_suffix(".packets.txt").write_text(decoded_packets)
            received_packet_count = len(decoded_packets.splitlines())
            receiver_should_receive = (
                expected_delivery[receiver_host_name]
                if isinstance(expected_delivery, dict)
                else expected_delivery
            )
            self.recorded_events.append(
                {
                    "source": source_host_name,
                    "destination": destination_host_name,
                    "receiver": receiver_host_name,
                    "sent": packet_count,
                    "received": received_packet_count,
                    "allowed": receiver_should_receive,
                }
            )
            assert received_packet_count == (
                packet_count if receiver_should_receive else 0
            ), "%s -> %s at %s: expected %s packets, observed %s; see %s" % (
                source_host_name,
                destination_host_name,
                receiver_host_name,
                packet_count if receiver_should_receive else 0,
                received_packet_count,
                capture_path.name,
            )

    def assert_destination_delivery(
        self, source_host_name, destination_host_name, expected_delivery=True
    ):
        """Check packet delivery or non-delivery at the destination host only."""
        self.assert_packet_delivery(
            source_host_name,
            destination_host_name,
            [destination_host_name],
            expected_delivery,
        )

    def establish_cached_forwarding(self, source_host_name, destination_host_name):
        """Send traffic and check for a destination forwarding rule in OVS.

        This currently checks presence and output, not every contract field
        or whether the rule's packet counter increases.
        """
        self.assert_destination_delivery(source_host_name, destination_host_name)
        self.wait_for_controller_updates()
        flow_table_dump = run_command(
            ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"]
        )
        source_port_number = int(source_host_name[1:])
        matching_forwarding_rules = [
            flow_entry
            for flow_entry in flow_table_dump.splitlines()
            if "dl_dst=" + host_mac_address(destination_host_name) in flow_entry
            and (
                "in_port=" not in flow_entry
                or "in_port=%d," % source_port_number in flow_entry
            )
            and re.search(
                r"actions=(?:output:)?%d(?:,|$)" % int(destination_host_name[1:]),
                flow_entry,
            )
        ]
        assert matching_forwarding_rules, (
            "Required cached forwarding rule absent: " + flow_table_dump
        )
        self.save_network_snapshot(
            "cached_%s_%s" % (source_host_name, destination_host_name)
        )

    def replace_destination_blocklist(self, blocked_host_names):
        """Replace the runtime destination blocklist and require API completion."""
        completion_response = self.send_controller_request(
            "PUT",
            "policy",
            {
                "blocked": [
                    host_mac_address(host_name) for host_name in blocked_host_names
                ]
            },
        )
        assert (
            completion_response.get("complete") is True
        ), "Policy response must acknowledge BarrierReply"

    def relocate_host_port(self, moved_host_name):
        """Renumber a host's OVS port to 4, trigger learning, and check stale rules."""
        # Change only the OVS ingress/output port number; host interface, MAC and IP stay fixed.
        switch_interface_name = "s1-eth" + moved_host_name[1:]
        run_command(
            ["ovs-vsctl", "set", "Interface", switch_interface_name, "ofport_request=4"]
        )
        wait_for_condition(
            lambda: run_command(
                ["ovs-vsctl", "get", "Interface", switch_interface_name, "ofport"]
            ).strip()
            == "4"
        )
        # The controller must actually observe the new source location first.
        self.send_test_packets(moved_host_name, "h1", packet_kind="arp")
        try:
            wait_for_condition(
                lambda: self.get_controller_status()
                .get("learned", {})
                .get("1", {})
                .get(host_mac_address(moved_host_name))
                == 4
            )
        except TimeoutError as error:
            raise AssertionError("Moved source was not learned on port 4") from error
        self.wait_for_controller_updates()
        self.save_network_snapshot("after_move")
        flow_table_dump = run_command(
            ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", "s1"]
        )
        stale_forwarding_rules = [
            flow_entry
            for flow_entry in flow_table_dump.splitlines()
            if "dl_dst=" + host_mac_address(moved_host_name) in flow_entry
            and "actions=output:" + moved_host_name[1:] in flow_entry
        ]
        assert (
            not stale_forwarding_rules
        ), "Stale destination rules survived move: " + "\n".join(stale_forwarding_rules)

    def run_test_scenario(self):
        """Execute the selected case's action sequence and behavior assertions."""
        scenario_name = self.test_case["scenario"]
        if scenario_name == "trace":
            # Reserve cases can describe an explicit sequence of these operations.
            for event_step in self.test_case["steps"]:
                event_operation = event_step["op"]
                if event_operation == "learn":
                    self.learn_host_locations()
                elif event_operation == "cache":
                    self.establish_cached_forwarding(
                        event_step["source"], event_step["destination"]
                    )
                elif event_operation == "observe":
                    self.assert_packet_delivery(
                        event_step["source"],
                        event_step["destination"],
                        list(event_step["expect"]),
                        event_step["expect"],
                    )
                elif event_operation == "move":
                    self.relocate_host_port(event_step["host"])
                elif event_operation == "policy":
                    self.replace_destination_blocklist(event_step["blocked"])
                else:
                    raise ValueError("Unknown trace operation: " + event_operation)
        elif scenario_name == "unknown":
            # B01: an unknown unicast destination should be flooded to both peers.
            if not self.options.stock_controller_mode:
                assert (
                    self.get_controller_status()["learned"]["1"] == {}
                ), "Fresh controller was not empty"
            self.assert_packet_delivery("h1", "h2", ["h2", "h3"], packet_count=1)
        elif scenario_name == "ping":
            # B03: normal ARP resolution and ICMP round trips must work all-pairs.
            packet_loss_percent = self.network.pingAll(timeout="1")
            self.recorded_events.append({"pingall_loss_percent": packet_loss_percent})
            assert packet_loss_percent == 0, (
                "ARP/ICMP pingall loss: %s%%" % packet_loss_percent
            )
        elif scenario_name == "static_unknown":
            # P02: policy must apply even before the destination has been learned.
            self.assert_destination_delivery("h1", self.test_case["blocked"], False)
            other_host_name = next(
                host_name
                for host_name in ["h2", "h3"]
                if host_name != self.test_case["blocked"]
            )
            self.assert_destination_delivery("h1", other_host_name)
        else:
            # Remaining cases start with learned locations, then change conditions.
            self.learn_host_locations()
            if scenario_name == "known":
                # B02: check delivery and absence of leakage for all six directions.
                for source_host_name in HOST_NAMES:
                    for destination_host_name in HOST_NAMES:
                        if source_host_name == destination_host_name:
                            continue
                        other_host_name = next(
                            host_name
                            for host_name in HOST_NAMES
                            if host_name
                            not in {source_host_name, destination_host_name}
                        )
                        self.establish_cached_forwarding(
                            source_host_name, destination_host_name
                        )
                        self.assert_packet_delivery(
                            source_host_name,
                            destination_host_name,
                            [destination_host_name, other_host_name],
                            {destination_host_name: True, other_host_name: False},
                        )
            elif scenario_name == "static":
                # P01: block destinations, while retaining allowed source traffic.
                blocked_host_name = self.test_case["blocked"]
                other_host_name = next(
                    host_name
                    for host_name in ["h2", "h3"]
                    if host_name != blocked_host_name
                )
                self.assert_destination_delivery(
                    "h1", other_host_name
                )  # Live allowed path, even under policy.
                self.assert_destination_delivery("h1", blocked_host_name, False)
                self.assert_destination_delivery(
                    blocked_host_name, "h1"
                )  # Source is allowed: destination-only policy.
            elif scenario_name in {"move", "move_block"}:
                # M01/M02: preserve cached state through movement and check recovery.
                moved_host_name = self.test_case["moved"]
                self.establish_cached_forwarding("h1", moved_host_name)
                self.relocate_host_port(moved_host_name)
                self.assert_destination_delivery("h1", moved_host_name)
                self.assert_destination_delivery(moved_host_name, "h1")
                if scenario_name == "move_block":
                    self.assert_destination_delivery(
                        "h1", self.test_case["blocked"], False
                    )
            elif scenario_name == "runtime":
                # R01: update policy without restarting or clearing cached flows.
                blocked_host_name = self.test_case["blocked"]
                other_host_name = next(
                    host_name
                    for host_name in ["h2", "h3"]
                    if host_name != blocked_host_name
                )
                self.establish_cached_forwarding("h1", blocked_host_name)
                self.replace_destination_blocklist([blocked_host_name])
                self.save_network_snapshot("after_block")
                self.assert_destination_delivery("h1", other_host_name)
                self.assert_destination_delivery(
                    "h1", blocked_host_name, False
                )  # Existing cached path.
                self.assert_destination_delivery(
                    other_host_name, blocked_host_name, False
                )  # New ingress/destination pair.
                self.assert_destination_delivery(blocked_host_name, "h1")
                self.replace_destination_blocklist([])
                self.assert_destination_delivery("h1", blocked_host_name)
                # Repeat to expose stale state across successive updates.
                self.replace_destination_blocklist([blocked_host_name])
                self.assert_destination_delivery("h1", blocked_host_name, False)
                self.replace_destination_blocklist([])
                self.assert_destination_delivery("h1", blocked_host_name)
            elif scenario_name == "invalid":
                # R02: malformed updates must leave policy and forwarding intact.
                self.replace_destination_blocklist(["h2"])
                previous_blocklist = self.get_controller_status()["blocked"]
                for request_body in [
                    {"blocked": ["invalid"]},
                    {"blocked": "not-a-list"},
                    {},
                    {"blocked": [12]},
                    {"blocked": [], "extra": True},
                    [],
                    None,
                ]:
                    self.send_controller_request(
                        "PUT", "policy", request_body, expected_http_status=400
                    )
                    assert (
                        self.get_controller_status()["blocked"] == previous_blocklist
                    ), "Invalid input mutated policy"
                self.assert_destination_delivery("h1", "h2", False)
                self.assert_destination_delivery("h1", "h3")
            else:
                raise ValueError("Unknown scenario: " + scenario_name)
        self.wait_for_controller_updates()

    def cleanup(self):
        """Save final evidence and stop this case's captures, network, and controller."""
        for child_process in self.capture_processes:
            stop_process(child_process)
        try:
            if self.network is not None:
                self.save_network_snapshot("final")
                self.network.stop()
        finally:
            if self.controller_process is not None:
                stop_process(self.controller_process)
            if self.controller_log_file is not None:
                self.controller_log_file.close()
            (self.evidence_directory / "events.json").write_text(
                json.dumps(self.recorded_events, indent=2)
            )


def validate_test_environment(options):
    """Check Linux/root privileges, dependencies, and unused switch/port resources."""
    if platform.system() != "Linux" or os.geteuid() != 0:
        raise RuntimeError("Run in your Ubuntu Mininet VM as root; see README.md")
    for tool_name in ["ovs-vsctl", "ovs-ofctl", "tcpdump", "python3"]:
        if not shutil.which(tool_name):
            raise RuntimeError("Missing command: " + tool_name)
    if not shutil.which(options.ryu_manager):
        raise RuntimeError(
            "Provide --ryu-manager /absolute/path/to/venv/bin/ryu-manager"
        )
    if not Path(options.controller_path).is_file():
        raise RuntimeError("Controller file not found")
    existing_bridges = run_command(["ovs-vsctl", "list-br"]).splitlines()
    if "s1" in existing_bridges:
        raise RuntimeError(
            "s1 already exists. Exit your manual Mininet session before testing."
        )
    for service_port in (
        [options.openflow_port]
        if options.stock_controller_mode
        else [options.openflow_port, options.controller_api_port]
    ):
        with socket.socket() as port_check_socket:
            port_check_socket.bind(("127.0.0.1", service_port))
    if Mininet is None:
        raise RuntimeError(
            "Mininet is not installed in this Python environment; use the Ubuntu system Python"
        )


def main():
    """Parse CLI options, run the selected cases independently, and save results."""
    # Read the controller path, test stage, and evidence settings from the command.
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--stage", choices=REQUIREMENT_STAGES, default="base")
    argument_parser.add_argument(
        "--controller",
        dest="controller_path",
        required=True,
        help="Path to the actual controller source",
    )
    argument_parser.add_argument(
        "--stock-controller",
        "--stock-base",
        dest="stock_controller_mode",
        action="store_true",
        help="Base tests without the custom HTTP API",
    )
    argument_parser.add_argument(
        "--ryu-manager", default=shutil.which("ryu-manager") or "ryu-manager"
    )
    argument_parser.add_argument(
        "--case-file",
        "--cases",
        dest="case_file_path",
        default=str(VALIDATION_DIRECTORY / "development_cases.json"),
    )
    argument_parser.add_argument(
        "--case-id", "--case", dest="test_case_id", help="Run one case by exact ID"
    )
    argument_parser.add_argument(
        "--openflow-port", "--of-port", dest="openflow_port", type=int, default=6653
    )
    argument_parser.add_argument(
        "--controller-api-port",
        "--api-port",
        dest="controller_api_port",
        type=int,
        default=8080,
    )
    argument_parser.add_argument(
        "--results-directory",
        "--output",
        dest="results_directory",
        default=str(VALIDATION_DIRECTORY / "results"),
    )
    argument_parser.add_argument(
        "--observation-seconds",
        "--observe-seconds",
        dest="observation_seconds",
        type=float,
        default=1.0,
    )
    argument_parser.add_argument(
        "--list-cases", "--list", dest="list_cases", action="store_true"
    )
    options = argument_parser.parse_args()
    if not 0 < options.observation_seconds <= 60:
        argument_parser.error("--observe-seconds must be in (0, 60]")
    if options.stock_controller_mode and options.stage != "base":
        argument_parser.error(
            "--stock-base only supports --stage base; later stages need the agreed update interface"
        )
    if not __debug__:
        argument_parser.error(
            "Assertions are required: do not use python -O or PYTHONOPTIMIZE"
        )
    # Select cumulative-stage cases; --case can narrow this to one named case.
    test_cases = load_test_cases(options.case_file_path, options.stage)
    if options.test_case_id:
        test_cases = [
            test_case
            for test_case in test_cases
            if test_case["id"] == options.test_case_id
        ]
    if not test_cases:
        argument_parser.error("No matching cases; check --stage and --case")
    if options.list_cases:
        print(json.dumps(test_cases, indent=2))
        return 0
    validate_test_environment(options)
    # Record which source and environment produced this timestamped experiment.
    run_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%dT%H%M%S.%fZ"
    )
    evidence_directory = Path(options.results_directory).resolve() / (
        run_timestamp + "_" + Path(options.controller_path).stem
    )
    evidence_directory.mkdir(parents=True)
    environment_details = {
        "platform": platform.platform(),
        "python": sys.version,
        "arguments": vars(options),
    }
    controller_source_bytes = Path(options.controller_path).read_bytes()
    environment_details["controller_sha256"] = hashlib.sha256(
        controller_source_bytes
    ).hexdigest()
    (evidence_directory / "controller_source.py").write_bytes(controller_source_bytes)
    for component_name, command_arguments in [
        ("ovs", ["ovs-vsctl", "--version"]),
        ("tcpdump", ["tcpdump", "--version"]),
        ("mininet", ["mn", "--version"]),
        ("ryu", [options.ryu_manager, "--version"]),
    ]:
        try:
            environment_details[component_name] = run_command(
                command_arguments, check=False
            )
        except Exception as error:
            environment_details[component_name] = repr(error)
    (evidence_directory / "environment.json").write_text(
        json.dumps(environment_details, indent=2)
    )
    case_results = []
    for test_case in test_cases:
        # Each independent case gets its own controller, network, and evidence folder.
        case_evidence_directory = evidence_directory / test_case["id"]
        case_evidence_directory.mkdir()
        test_environment = NetworkTestEnvironment(
            options, test_case, case_evidence_directory
        )
        test_result = {"id": test_case["id"], "status": "PASS"}
        try:
            test_environment.start_network_and_controller()
            test_environment.run_test_scenario()
        except AssertionError as error:
            test_result.update(
                status="FAIL", error=str(error), traceback=traceback.format_exc()
            )
        except Exception as error:
            test_result.update(
                status="ERROR", error=str(error), traceback=traceback.format_exc()
            )
        finally:
            # Attempt cleanup even after a failed assertion or execution error.
            try:
                test_environment.cleanup()
            except Exception as error:
                test_result.update(status="ERROR", cleanup_error=repr(error))
        (case_evidence_directory / "result.json").write_text(
            json.dumps(test_result, indent=2)
        )
        case_results.append(test_result)
        print(
            "%s %s %s"
            % (test_result["status"], test_case["id"], test_result.get("error", "")),
            flush=True,
        )
    # Return success only when every selected case passed.
    (evidence_directory / "summary.json").write_text(json.dumps(case_results, indent=2))
    print("Evidence:", evidence_directory)
    return (
        0 if all(case_result["status"] == "PASS" for case_result in case_results) else 1
    )


if __name__ == "__main__":
    # Running this file directly starts the CLI and returns its exit code to the shell.
    sys.exit(main())
