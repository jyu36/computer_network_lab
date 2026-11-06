#!/usr/bin/env python3
"""Network lifecycle, controller API, host learning and switch rule inspection."""
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import urllib.error
import urllib.request
from pathlib import Path

from .topology import host_mac_address
from cases import SCENARIOS
from .results import BehaviorFailure
from .packet_observer import PacketObserver
from .processes import run_command, stop_process, wait_for_condition


# Mininet is a Linux dependency. Keep these imports optional so listing cases
# and importing checker helpers still work on a Mac without Mininet installed.
try:
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
except ModuleNotFoundError as error:
    if error.name != "mininet":
        raise  # Do not hide a broken installation or a missing dependency inside Mininet.
    Mininet = OVSSwitch = RemoteController = None

VALIDATION_DIRECTORY = Path(__file__).resolve().parents[1]
REQUIREMENT_STAGES = ["base", "blocklist", "movement", "runtime"]


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


class NetworkTestEnvironment(PacketObserver):
    """Manage one independent test case, its network, processes, and evidence."""

    def __init__(self, options, test_case, evidence_directory):
        """Store case settings and initialize resources without starting the network."""
        self.options, self.test_case, self.evidence_directory = (
            options,
            test_case,
            evidence_directory,
        )
        self.configuration = options.network_configuration
        self.host_names = self.configuration.host_names
        self.roles = self.configuration.roles
        aliases = {"$" + role: host for role, host in self.roles.items()}

        def resolve(value):
            if isinstance(value, str):
                return aliases.get(value, value)
            if isinstance(value, list):
                return [resolve(item) for item in value]
            if isinstance(value, dict):
                return {
                    aliases.get(key, key): resolve(item) for key, item in value.items()
                }
            return value

        self.test_case = resolve(test_case)
        self.network = self.controller_process = None
        self.checkpoint = "setup"
        self.observation_number = 0
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
        """Launch the selected controller and configured topology, then await readiness."""
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

        # Wait for the actual OpenFlow listener before Mininet checks it.
        def openflow_is_ready():
            """Check controller liveness and TCP readiness without creating a switch."""
            if self.controller_process.poll() is not None:
                raise RuntimeError("Controller exited; inspect controller.log")
            try:
                with socket.create_connection(
                    ("127.0.0.1", self.options.openflow_port), timeout=0.2
                ):
                    return True
            except OSError:
                return False

        wait_for_condition(openflow_is_ready, 15)
        # Create the configured switches and links. One controller manages them all.
        self.network = Mininet(controller=None, switch=OVSSwitch, build=False)
        self.network.addController(
            "c0",
            controller=RemoteController,
            ip="127.0.0.1",
            port=self.options.openflow_port,
        )
        switches = {
            name: self.network.addSwitch(
                name,
                protocols="OpenFlow13",
                failMode="secure",
                dpid="%016x" % int(name[1:]),
            )
            for name in self.configuration.switch_names
        }
        for host_name, (switch_name, port) in self.configuration.attachments.items():
            host_node = self.network.addHost(
                host_name,
                ip=self.configuration.host_ip(host_name),
                mac=host_mac_address(host_name),
            )
            self.network.addLink(host_node, switches[switch_name], port2=port)
        for left, left_port, right, right_port in self.configuration.links:
            self.network.addLink(
                switches[left], switches[right], port1=left_port, port2=right_port
            )
        self.network.build()

        # Disable IPv6 in each host because this experiment covers ARP/IPv4.
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
                for switch in self.configuration.switch_names:
                    dump = run_command(
                        ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch]
                    )
                    if "CONTROLLER" not in dump or "priority=0" not in dump:
                        return False
                return True

            wait_for_condition(switch_is_ready, 15)
        else:
            wait_for_condition(
                lambda: sorted(self.get_controller_status().get("switches", []))
                == list(range(1, len(self.configuration.switch_names) + 1))
            )
        # API mode also waits for update completion. Save the starting evidence.
        self.wait_for_controller_updates()
        self.save_network_snapshot("initial")

    def save_network_snapshot(self, snapshot_label):
        """Save labeled switch flow/port dumps and controller status when available."""
        # Save switch evidence even if the controller API has stopped responding.
        for switch in self.configuration.switch_names:
            for snapshot_kind, command_arguments in [
                ("flows", ["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch]),
                ("ports", ["ovs-ofctl", "-O", "OpenFlow13", "show", switch]),
            ]:
                try:
                    snapshot_text = run_command(command_arguments, check=False)
                except Exception as error:
                    snapshot_text = repr(error)
                (
                    self.evidence_directory
                    / (snapshot_label + "." + switch + "." + snapshot_kind + ".txt")
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

    def learn_host_locations(self, host_names=None):
        """Send ARP traffic so the controller can learn host locations naturally."""
        host_names = host_names or self.host_names
        for host_name in host_names:
            self.send_test_packets(
                host_name,
                (
                    self.host_names[0]
                    if host_name != self.host_names[0]
                    else self.host_names[1]
                ),
                packet_kind="arp",
            )
        if not self.options.stock_controller_mode:
            wait_for_condition(
                lambda: all(
                    self.get_controller_status()
                    .get("learned", {})
                    .get(str(int(switch[1:])), {})
                    .get(host_mac_address(host_name))
                    == self.configuration.port_toward_host(switch, host_name)
                    for switch in self.configuration.switch_names
                    for host_name in host_names
                )
            )
        self.wait_for_controller_updates()

    def establish_cached_forwarding(self, source_host_name, destination_host_name):
        """Send traffic and check for a destination forwarding rule in OVS.

        Checks priority, ingress match, destination match and the output port
        on every switch in the source-to-destination path.
        """
        self.assert_destination_delivery(source_host_name, destination_host_name)
        self.wait_for_controller_updates()
        source_switch = self.configuration.attachments[source_host_name][0]
        destination_switch = self.configuration.attachments[destination_host_name][0]
        for switch in self.configuration.path(source_switch, destination_switch):
            dump = run_command(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch])
            ingress = self.configuration.port_toward_host(switch, source_host_name)
            output = self.configuration.port_toward_host(switch, destination_host_name)
            assert any(
                "dl_dst=" + host_mac_address(destination_host_name) in entry
                and re.search(r"\bin_port=%d(?:,|\s)" % ingress, entry)
                and re.search(r"\bpriority=1(?:,|\s)", entry)
                and re.search(r"actions=(?:output:)?%d(?:,|$)" % output, entry)
                for entry in dump.splitlines()
            ), "Required cached forwarding rule absent on %s: %s" % (switch, dump)
        self.save_network_snapshot(
            "cached_%s_%s" % (source_host_name, destination_host_name)
        )

    def forwarding_packet_counts(self, source_host_name, destination_host_name):
        """Read counters for the exact learned rule on each switch in the path."""
        source_switch = self.configuration.attachments[source_host_name][0]
        destination_switch = self.configuration.attachments[destination_host_name][0]
        counts = {}
        for switch in self.configuration.path(source_switch, destination_switch):
            dump = run_command(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch])
            ingress = self.configuration.port_toward_host(switch, source_host_name)
            matches = [
                entry
                for entry in dump.splitlines()
                if "dl_dst=" + host_mac_address(destination_host_name) in entry
                and re.search(r"\bin_port=%d(?:,|\s)" % ingress, entry)
                and re.search(r"\bpriority=1(?:,|\s)", entry)
            ]
            assert len(matches) == 1, "Expected exactly one learned rule on " + switch
            counter = re.search(r"\bn_packets=(\d+)", matches[0])
            if counter is None:
                raise RuntimeError("Missing OVS packet counter: " + matches[0])
            counts[switch] = int(counter.group(1))
        return counts

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
        """Move a host to an unused port on its switch and verify relearning."""
        switch, old_port = self.configuration.attachments[moved_host_name]
        new_port = self.configuration.unused_port(switch)
        interface = "%s-eth%d" % (switch, old_port)
        run_command(
            ["ovs-vsctl", "set", "Interface", interface, "ofport_request=%d" % new_port]
        )
        wait_for_condition(
            lambda: run_command(
                ["ovs-vsctl", "get", "Interface", interface, "ofport"]
            ).strip()
            == str(new_port)
        )
        self.configuration.attachments[moved_host_name] = (switch, new_port)
        peer = next(host for host in self.host_names if host != moved_host_name)
        self.send_test_packets(moved_host_name, peer, packet_kind="arp")
        try:
            wait_for_condition(
                lambda: self.get_controller_status()
                .get("learned", {})
                .get(str(int(switch[1:])), {})
                .get(host_mac_address(moved_host_name))
                == new_port
            )
        except TimeoutError as error:
            raise BehaviorFailure(
                "host_location", "Moved source was not learned on port %d" % new_port
            ) from error
        self.wait_for_controller_updates()
        self.save_network_snapshot("after_move")
        dump = run_command(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", switch])
        stale = [
            entry
            for entry in dump.splitlines()
            if "dl_dst=" + host_mac_address(moved_host_name) in entry
            and re.search(r"actions=(?:output:)?%d(?:,|$)" % old_port, entry)
        ]
        assert not stale, "Stale destination rules survived move: " + "\n".join(stale)

    def run_test_scenario(self):
        """Dispatch this case to its named scenario function."""
        SCENARIOS[self.test_case["scenario"]](self)
        self.wait_for_controller_updates()

    def cleanup(self):
        """Save final evidence and stop this case's captures, network, and controller."""
        for child_process in self.capture_processes:
            stop_process(child_process)
        try:
            if self.network is not None:
                try:
                    self.save_network_snapshot("final")
                finally:
                    self.network.stop()
        finally:
            if self.controller_process is not None:
                stop_process(self.controller_process)
            if self.controller_log_file is not None:
                self.controller_log_file.close()
            (self.evidence_directory / "events.json").write_text(
                json.dumps(self.recorded_events, indent=2)
            )


def check_service_port_available(service_port):
    """Allow reuse after TCP shutdown while rejecting an existing listener."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as port_check_socket:
            # Ryu's listeners reuse addresses too. A plain bind can incorrectly
            # reject a recently closed connection that is still in TIME_WAIT.
            port_check_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            port_check_socket.bind(("127.0.0.1", service_port))
            port_check_socket.listen(1)
    except OSError as error:
        raise RuntimeError(
            "Cannot reserve controller TCP port %d: %s. "
            "Check active listeners in Ubuntu with sudo ss -ltnp; "
            "stop the process using this port before retrying." % (service_port, error)
        ) from error


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
    if set(options.network_configuration.switch_names) & set(existing_bridges):
        raise RuntimeError(
            "s1 already exists. Exit your manual Mininet session before testing."
        )
    for service_port in (
        [options.openflow_port]
        if options.stock_controller_mode
        else [options.openflow_port, options.controller_api_port]
    ):
        check_service_port_available(service_port)
    if Mininet is None:
        raise RuntimeError(
            "Mininet is not installed in this Python environment; use the Ubuntu system Python"
        )
