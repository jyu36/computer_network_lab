"""Send uniquely tagged probes and verify packet captures inside host namespaces."""

import re
import signal
import subprocess
import time
from pathlib import Path
from .topology import host_mac_address
from .processes import run_command, stop_process, wait_for_condition
from .results import BehaviorFailure


class PacketObserver:
    """Packet operations shared by all network scenarios."""

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
            str(Path(__file__).with_name("send_test_packets.py")),
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
        try:
            probe_stdout, probe_stderr = child_process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stop_process(child_process)
            raise
        if child_process.returncode:
            raise RuntimeError("Probe failed: %s %s" % (probe_stdout, probe_stderr))

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
        self.observation_number += 1
        self.packet_identifier = self.packet_identifier % 65535 + 1
        receiver_captures = []
        try:
            for receiver_host_name in receiver_host_names:
                host_node = self.network.get(receiver_host_name)
                capture_filename_stem = "%03d_%s_to_%s_at_%s" % (
                    self.observation_number,
                    source_host_name,
                    destination_host_name,
                    receiver_host_name,
                )
                capture_path, capture_log_path = (
                    self.evidence_directory / (capture_filename_stem + ".pcap"),
                    self.evidence_directory / (capture_filename_stem + ".tcpdump.log"),
                )
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
            time.sleep(self.options.observation_seconds)
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
                "(?m)^(\\d+) packets dropped by kernel\\s*$",
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
            expected_count = packet_count if receiver_should_receive else 0
            if received_packet_count != expected_count:
                raise BehaviorFailure(
                    "packet_delivery",
                    "%s -> %s at %s: expected %d packets, observed %d; see %s"
                    % (
                        source_host_name,
                        destination_host_name,
                        receiver_host_name,
                        expected_count,
                        received_packet_count,
                        capture_path.name,
                    ),
                    expected=expected_count,
                    observed=received_packet_count,
                    receiver=receiver_host_name,
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
