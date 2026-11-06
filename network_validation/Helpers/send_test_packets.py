"""Send tagged ARP or IPv4 ICMP frames from a Mininet host using raw sockets."""

import argparse
import socket
import struct
import time


def mac_address_to_bytes(mac_address):
    """Convert a colon-separated MAC address into six Ethernet header bytes."""
    return bytes.fromhex(mac_address.replace(":", ""))


def calculate_internet_checksum(packet_bytes):
    """Calculate the 16-bit checksum used by the IPv4 and ICMP headers."""
    if len(packet_bytes) % 2:
        packet_bytes += b"\x00"
    checksum_sum = sum(struct.unpack("!%dH" % (len(packet_bytes) // 2), packet_bytes))
    while checksum_sum >> 16:
        checksum_sum = (checksum_sum & 65535) + (checksum_sum >> 16)
    return (~checksum_sum) & 65535


def build_test_frame(
    source_mac,
    destination_mac,
    source_ip,
    destination_ip,
    packet_identifier,
    packet_kind,
):
    """Build an ARP broadcast request or a tagged IPv4 ICMP echo request."""
    if packet_kind == "arp":
        arp_payload = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        arp_payload += mac_address_to_bytes(source_mac) + socket.inet_aton(source_ip)
        arp_payload += b"\x00" * 6 + socket.inet_aton(destination_ip)
        return (
            b"\xff" * 6 + mac_address_to_bytes(source_mac) + b"\x08\x06" + arp_payload
        )
    icmp_payload = (
        struct.pack("!BBHHH", 8, 0, 0, packet_identifier, 1) + b"RAIN-CHECKER"
    )
    icmp_payload = (
        icmp_payload[:2]
        + struct.pack("!H", calculate_internet_checksum(icmp_payload))
        + icmp_payload[4:]
    )
    ipv4_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(icmp_payload),
        packet_identifier,
        0,
        64,
        1,
        0,
        socket.inet_aton(source_ip),
        socket.inet_aton(destination_ip),
    )
    ipv4_header = (
        ipv4_header[:10]
        + struct.pack("!H", calculate_internet_checksum(ipv4_header))
        + ipv4_header[12:]
    )
    return (
        mac_address_to_bytes(destination_mac)
        + mac_address_to_bytes(source_mac)
        + b"\x08\x00"
        + ipv4_header
        + icmp_payload
    )


def main():
    """Parse packet settings and send the requested frames on the host interface."""
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--interface", required=True)
    argument_parser.add_argument("--src-mac", dest="source_mac", required=True)
    argument_parser.add_argument("--dst-mac", dest="destination_mac", required=True)
    argument_parser.add_argument("--src-ip", dest="source_ip", required=True)
    argument_parser.add_argument("--dst-ip", dest="destination_ip", required=True)
    argument_parser.add_argument(
        "--tag", dest="packet_identifier", type=int, required=True
    )
    argument_parser.add_argument(
        "--kind", dest="packet_kind", choices=["arp", "icmp"], default="icmp"
    )
    argument_parser.add_argument("--count", dest="packet_count", type=int, default=3)
    options = argument_parser.parse_args()
    frame_bytes = build_test_frame(
        options.source_mac,
        options.destination_mac,
        options.source_ip,
        options.destination_ip,
        options.packet_identifier,
        options.packet_kind,
    )
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as packet_socket:
        packet_socket.bind((options.interface, 0))
        for _ in range(options.packet_count):
            packet_socket.send(frame_bytes)
            time.sleep(0.05)


if __name__ == "__main__":
    main()
