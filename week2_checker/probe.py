"""Send uniquely tagged frames from a Mininet host. Standard library only."""
import argparse
import socket
import struct
import time


def mac_bytes(mac):
    return bytes.fromhex(mac.replace(':', ''))


def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def frame(src_mac, dst_mac, src_ip, dst_ip, tag, kind):
    if kind == 'arp':
        arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 1)
        arp += mac_bytes(src_mac) + socket.inet_aton(src_ip)
        arp += b'\x00' * 6 + socket.inet_aton(dst_ip)
        return b'\xff' * 6 + mac_bytes(src_mac) + b'\x08\x06' + arp
    body = struct.pack('!BBHHH', 8, 0, 0, tag, 1) + b'RAIN-CHECKER'
    body = body[:2] + struct.pack('!H', checksum(body)) + body[4:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(body), tag, 0,
                     64, 1, 0, socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:]
    return mac_bytes(dst_mac) + mac_bytes(src_mac) + b'\x08\x00' + ip + body


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    for name in ['interface', 'src-mac', 'dst-mac', 'src-ip', 'dst-ip']:
        p.add_argument('--' + name, required=True)
    p.add_argument('--tag', type=int, required=True)
    p.add_argument('--kind', choices=['arp', 'icmp'], default='icmp')
    p.add_argument('--count', type=int, default=3)
    a = p.parse_args()
    data = frame(a.src_mac, a.dst_mac, a.src_ip, a.dst_ip, a.tag, a.kind)
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
        sock.bind((a.interface, 0))
        for _ in range(a.count):
            sock.send(data)
            time.sleep(0.05)
