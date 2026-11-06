"""Validate reproducible network fixtures and calculate expected switch ports."""

import copy
import ipaddress
import json
from pathlib import Path


def host_mac_address(host_name):
    """Assign unique 48-bit addresses to h1 through h65279."""
    number = int(host_name[1:])
    return ":".join("%02x" % ((number >> shift) & 255) for shift in range(40, -1, -8))


class NetworkConfiguration:
    """Describe a connected, loop-free switch graph and host attachments."""

    def __init__(self, configuration):
        self.data = copy.deepcopy(configuration)
        self.name = configuration["name"]
        if not self.name or any(
            c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
            for c in self.name
        ):
            raise ValueError(
                "Configuration names must contain letters, digits, underscores or hyphens"
            )
        count = configuration["host_count"]
        if (
            isinstance(count, bool)
            or not isinstance(count, int)
            or not 3 <= count <= 65279
        ):
            raise ValueError("host_count must be an integer between 3 and 65279")
        self.host_names = ["h%d" % n for n in range(1, count + 1)]
        self.switch_names = configuration.get("switches", ["s1"])
        if not self.switch_names or self.switch_names != [
            "s%d" % n for n in range(1, len(self.switch_names) + 1)
        ]:
            raise ValueError("Switches must be named consecutively s1, s2, ...")
        self.attachments = {}
        ports = configuration.get("host_ports", list(range(1, count + 1)))
        switches = configuration.get("host_switches", ["s1"] * count)
        if len(ports) != count or len(switches) != count:
            raise ValueError("Each host needs one port and one switch")
        occupied = set()

        def reserve(switch, port):
            if (
                switch not in self.switch_names
                or isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port < 65280
                or (switch, port) in occupied
            ):
                raise ValueError(
                    "Invalid or duplicate switch port: %s:%s" % (switch, port)
                )
            occupied.add((switch, port))

        for host, switch, port in zip(self.host_names, switches, ports):
            reserve(switch, port)
            self.attachments[host] = (switch, port)
        self.links = configuration.get("switch_links", [])
        self.neighbors = {switch: {} for switch in self.switch_names}
        for left, left_port, right, right_port in self.links:
            reserve(left, left_port)
            reserve(right, right_port)
            if left == right or right in self.neighbors[left]:
                raise ValueError("Switch links must form a tree")
            self.neighbors[left][right] = left_port
            self.neighbors[right][left] = right_port
        if len(self.links) != len(self.switch_names) - 1:
            raise ValueError("Only connected, loop-free switch trees are supported")
        for switch in self.switch_names:
            self.path(self.switch_names[0], switch)
        self.roles = dict(zip(("source", "destination", "other"), self.host_names[:3]))
        self.roles.update(configuration.get("roles", {}))
        if (
            any(host not in self.host_names for host in self.roles.values())
            or len(set(self.roles.values())) != 3
        ):
            raise ValueError(
                "source, destination and other must identify three distinct hosts"
            )

    def path(self, source, destination):
        """Find the unique switch path or reject disconnected configurations."""
        pending = [(source, [source])]
        visited = set()
        while pending:
            switch, path = pending.pop()
            if switch == destination:
                return path
            visited.add(switch)
            pending.extend(
                (neighbor, path + [neighbor])
                for neighbor in self.neighbors[switch]
                if neighbor not in visited
            )
        raise ValueError("Disconnected switch graph")

    def port_toward_host(self, switch, host):
        """Return the expected output port toward a host from any switch."""
        attached_switch, host_port = self.attachments[host]
        path = self.path(switch, attached_switch)
        return host_port if len(path) == 1 else self.neighbors[switch][path[1]]

    def host_ip(self, host):
        """Allocate IPv4 addresses without overflowing an octet at 256 hosts."""
        return str(ipaddress.IPv4Address("10.0.0.0") + int(host[1:])) + "/16"

    def unused_port(self, switch):
        """Choose a free physical port for a same-switch movement experiment."""
        used = set(self.neighbors[switch].values()) | {
            port for attached, port in self.attachments.values() if attached == switch
        }
        return next(port for port in range(1, 65280) if port not in used)


def load_configurations(path, selected_names=None):
    """Load named fixtures and reject unknown names rather than silently skip."""
    configurations = [
        NetworkConfiguration(item) for item in json.loads(Path(path).read_text())
    ]
    names = [item.name for item in configurations]
    if len(set(names)) != len(names):
        raise ValueError("Duplicate configuration names")
    if selected_names and not set(selected_names) <= set(names):
        raise ValueError("Unknown configuration name")
    return [
        item
        for item in configurations
        if not selected_names or item.name in selected_names
    ]
