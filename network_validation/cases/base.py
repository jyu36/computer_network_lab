"""Executable base scenarios; network operations live in environment.py."""

from Helpers.topology import host_mac_address


def test_unknown_destination_flooding(environment):
    """Test flooding with an unlearned destination, allowing unrelated learning."""
    if not environment.options.stock_controller_mode:
        environment.checkpoint = "unknown_destination_precondition"
        destination_mac = host_mac_address(environment.roles["destination"])
        learned = environment.get_controller_status()["learned"]
        switches_with_destination = [
            switch
            for switch, locations in learned.items()
            if destination_mac in {mac.lower() for mac in locations}
        ]
        environment.recorded_events.append(
            {
                "unknown_destination_precondition": {
                    "destination_mac": destination_mac,
                    "learned_before_probe": learned,
                    "switches_with_destination": switches_with_destination,
                }
            }
        )
        # A fresh process can legitimately learn background sources at startup.
        # Only the probe destination must be unknown. A known destination makes
        # this experiment invalid, rather than demonstrating a flooding defect.
        if switches_with_destination:
            raise RuntimeError(
                "Unknown-destination precondition not met: probe destination %s "
                "is already learned on switches %s"
                % (destination_mac, switches_with_destination)
            )
    environment.checkpoint = "unknown_destination_flooding"
    environment.assert_packet_delivery(
        environment.roles["source"],
        environment.roles["destination"],
        [
            host
            for host in environment.host_names
            if host != environment.roles["source"]
        ],
        expected_delivery={
            host: environment.configuration.hosts_connected(
                environment.roles["source"], host
            )
            for host in environment.host_names
            if host != environment.roles["source"]
        },
        packet_count=1,
    )


def test_known_destination_forwarding(environment):
    """Run the known behavior check in a fresh experiment."""
    environment.checkpoint = "learning"
    environment.learn_host_locations()
    for source_host_name, destination_host_name in environment.selected_host_pairs():
        if not environment.configuration.hosts_connected(
            source_host_name, destination_host_name
        ):
            environment.checkpoint = "partition_isolation"
            environment.assert_expected_destination_delivery(
                source_host_name, destination_host_name
            )
            continue
        observers = [
            host for host in environment.host_names if host != source_host_name
        ]
        environment.checkpoint = "known_forwarding"
        environment.establish_cached_forwarding(source_host_name, destination_host_name)
        before = environment.forwarding_packet_counts(
            source_host_name, destination_host_name
        )
        environment.assert_packet_delivery(
            source_host_name,
            destination_host_name,
            observers,
            {host: host == destination_host_name for host in observers},
        )
        after = environment.forwarding_packet_counts(
            source_host_name, destination_host_name
        )
        environment.recorded_events.append(
            {
                "cached_rule_counters": {
                    "source": source_host_name,
                    "destination": destination_host_name,
                    "before": before,
                    "after": after,
                }
            }
        )
        assert all(
            after[switch] >= before[switch] + 3 for switch in before
        ), "Subsequent requests did not use every installed forwarding rule"


def test_arp_and_ping(environment):
    """Run the ping behavior check in a fresh experiment."""
    pairs = environment.selected_host_pairs()
    total = len(environment.host_names) * (len(environment.host_names) - 1)
    if len(pairs) < total or not environment.configuration.is_connected:
        for source, destination in pairs:
            environment.assert_expected_ping_delivery(source, destination)
        return
    packet_loss_percent = environment.network.pingAll(timeout="1")
    environment.recorded_events.append({"pingall_loss_percent": packet_loss_percent})
    assert packet_loss_percent == 0, "ARP/ICMP pingall loss: %s%%" % packet_loss_percent
    for source, destination in pairs:
        environment.assert_forwarding_table_behavior(source, destination, True)
