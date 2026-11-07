"""Executable base scenarios; network operations live in environment.py."""


def test_unknown_destination_flooding(environment):
    """Run the unknown behavior check in a fresh experiment."""
    if not environment.options.stock_controller_mode:
        assert all(
            not locations
            for locations in environment.get_controller_status()["learned"].values()
        ), "Fresh controller was not empty"
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
