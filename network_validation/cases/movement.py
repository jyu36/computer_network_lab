"""Executable movement scenarios; network operations live in environment.py."""


def test_move_after_cached_forwarding(environment):
    """Run the move behavior check in a fresh experiment."""
    environment.checkpoint = "learning"
    environment.learn_host_locations()
    moved_host_name = environment.test_case["moved"]
    environment.establish_cached_forwarding(
        environment.roles["source"], moved_host_name
    )
    environment.checkpoint = "movement"
    environment.relocate_host_port(moved_host_name)
    environment.assert_destination_delivery(
        environment.roles["source"], moved_host_name
    )
    environment.assert_destination_delivery(
        moved_host_name, environment.roles["source"]
    )


def test_move_preserves_blocklist(environment):
    """Run the move_block behavior check in a fresh experiment."""
    environment.checkpoint = "learning"
    environment.learn_host_locations()
    moved_host_name = environment.test_case["moved"]
    environment.establish_cached_forwarding(
        environment.roles["source"], moved_host_name
    )
    environment.checkpoint = "movement"
    environment.relocate_host_port(moved_host_name)
    environment.assert_destination_delivery(
        environment.roles["source"], moved_host_name
    )
    environment.assert_destination_delivery(
        moved_host_name, environment.roles["source"]
    )
    environment.assert_destination_delivery(
        environment.roles["source"], environment.test_case["blocked"], False
    )
