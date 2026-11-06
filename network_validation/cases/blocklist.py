"""Executable blocklist scenarios; network operations live in environment.py."""


def test_destination_blocking(environment):
    """Run the static behavior check in a fresh experiment."""
    environment.checkpoint = "learning"
    environment.learn_host_locations()
    blocked_host_name = environment.test_case["blocked"]
    other_host_name = next(
        (
            host_name
            for host_name in [
                environment.roles["destination"],
                environment.roles["other"],
            ]
            if host_name != blocked_host_name
        )
    )
    environment.assert_destination_delivery(
        environment.roles["source"], other_host_name
    )
    environment.assert_destination_delivery(
        environment.roles["source"], blocked_host_name, False
    )
    environment.assert_destination_delivery(
        blocked_host_name, environment.roles["source"]
    )


def test_unknown_blocked_destination(environment):
    """Run the static_unknown behavior check in a fresh experiment."""
    environment.assert_destination_delivery(
        environment.roles["source"], environment.test_case["blocked"], False
    )
    other_host_name = next(
        (
            host_name
            for host_name in [
                environment.roles["destination"],
                environment.roles["other"],
            ]
            if host_name != environment.test_case["blocked"]
        )
    )
    environment.assert_destination_delivery(
        environment.roles["source"], other_host_name
    )
