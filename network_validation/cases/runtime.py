"""Executable runtime scenarios; network operations live in environment.py."""


def test_runtime_block_and_unblock(environment):
    """Run the runtime behavior check in a fresh experiment."""
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
    environment.establish_cached_forwarding(
        environment.roles["source"], blocked_host_name
    )
    environment.replace_destination_blocklist([blocked_host_name])
    environment.save_network_snapshot("after_block")
    environment.assert_destination_delivery(
        environment.roles["source"], other_host_name
    )
    environment.checkpoint = "cached_path_blocked"
    environment.assert_destination_delivery(
        environment.roles["source"], blocked_host_name, False
    )
    environment.assert_destination_delivery(other_host_name, blocked_host_name, False)
    environment.assert_destination_delivery(
        blocked_host_name, environment.roles["source"]
    )
    environment.replace_destination_blocklist([])
    environment.assert_destination_delivery(
        environment.roles["source"], blocked_host_name
    )
    environment.replace_destination_blocklist([blocked_host_name])
    environment.assert_destination_delivery(
        environment.roles["source"], blocked_host_name, False
    )
    environment.replace_destination_blocklist([])
    environment.assert_destination_delivery(
        environment.roles["source"], blocked_host_name
    )


def test_invalid_policy_updates(environment):
    """Run the invalid behavior check in a fresh experiment."""
    environment.checkpoint = "learning"
    environment.learn_host_locations()
    environment.replace_destination_blocklist([environment.roles["destination"]])
    previous_blocklist = environment.get_controller_status()["blocked"]
    for request_body in [
        {"blocked": ["invalid"]},
        {"blocked": "not-a-list"},
        {},
        {"blocked": [12]},
        {"blocked": [], "extra": True},
        [],
        None,
    ]:
        environment.send_controller_request(
            "PUT", "policy", request_body, expected_http_status=400
        )
        assert (
            environment.get_controller_status()["blocked"] == previous_blocklist
        ), "Invalid input mutated policy"
    environment.assert_destination_delivery(
        environment.roles["source"], environment.roles["destination"], False
    )
    environment.assert_destination_delivery(
        environment.roles["source"], environment.roles["other"]
    )
