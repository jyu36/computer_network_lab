"""Executable trace scenarios; network operations live in environment.py."""


def test_action_trace(environment):
    """Run the trace behavior check in a fresh experiment."""
    for event_step in environment.test_case["steps"]:
        event_operation = event_step["op"]
        if event_operation == "learn":
            environment.checkpoint = "learning"
            environment.learn_host_locations()
        elif event_operation == "cache":
            environment.establish_cached_forwarding(
                event_step["source"], event_step["destination"]
            )
        elif event_operation == "observe":
            environment.assert_packet_delivery(
                event_step["source"],
                event_step["destination"],
                list(event_step["expect"]),
                event_step["expect"],
            )
        elif event_operation == "move":
            environment.relocate_host_port(event_step["host"])
        elif event_operation == "policy":
            environment.replace_destination_blocklist(event_step["blocked"])
        else:
            raise ValueError("Unknown trace operation: " + event_operation)
