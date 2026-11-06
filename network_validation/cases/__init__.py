"""Map scenario names to their independently readable test functions."""

from .base import test_unknown_destination_flooding
from .base import test_known_destination_forwarding
from .base import test_arp_and_ping
from .blocklist import test_destination_blocking
from .blocklist import test_unknown_blocked_destination
from .movement import test_move_after_cached_forwarding
from .movement import test_move_preserves_blocklist
from .runtime import test_runtime_block_and_unblock
from .runtime import test_invalid_policy_updates
from .trace import test_action_trace

SCENARIOS = {
    "unknown": test_unknown_destination_flooding,
    "known": test_known_destination_forwarding,
    "ping": test_arp_and_ping,
    "static": test_destination_blocking,
    "static_unknown": test_unknown_blocked_destination,
    "move": test_move_after_cached_forwarding,
    "move_block": test_move_preserves_blocklist,
    "runtime": test_runtime_block_and_unblock,
    "invalid": test_invalid_policy_updates,
    "trace": test_action_trace,
}
