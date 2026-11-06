"""Bounded subprocess execution and readiness polling."""

import signal
import subprocess
import time


def wait_for_condition(condition, timeout_seconds=8):
    """Poll a condition until it returns a truthy value, or raise on timeout."""
    deadline_seconds = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline_seconds:
        condition_result = condition()
        if condition_result:
            return condition_result
        time.sleep(0.05)
    raise TimeoutError("Readiness/observation deadline exceeded")


def run_command(command_arguments, check=True):
    """Run a command with a timeout and return its standard output as text."""
    return subprocess.run(
        command_arguments, capture_output=True, text=True, timeout=15, check=check
    ).stdout


def stop_process(child_process):
    """Interrupt a running process, then kill it if it does not stop promptly."""
    if child_process.poll() is None:
        child_process.send_signal(signal.SIGINT)
        try:
            child_process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child_process.kill()
            child_process.wait()
