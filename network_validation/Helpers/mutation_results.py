"""Validate complete mutation runs and attribute expected behavioral failures."""


def classify_test_run(exit_code, case_results, expected_case_ids):
    """Classify a complete case set while rejecting execution errors or missing cases."""
    actual_ids = [
        (row["configuration"], row["id"]) if "configuration" in row else row["id"]
        for row in case_results
    ]
    if set(actual_ids) != set(expected_case_ids) or len(case_results) != len(
        expected_case_ids
    ):
        return "INVALID"
    if any(
        case_result["status"] not in {"PASS", "FAIL"} for case_result in case_results
    ):
        return "INVALID"
    if all(case_result["status"] == "PASS" for case_result in case_results):
        return "PASS" if exit_code == 0 else "INVALID"
    return "FAIL" if exit_code == 1 else "INVALID"


def matches_expected_defect(variant_name, result):
    """Require the intended behavioral symptom, rather than any failed assertion."""
    if result["status"] != "FAIL":
        return False
    if variant_name == "stale_host_location":
        return (
            result.get("checkpoint") == "movement"
            and result.get("failure_code") == "host_location"
        )
    expected_checkpoint = (
        "known_forwarding"
        if variant_name == "wrong_output_port"
        else "cached_path_blocked"
    )
    details = result.get("details", {})
    return (
        result.get("checkpoint") == expected_checkpoint
        and result.get("failure_code") == "packet_delivery"
        and (
            details.get("expected", 0) > 0
            if variant_name == "wrong_output_port"
            else details.get("expected") == 0 and details.get("observed", 0) > 0
        )
    )
