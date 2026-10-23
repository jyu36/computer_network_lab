#!/usr/bin/env python3
"""Run the good control first; count only assertion failures as mutation detections."""
import argparse
import datetime
import json
import os
import signal
from pathlib import Path
import subprocess
import sys

VALIDATION_DIRECTORY = Path(__file__).resolve().parent
MUTATION_DETECTION_CASES = {
    "wrong_output_port": ("base", "B02_known_forward"),
    "stale_host_location": ("movement", "M01_move_after_cache"),
    "cached_policy_bypass": ("runtime", "R01_block_unblock_cached"),
}


def classify_test_run(exit_code, case_results, expected_case_ids):
    """Classify a complete case set while rejecting execution errors or missing cases."""
    if {case_result["id"] for case_result in case_results} != set(
        expected_case_ids
    ) or len(case_results) != len(expected_case_ids):
        return "INVALID"
    if any(
        case_result["status"] not in {"PASS", "FAIL"} for case_result in case_results
    ):
        return "INVALID"
    if all(case_result["status"] == "PASS" for case_result in case_results):
        return "PASS" if exit_code == 0 else "INVALID"
    return "FAIL" if exit_code == 1 else "INVALID"


def main():
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--ryu-manager", required=True)
    argument_parser.add_argument(
        "--controller-variants",
        "--variants",
        dest="controller_variants_directory",
        type=Path,
        default=VALIDATION_DIRECTORY / "controller_variants",
    )
    argument_parser.add_argument(
        "--repetitions", "--repeats", dest="repetition_count", type=int, default=3
    )
    options = argument_parser.parse_args()
    if options.repetition_count < 1:
        argument_parser.error("repeats must be positive")
    mutation_results_directory = (
        VALIDATION_DIRECTORY
        / "results"
        / (
            "mutation_"
            + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        )
    )
    mutation_results_directory.mkdir(parents=True)
    mutation_report = {
        "runs": [],
        "complete": False,
        "note": "Curated defects only; not a general correctness guarantee",
    }
    development_cases = json.loads(
        (VALIDATION_DIRECTORY / "development_cases.json").read_text()
    )

    def save_mutation_report():
        """Persist the mutation experiment report after each controller run."""
        (mutation_results_directory / "mutation_report.json").write_text(
            json.dumps(mutation_report, indent=2) + "\n"
        )

    def run_controller_variant(
        variant_name, requirement_stage, case_id, repetition_number
    ):
        """Launch the network runner for one controller variant and record its outcome."""
        variant_results_directory = mutation_results_directory / (
            "%s_%d" % (variant_name, repetition_number)
        )
        runner_command = [
            sys.executable,
            str(VALIDATION_DIRECTORY / "run_network_tests.py"),
            "--controller",
            str(options.controller_variants_directory / (variant_name + ".py")),
            "--stage",
            requirement_stage,
            "--ryu-manager",
            options.ryu_manager,
            "--output",
            str(variant_results_directory),
        ]
        if case_id:
            runner_command += ["--case", case_id]
        # Each run has a hard outer bound as well as per-operation timeouts.
        runner_process = subprocess.Popen(
            runner_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            runner_output, _ = runner_process.communicate(timeout=900)
            exit_code = runner_process.returncode
        except subprocess.TimeoutExpired:
            # Interrupt Python first so its finally block tears down Mininet.
            runner_process.send_signal(signal.SIGINT)
            try:
                runner_output, _ = runner_process.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(runner_process.pid, signal.SIGKILL)
                runner_output, _ = runner_process.communicate()
            runner_output += (
                "\nOUTER TIMEOUT: invalid run; check VM cleanup before retrying.\n"
            )
            exit_code = -1
        (
            mutation_results_directory
            / ("%s_%d.log" % (variant_name, repetition_number))
        ).write_text(runner_output)
        summary_paths = list(variant_results_directory.glob("*/summary.json"))
        expected_case_ids = (
            [case_id]
            if case_id
            else [test_case["id"] for test_case in development_cases]
        )
        case_results = (
            json.loads(summary_paths[0].read_text()) if len(summary_paths) == 1 else []
        )
        run_outcome = classify_test_run(exit_code, case_results, expected_case_ids)
        run_record = {
            "variant": variant_name,
            "repetition": repetition_number,
            "outcome": run_outcome,
            "returncode": exit_code,
            "cases": case_results,
            "command": runner_command,
        }
        mutation_report["runs"].append(run_record)
        save_mutation_report()
        print(variant_name, repetition_number, run_outcome, flush=True)
        return run_outcome

    save_mutation_report()
    for repetition_number in range(1, options.repetition_count + 1):
        if (
            run_controller_variant(
                "reference_controller", "runtime", None, repetition_number
            )
            != "PASS"
        ):
            print(
                "Reference controller did not pass. Mutation evidence is invalid. Inspect",
                mutation_results_directory,
            )
            return 2
        for variant_name, (
            requirement_stage,
            case_id,
        ) in MUTATION_DETECTION_CASES.items():
            if (
                run_controller_variant(
                    variant_name, requirement_stage, case_id, repetition_number
                )
                != "FAIL"
            ):
                print(
                    "Mutant survived or run was invalid. Inspect",
                    mutation_results_directory,
                )
                return 2
    mutation_report.update(
        complete=True,
        detected_distinct=3,
        attempted_distinct=3,
        repeated_runs_per_variant=options.repetition_count,
    )
    save_mutation_report()
    print(
        "All curated defects detected on every repetition. Evidence:",
        mutation_results_directory,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
