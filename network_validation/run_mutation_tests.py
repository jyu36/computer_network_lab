#!/usr/bin/env python3
"""Compare full suites against the reference and require each mutant's intended failure."""
import argparse
import datetime
import json
import os
import signal
from pathlib import Path
from Helpers.topology import load_configurations
from Helpers.mutation_results import classify_test_run, matches_expected_defect
import subprocess
import sys

VALIDATION_DIRECTORY = Path(__file__).resolve().parent
MUTATION_DETECTION_CASES = {
    "wrong_output_port": "known_destination_forwarding",
    "stale_host_location": "host_movement_after_cached_forwarding",
    "cached_policy_bypass": "runtime_block_and_unblock_cached_destination",
}


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
    argument_parser.add_argument(
        "--configuration-file",
        default=str(VALIDATION_DIRECTORY / "network_configurations.json"),
    )
    argument_parser.add_argument("--configuration", action="append")
    argument_parser.add_argument("--timeout-seconds", type=int, default=3600)
    argument_parser.add_argument(
        "--quick",
        action="store_true",
        help="Use sampled host pairs in every reference and mutant run",
    )
    argument_parser.add_argument("--max-host-pairs", type=int, default=None)
    argument_parser.add_argument("--pair-seed", type=int, default=0)
    options = argument_parser.parse_args()
    if options.max_host_pairs is None:
        options.max_host_pairs = 6 if options.quick else 0
    if options.max_host_pairs < 0:
        argument_parser.error("--max-host-pairs must be nonnegative")
    configurations = load_configurations(
        options.configuration_file, options.configuration
    )
    if not configurations or options.timeout_seconds < 1:
        argument_parser.error("Select configurations and a positive timeout")
    if options.repetition_count < 1:
        argument_parser.error("repeats must be positive")
    print(
        "Profile: %s"
        % (
            "SAMPLED development comparison (pair limit %d, seed %d)"
            % (options.max_host_pairs, options.pair_seed)
            if options.max_host_pairs
            else "FULL (all host pairs for forwarding/ping)"
        ),
        flush=True,
    )
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
        "profile": "sampled" if options.max_host_pairs else "full",
        "max_host_pairs": options.max_host_pairs,
        "pair_seed": options.pair_seed,
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

    def run_controller_variant(variant_name, case_id, repetition_number):
        """Launch the network runner for one controller variant and record its outcome."""
        variant_results_directory = mutation_results_directory / (
            "%s_%d" % (variant_name, repetition_number)
        )
        runner_command = [
            sys.executable,
            str(VALIDATION_DIRECTORY / "run_network_tests.py"),
            "--controller",
            str(options.controller_variants_directory / (variant_name + ".py")),
            "--suite",
            "full",
            "--ryu-manager",
            options.ryu_manager,
            "--output",
            str(variant_results_directory),
        ]
        runner_command += [
            "--configuration-file",
            options.configuration_file,
            "--max-host-pairs",
            str(options.max_host_pairs),
            "--pair-seed",
            str(options.pair_seed),
        ]
        for configuration in configurations:
            runner_command += ["--configuration", configuration.name]
        print(
            "Running %s, repetition %d: all selected cases on %d configurations"
            % (variant_name, repetition_number, len(configurations)),
            flush=True,
        )
        # Each run has a hard outer bound as well as per-operation timeouts.
        runner_process = subprocess.Popen(
            runner_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,
        )
        try:
            runner_output, _ = runner_process.communicate(
                timeout=options.timeout_seconds
            )
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
        expected_case_ids = [
            (configuration.name, case["id"])
            for configuration in configurations
            for case in development_cases
        ]
        case_results = (
            json.loads(summary_paths[0].read_text()) if len(summary_paths) == 1 else []
        )
        run_outcome = classify_test_run(exit_code, case_results, expected_case_ids)
        if case_id and run_outcome != "INVALID":
            target_results = [row for row in case_results if row["id"] == case_id]
            run_outcome = (
                "DETECTED"
                if len(target_results) == len(configurations)
                and all(
                    matches_expected_defect(variant_name, row) for row in target_results
                )
                else "UNCONFIRMED"
            )
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
            run_controller_variant("reference_controller", None, repetition_number)
            != "PASS"
        ):
            print(
                "Reference controller did not pass. Mutation evidence is invalid. Inspect",
                mutation_results_directory,
            )
            return 2
        for variant_name, case_id in MUTATION_DETECTION_CASES.items():
            outcome = run_controller_variant(variant_name, case_id, repetition_number)
            if outcome == "INVALID":
                print(
                    "Invalid execution; inspect VM state and evidence:",
                    mutation_results_directory,
                )
                return 2
    mutant_runs = [
        run
        for run in mutation_report["runs"]
        if run["variant"] != "reference_controller"
    ]
    complete = all(run["outcome"] == "DETECTED" for run in mutant_runs)
    mutation_report.update(
        complete=complete,
        detected_distinct=len(
            {run["variant"] for run in mutant_runs if run["outcome"] == "DETECTED"}
        ),
        attempted_distinct=len({run["variant"] for run in mutant_runs}),
        repeated_runs_per_variant=options.repetition_count,
    )
    save_mutation_report()
    print(
        (
            "All curated defects detected on every repetition. Evidence:"
            if complete
            else "Some expected detections were unconfirmed. Evidence:"
        ),
        mutation_results_directory,
    )
    return 0 if complete else 2


if __name__ == "__main__":
    sys.exit(main())
