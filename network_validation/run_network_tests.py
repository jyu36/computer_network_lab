#!/usr/bin/env python3
"""Select controllers, network configurations and cases; save grouped results."""
import copy
import argparse
import datetime
import hashlib
import json
import platform
import shutil
import sys
import traceback
import time
from pathlib import Path
from Helpers.environment import (
    NetworkTestEnvironment,
    REQUIREMENT_STAGES,
    VALIDATION_DIRECTORY,
    load_test_cases,
    run_command,
)
from Helpers.environment import validate_test_environment
from Helpers.topology import load_configurations
from Helpers.results import save_results, format_summary, BehaviorFailure


def main():
    """Parse CLI options, run the selected cases independently, and save results."""
    # Read the controller path, test stage, and evidence settings from the command.
    argument_parser = argparse.ArgumentParser(description=__doc__)
    argument_parser.add_argument("--stage", choices=REQUIREMENT_STAGES, default=None)
    argument_parser.add_argument(
        "--controller",
        dest="controller_path",
        required=True,
        help="Path to the actual controller source",
    )
    argument_parser.add_argument(
        "--stock-controller",
        "--stock-base",
        dest="stock_controller_mode",
        action="store_true",
        help="Base tests without the custom HTTP API",
    )
    argument_parser.add_argument(
        "--ryu-manager", default=shutil.which("ryu-manager") or "ryu-manager"
    )
    argument_parser.add_argument(
        "--case-file",
        "--cases",
        dest="case_file_path",
        default=str(VALIDATION_DIRECTORY / "development_cases.json"),
    )
    argument_parser.add_argument(
        "--case-id", "--case", dest="test_case_id", help="Run one case by exact ID"
    )
    argument_parser.add_argument(
        "--openflow-port", "--of-port", dest="openflow_port", type=int, default=6653
    )
    argument_parser.add_argument(
        "--controller-api-port",
        "--api-port",
        dest="controller_api_port",
        type=int,
        default=8080,
    )
    argument_parser.add_argument(
        "--results-directory",
        "--output",
        dest="results_directory",
        default=str(VALIDATION_DIRECTORY / "results"),
    )
    argument_parser.add_argument(
        "--observation-seconds",
        "--observe-seconds",
        dest="observation_seconds",
        type=float,
        default=1.0,
    )
    argument_parser.add_argument(
        "--list-cases", "--list", dest="list_cases", action="store_true"
    )
    argument_parser.add_argument(
        "--suite",
        choices=["full"] + REQUIREMENT_STAGES,
        help="Cumulative requirements; default full (stock controller: base)",
    )
    argument_parser.add_argument(
        "--configuration-file",
        default=str(VALIDATION_DIRECTORY / "network_configurations.json"),
    )
    argument_parser.add_argument(
        "--configuration",
        action="append",
        help="Select named networks; repeat to select several, default all",
    )
    argument_parser.add_argument(
        "--plan",
        action="store_true",
        help="Show planned experiments without starting Mininet",
    )
    argument_parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print individual case outcomes as well as grouped results",
    )
    argument_parser.add_argument(
        "--quick",
        action="store_true",
        help="Development run: sample at most six directed pairs for forwarding and ping",
    )
    argument_parser.add_argument(
        "--max-host-pairs",
        type=int,
        default=None,
        help="Pair limit for forwarding/ping; zero tests every pair",
    )
    argument_parser.add_argument(
        "--pair-seed", type=int, default=0, help="Reproduce the selected host pairs"
    )
    options = argument_parser.parse_args()
    if options.max_host_pairs is None:
        options.max_host_pairs = 6 if options.quick else 0
    if options.max_host_pairs < 0:
        argument_parser.error("--max-host-pairs must be nonnegative")
    if options.suite and options.stage:
        argument_parser.error("Choose --suite or the legacy --stage, not both")
    options.stage = (
        options.stage
        or ({"full": "runtime"}.get(options.suite, options.suite))
        or ("base" if options.stock_controller_mode else "runtime")
    )
    try:
        configurations = load_configurations(
            options.configuration_file, options.configuration
        )
    except (ValueError, KeyError, TypeError) as error:
        argument_parser.error(str(error))
    if not configurations:
        argument_parser.error("No network configurations selected")
    if not 0 < options.observation_seconds <= 60:
        argument_parser.error("--observe-seconds must be in (0, 60]")
    if options.stock_controller_mode and options.stage != "base":
        argument_parser.error(
            "--stock-base only supports --stage base; later stages need the agreed update interface"
        )
    if not __debug__:
        argument_parser.error(
            "Assertions are required: do not use python -O or PYTHONOPTIMIZE"
        )
    # Select cumulative-stage cases; --case can narrow this to one named case.
    test_cases = load_test_cases(options.case_file_path, options.stage)
    if options.test_case_id:
        test_cases = [
            test_case
            for test_case in test_cases
            if test_case["id"] == options.test_case_id
        ]
    if not test_cases:
        argument_parser.error("No matching cases; check --stage and --case")
    if options.list_cases:
        print(json.dumps(test_cases, indent=2))
        return 0
    if options.plan:
        print(
            json.dumps(
                {
                    "configurations": [
                        configuration.data for configuration in configurations
                    ],
                    "cases": [case["id"] for case in test_cases],
                    "experiment_count": len(configurations) * len(test_cases),
                    "profile": "sampled" if options.max_host_pairs else "full",
                    "host_pair_coverage": {
                        configuration.name: {
                            "selected": min(
                                options.max_host_pairs
                                or len(configuration.host_names)
                                * (len(configuration.host_names) - 1),
                                len(configuration.host_names)
                                * (len(configuration.host_names) - 1),
                            ),
                            "total": len(configuration.host_names)
                            * (len(configuration.host_names) - 1),
                        }
                        for configuration in configurations
                    },
                    "reset": "Fresh controller and network for each configuration/case",
                },
                indent=2,
            )
        )
        return 0
    for configuration in configurations:
        options.network_configuration = configuration
        validate_test_environment(options)
    # Record which source and environment produced this timestamped experiment.
    run_timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y%m%dT%H%M%S.%fZ"
    )
    evidence_directory = Path(options.results_directory).resolve() / (
        run_timestamp + "_" + Path(options.controller_path).stem
    )
    evidence_directory.mkdir(parents=True)
    environment_details = {
        "platform": platform.platform(),
        "python": sys.version,
        "arguments": {
            key: value
            for key, value in vars(options).items()
            if key != "network_configuration"
        },
        "configurations": [configuration.data for configuration in configurations],
    }
    controller_source_bytes = Path(options.controller_path).read_bytes()
    environment_details["controller_sha256"] = hashlib.sha256(
        controller_source_bytes
    ).hexdigest()
    (evidence_directory / "controller_source.py").write_bytes(controller_source_bytes)
    for component_name, command_arguments in [
        ("ovs", ["ovs-vsctl", "--version"]),
        ("tcpdump", ["tcpdump", "--version"]),
        ("mininet", ["mn", "--version"]),
        ("ryu", [options.ryu_manager, "--version"]),
    ]:
        try:
            environment_details[component_name] = run_command(
                command_arguments, check=False
            )
        except Exception as error:
            environment_details[component_name] = repr(error)
    (evidence_directory / "environment.json").write_text(
        json.dumps(environment_details, indent=2)
    )
    print(
        "Profile: %s; observation window: %.2fs"
        % (
            (
                "SAMPLED development run (pair limit %d, seed %d)"
                % (options.max_host_pairs, options.pair_seed)
                if options.max_host_pairs
                else "FULL (all host pairs for forwarding/ping)"
            ),
            options.observation_seconds,
        ),
        flush=True,
    )
    case_results = []
    cleanup_failed = False
    for configuration in configurations:
        print(
            "Running %s: %d cases" % (configuration.name, len(test_cases)), flush=True
        )
        for test_case in test_cases:
            # Each independent case gets its own controller, network, and evidence folder.
            case_evidence_directory = (
                evidence_directory / configuration.name / test_case["id"]
            )
            case_evidence_directory.mkdir(parents=True)
            options.network_configuration = copy.deepcopy(configuration)
            test_environment = NetworkTestEnvironment(
                options, test_case, case_evidence_directory
            )
            test_result = {
                "configuration": configuration.name,
                "id": test_case["id"],
                "stage": test_case["stage"],
                "status": "PASS",
                "profile": "sampled" if options.max_host_pairs else "full",
                "max_host_pairs": options.max_host_pairs,
                "pair_seed": options.pair_seed,
            }
            if cleanup_failed:
                test_result.update(
                    status="NOT_RUN",
                    error="Previous experiment cleanup failed; restore the VM before retrying",
                )
                case_results.append(test_result)
                (case_evidence_directory / "result.json").write_text(
                    json.dumps(test_result, indent=2)
                )
                continue
            if options.verbose:
                print("RUN %s / %s" % (configuration.name, test_case["id"]), flush=True)
            case_started = time.monotonic()
            try:
                test_environment.start_network_and_controller()
                test_environment.run_test_scenario()
            except AssertionError as error:
                test_result.update(
                    status="FAIL",
                    error=str(error),
                    traceback=traceback.format_exc(),
                    checkpoint=test_environment.checkpoint,
                    failure_code=(
                        error.code
                        if isinstance(error, BehaviorFailure)
                        else "assertion"
                    ),
                    details=error.details if isinstance(error, BehaviorFailure) else {},
                )
            except Exception as error:
                test_result.update(
                    status="ERROR", error=str(error), traceback=traceback.format_exc()
                )
            finally:
                # Attempt cleanup even after a failed assertion or execution error.
                try:
                    test_environment.cleanup()
                except Exception as error:
                    test_result.update(status="ERROR", cleanup_error=repr(error))
                    cleanup_failed = True
            test_result["duration_seconds"] = round(time.monotonic() - case_started, 3)
            (case_evidence_directory / "result.json").write_text(
                json.dumps(test_result, indent=2)
            )
            case_results.append(test_result)
            if options.verbose:
                print(
                    "%s %s (%.1fs) %s"
                    % (
                        test_result["status"],
                        test_case["id"],
                        test_result["duration_seconds"],
                        test_result.get("error", ""),
                    ),
                    flush=True,
                )
    # Return success only when every selected case passed.
    save_results(evidence_directory, case_results)
    print(format_summary(case_results))
    print("Evidence:", evidence_directory)
    return (
        2
        if any(row["status"] in {"ERROR", "NOT_RUN"} for row in case_results)
        else (0 if all(row["status"] == "PASS" for row in case_results) else 1)
    )


if __name__ == "__main__":
    sys.exit(main())
