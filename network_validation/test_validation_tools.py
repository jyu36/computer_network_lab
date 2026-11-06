"""Local tooling checks only. These do not simulate a switch or prove controller correctness."""

import ast
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from generate_controller_variants import generate_controller_variants
from run_mutation_tests import classify_test_run, matches_expected_defect
from Helpers.topology import NetworkConfiguration, load_configurations, host_mac_address
from Helpers.environment import NetworkTestEnvironment
from Helpers.results import format_summary
import run_network_tests
from run_network_tests import load_test_cases

VALIDATION_DIRECTORY = Path(__file__).resolve().parent


class ValidationToolTests(unittest.TestCase):
    """Check source generation and renamed CLI entry points without a Linux network."""

    def test_crashes_and_missing_tests_cannot_kill_mutants(self):
        self.assertEqual(
            classify_test_run(1, [{"id": "x", "status": "ERROR"}], ["x"]), "INVALID"
        )
        self.assertEqual(classify_test_run(1, [], ["x"]), "INVALID")
        self.assertEqual(
            classify_test_run(1, [{"id": "y", "status": "FAIL"}], ["x"]), "INVALID"
        )
        self.assertEqual(
            classify_test_run(1, [{"id": "x", "status": "PASS"}], ["x"]), "INVALID"
        )
        self.assertEqual(
            classify_test_run(-9, [{"id": "x", "status": "FAIL"}], ["x"]), "INVALID"
        )
        self.assertEqual(
            classify_test_run(1, [{"id": "x", "status": "FAIL"}], ["x"]), "FAIL"
        )
        self.assertEqual(
            classify_test_run(0, [{"id": "x", "status": "PASS"}], ["x"]), "PASS"
        )

    def test_variants_are_reproducible_and_do_not_use_runtime_bug_flags(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            temporary_root = Path(temporary_directory)
            first_manifest = generate_controller_variants(temporary_root / "a")
            second_manifest = generate_controller_variants(temporary_root / "b")
            self.assertEqual(first_manifest, second_manifest)
            self.assertEqual(len(set(first_manifest["variants"].values())), 4)
            for variant_name in first_manifest["variants"]:
                controller_source_code = (
                    temporary_root / "a" / (variant_name + ".py")
                ).read_text()
                self.assertNotIn("RAIN_BUG", controller_source_code)
                self.assertNotIn("self.injected_fault", controller_source_code)
                ast.parse(controller_source_code, feature_version=(3, 8))
            with self.assertRaises(FileExistsError):
                generate_controller_variants(temporary_root / "a")

    def test_published_variants_match_the_current_template_and_manifest(self):
        """Catch stale controller files, diffs, or hashes after editing the template."""
        published_directory = VALIDATION_DIRECTORY / "controller_variants"
        with tempfile.TemporaryDirectory() as temporary_directory:
            generated_directory = Path(temporary_directory) / "generated"
            generate_controller_variants(generated_directory)
            generated_files = {
                path.relative_to(generated_directory)
                for path in generated_directory.rglob("*")
                if path.is_file()
            }
            expected_files = {
                Path(name + ".py")
                for name in (
                    "reference_controller",
                    "wrong_output_port",
                    "stale_host_location",
                    "cached_policy_bypass",
                )
            }
            expected_files.update(
                Path("Helpers") / (name + ".patch")
                for name in (
                    "wrong_output_port",
                    "stale_host_location",
                    "cached_policy_bypass",
                )
            )
            expected_files.add(Path("Helpers/source_manifest.json"))
            self.assertEqual(generated_files, expected_files)
            for relative_path in generated_files:
                self.assertEqual(
                    (generated_directory / relative_path).read_bytes(),
                    (published_directory / relative_path).read_bytes(),
                    str(relative_path),
                )

    def test_renamed_runner_lists_cumulative_cases_from_another_directory(self):
        """Check that the CLI finds its case file independently of the working directory."""
        with tempfile.TemporaryDirectory() as temporary_directory:
            for requirement_stage, expected_count in [
                ("base", 3),
                ("blocklist", 5),
                ("movement", 7),
                ("runtime", 9),
            ]:
                completed_run = subprocess.run(
                    [
                        sys.executable,
                        str(VALIDATION_DIRECTORY / "run_network_tests.py"),
                        "--controller",
                        str(
                            VALIDATION_DIRECTORY
                            / "controller_variants/reference_controller.py"
                        ),
                        "--stage",
                        requirement_stage,
                        "--list-cases",
                    ],
                    cwd=temporary_directory,
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=10,
                )
                selected_cases = json.loads(completed_run.stdout)
                self.assertEqual(len(selected_cases), expected_count)
                self.assertEqual(
                    selected_cases,
                    load_test_cases(
                        VALIDATION_DIRECTORY / "development_cases.json",
                        requirement_stage,
                    ),
                )

    def test_legacy_cli_flags_still_select_a_single_stock_controller_case(self):
        """Keep previously documented option spellings usable with the renamed script."""
        completed_run = subprocess.run(
            [
                sys.executable,
                str(VALIDATION_DIRECTORY / "run_network_tests.py"),
                "--controller",
                "unused_for_case_listing.py",
                "--stock-base",
                "--stage",
                "base",
                "--case",
                "known_destination_forwarding",
                "--list",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        self.assertEqual(
            [test_case["id"] for test_case in json.loads(completed_run.stdout)],
            ["known_destination_forwarding"],
        )


class ConfigurableExperimentTests(unittest.TestCase):
    """Exercise topology expectations, actor selection and experiment orchestration."""

    def test_tree_paths_and_movement_use_actual_switch_ports(self):
        configuration = load_configurations(
            VALIDATION_DIRECTORY / "network_configurations.json",
            ["two_switches_4_hosts"],
        )[0]
        self.assertEqual(configuration.path("s1", "s2"), ["s1", "s2"])
        self.assertEqual(configuration.port_toward_host("s1", "h2"), 3)
        self.assertEqual(configuration.port_toward_host("s2", "h2"), 1)
        self.assertEqual(configuration.unused_port("s2"), 4)
        configuration.attachments["h2"] = ("s2", 4)
        self.assertEqual(configuration.port_toward_host("s1", "h2"), 3)
        self.assertEqual(configuration.port_toward_host("s2", "h2"), 4)

    def test_branching_tree_routes_between_distinct_leaf_switches(self):
        configuration = load_configurations(
            VALIDATION_DIRECTORY / "network_configurations.json",
            ["branching_tree_3_switches_6_hosts"],
        )[0]
        source = configuration.roles["source"]
        destination = configuration.roles["destination"]
        self.assertEqual((source, destination), ("h1", "h4"))
        self.assertEqual(
            configuration.path(
                configuration.attachments[source][0],
                configuration.attachments[destination][0],
            ),
            ["s2", "s1", "s3"],
        )
        self.assertEqual(
            {
                switch: configuration.port_toward_host(switch, destination)
                for switch in configuration.switch_names
            },
            {"s1": 5, "s2": 8, "s3": 2},
        )
        self.assertEqual(configuration.unused_port("s3"), 1)
        self.assertEqual(
            len(configuration.host_names) * (len(configuration.host_names) - 1), 30
        )

    def test_deep_tree_routes_across_both_aggregation_branches(self):
        configuration = load_configurations(
            VALIDATION_DIRECTORY / "network_configurations.json",
            ["deep_tree_7_switches_8_hosts"],
        )[0]
        self.assertEqual(configuration.path("s4", "s7"), ["s4", "s2", "s1", "s3", "s7"])
        expected_ports = {"s4": 9, "s2": 10, "s1": 8, "s3": 6, "s7": 2}
        self.assertEqual(
            {
                switch: configuration.port_toward_host(switch, "h7")
                for switch in expected_ports
            },
            expected_ports,
        )
        configuration.attachments["h7"] = ("s7", configuration.unused_port("s7"))
        self.assertEqual(configuration.port_toward_host("s7", "h7"), 1)
        self.assertEqual(configuration.port_toward_host("s3", "h7"), 6)
        self.assertEqual(
            len(configuration.host_names) * (len(configuration.host_names) - 1), 56
        )

    def test_descriptive_case_names_match_registered_scenarios_and_mutation_targets(
        self,
    ):
        from cases import SCENARIOS
        from run_mutation_tests import MUTATION_DETECTION_CASES

        cases = load_test_cases(
            VALIDATION_DIRECTORY / "development_cases.json", "runtime"
        )
        ids = {case["id"] for case in cases}
        self.assertEqual(len(ids), 9)
        self.assertTrue(set(MUTATION_DETECTION_CASES.values()) <= ids)
        for case in cases:
            self.assertTrue(case["id"].islower())
            self.assertFalse(any(character.isdigit() for character in case["id"]))
            self.assertIn(case["scenario"], SCENARIOS)
        plan = subprocess.run(
            [
                sys.executable,
                str(VALIDATION_DIRECTORY / "run_network_tests.py"),
                "--controller",
                "unused",
                "--configuration",
                "deep_tree_7_switches_8_hosts",
                "--case-id",
                "known_destination_forwarding",
                "--plan",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(json.loads(plan.stdout)["experiment_count"], 1)

    def test_inventory_supports_500_unique_hosts(self):
        configuration = NetworkConfiguration({"name": "large", "host_count": 500})
        self.assertEqual(
            len({host_mac_address(host) for host in configuration.host_names}), 500
        )
        self.assertEqual(configuration.host_ip("h256"), "10.0.1.0/16")
        self.assertEqual(len(host_mac_address("h256").split(":")), 6)

    def test_bad_topologies_and_unknown_names_are_rejected(self):
        for data in [
            {"name": "duplicate", "host_count": 3, "host_ports": [1, 1, 3]},
            {"name": "disconnected", "host_count": 3, "switches": ["s1", "s2"]},
            {"name": "loop", "host_count": 3, "switch_links": [["s1", 4, "s1", 5]]},
            {"name": "bad_roles", "host_count": 3, "roles": {"source": "h2"}},
        ]:
            with self.assertRaises(ValueError):
                NetworkConfiguration(data)
        with self.assertRaises(ValueError):
            load_configurations(
                VALIDATION_DIRECTORY / "network_configurations.json", ["typo"]
            )

    def test_actor_placeholders_preserve_literal_host_names(self):
        configuration = load_configurations(
            VALIDATION_DIRECTORY / "network_configurations.json"
        )[1]
        case = {"scenario": "static", "blocked": "$destination", "literal": "h2"}
        environment = NetworkTestEnvironment(
            SimpleNamespace(network_configuration=configuration), case, Path("unused")
        )
        self.assertEqual(environment.test_case["blocked"], "h3")
        self.assertEqual(environment.test_case["literal"], "h2")
        self.assertEqual(case["blocked"], "$destination")

    def test_mutation_detection_requires_intended_measured_symptom(self):
        failure = {
            "status": "FAIL",
            "checkpoint": "cached_path_blocked",
            "failure_code": "packet_delivery",
            "details": {"expected": 0, "observed": 3},
        }
        self.assertTrue(matches_expected_defect("cached_policy_bypass", failure))
        for change in (
            {"status": "ERROR"},
            {"checkpoint": "learning"},
            {"failure_code": "assertion"},
            {"details": {"expected": 3, "observed": 0}},
        ):
            self.assertFalse(
                matches_expected_defect("cached_policy_bypass", dict(failure, **change))
            )
        self.assertEqual(
            classify_test_run(
                1,
                [
                    dict(
                        failure,
                        id="runtime_block_and_unblock_cached_destination",
                        configuration="A",
                    )
                ],
                [
                    ("A", "runtime_block_and_unblock_cached_destination"),
                    ("B", "runtime_block_and_unblock_cached_destination"),
                ],
            ),
            "INVALID",
        )

    def test_cached_rule_inspection_uses_each_switchs_actual_ports(self):
        configuration = load_configurations(
            VALIDATION_DIRECTORY / "network_configurations.json",
            ["two_switches_4_hosts"],
        )[0]
        environment = NetworkTestEnvironment(
            SimpleNamespace(network_configuration=configuration),
            {"scenario": "known"},
            Path("unused"),
        )
        dumps = {
            "s1": "cookie=0x1, n_packets=7, priority=1,in_port=1,dl_dst=00:00:00:00:00:02 actions=output:3",
            "s2": "cookie=0x1, n_packets=8, priority=1,in_port=3,dl_dst=00:00:00:00:00:02 actions=1",
        }
        with patch(
            "Helpers.environment.run_command",
            side_effect=lambda command: dumps[command[-1]],
        ), patch.object(environment, "assert_destination_delivery"), patch.object(
            environment, "wait_for_controller_updates"
        ), patch.object(
            environment, "save_network_snapshot"
        ):
            environment.establish_cached_forwarding("h1", "h2")
            self.assertEqual(
                environment.forwarding_packet_counts("h1", "h2"), {"s1": 7, "s2": 8}
            )
            dumps["s2"] = dumps["s2"].replace("in_port=3", "in_port=2")
            with self.assertRaises(AssertionError):
                environment.establish_cached_forwarding("h1", "h2")

    def test_runner_executes_complete_matrix_and_resets_after_failure(self):
        started, cleaned = [], []

        class FakeEnvironment:
            def __init__(self, options, case, evidence):
                self.configuration = options.network_configuration
                self.case = case
                self.checkpoint = "mock"

            def start_network_and_controller(self):
                started.append((self.configuration.name, self.case["id"]))
                if self.configuration.attachments["h1"][1] == 99:
                    raise RuntimeError("Network state leaked from the previous case")

            def run_test_scenario(self):
                self.configuration.attachments["h1"] = ("s1", 99)
                if self.case["id"] == "known_destination_forwarding":
                    raise AssertionError("injected observation failure")

            def cleanup(self):
                cleaned.append((self.configuration.name, self.case["id"]))

        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(
            io.StringIO()
        ) as output:
            arguments = [
                "run_network_tests.py",
                "--controller",
                str(
                    VALIDATION_DIRECTORY
                    / "controller_variants/Helpers/controller_template.py"
                ),
                "--output",
                temporary,
            ]
            with patch.object(sys, "argv", arguments), patch.object(
                run_network_tests, "NetworkTestEnvironment", FakeEnvironment
            ), patch.object(
                run_network_tests, "validate_test_environment"
            ), patch.object(
                run_network_tests, "run_command", return_value="mock version"
            ):
                self.assertEqual(run_network_tests.main(), 1)
            summary = json.loads(
                next(Path(temporary).glob("*/summary.json")).read_text()
            )
            self.assertEqual(len(started), 45)
            self.assertEqual(started, cleaned)
            self.assertEqual(sum(row["status"] == "FAIL" for row in summary), 5)
            self.assertIn("two_switches_4_hosts", output.getvalue())
            self.assertIn("1 FAIL", format_summary(summary))
            self.assertTrue(next(Path(temporary).glob("*/summary.csv")).is_file())


if __name__ == "__main__":
    unittest.main()
