"""Local tooling checks only. These do not simulate a switch or prove controller correctness."""

import ast
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from generate_controller_variants import generate_controller_variants
from run_mutation_tests import classify_test_run
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
            self.assertEqual(
                {path.name for path in generated_directory.iterdir()},
                {path.name for path in published_directory.iterdir() if path.is_file()},
            )
            for generated_path in generated_directory.iterdir():
                self.assertEqual(
                    generated_path.read_bytes(),
                    (published_directory / generated_path.name).read_bytes(),
                    generated_path.name,
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
                "B02_known_forward",
                "--list",
            ],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        self.assertEqual(
            [test_case["id"] for test_case in json.loads(completed_run.stdout)],
            ["B02_known_forward"],
        )


if __name__ == "__main__":
    unittest.main()
