"""Local checks for the paired-evidence comparator; no Mininet is simulated."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from Helpers.topology import load_configurations
from week_four.Helpers.preservation import (
    build_plan, compare_batch, compare_case, load_run_evidence,
)


PROJECT_DIRECTORY = Path(__file__).resolve().parents[1]


class PreservationComparisonTests(unittest.TestCase):
    def setUp(self):
        self.observation = {
            'source': 'h1', 'destination': 'h2', 'receiver': 'h2',
            'sent': 3, 'received': 3, 'allowed': True,
        }
        self.passed = {'status': 'PASS', 'packets': [self.observation],
                       'table_checks': {'PASS': 1, 'FAIL': 0, 'INCONCLUSIVE': 2}}

    def test_matching_passes_keep_table_uncertainty_separate(self):
        self.assertEqual(compare_case(self.passed, copy.deepcopy(self.passed))[0], 'MATCH')

    def test_matching_failures_are_not_accepted(self):
        failed = dict(self.passed, status='FAIL')
        self.assertEqual(compare_case(failed, failed)[0], 'REJECT')
        missing = dict(self.passed, status='NOT_RUN')
        self.assertEqual(compare_case(missing, missing)[0], 'INCONCLUSIVE')

    def test_empty_packet_evidence_is_not_a_match(self):
        empty = dict(self.passed, packets=[])
        self.assertEqual(compare_case(empty, empty)[0], 'INCONCLUSIVE')

    def test_incorrect_counts_are_rejected_even_if_status_claims_pass(self):
        incorrect = copy.deepcopy(self.passed)
        incorrect['packets'][0]['received'] = 0
        self.assertEqual(compare_case(incorrect, incorrect)[0], 'REJECT')

    def test_ordered_observations_must_match(self):
        other = dict(self.observation, source='h2', destination='h1', receiver='h1')
        original = dict(self.passed, packets=[self.observation, other])
        simplified = dict(self.passed, packets=[other, self.observation])
        self.assertEqual(compare_case(original, simplified)[0], 'REJECT')

    def test_definite_table_failure_cannot_be_hidden_by_case_pass(self):
        failed = dict(self.passed, table_checks={'FAIL': 1})
        self.assertEqual(compare_case(self.passed, failed)[0], 'REJECT')

    def make_evidence(self, directory, run, duplicate=False):
        """Write minimal evidence with a real, verifiable source snapshot hash."""
        evidence = directory / 'timestamp_controller'
        case = evidence / 'fixture' / 'case'
        case.mkdir(parents=True)
        (evidence / 'controller_source.py').write_bytes(b'controller snapshot\n')
        (evidence / 'environment.json').write_text(json.dumps({
            'controller_sha256': run['controller_sha256']}))
        row = {'configuration': 'fixture', 'id': 'case', 'status': 'PASS',
               'forwarding_table_checks': {'PASS': 1, 'INCONCLUSIVE': 2}}
        (evidence / 'summary.json').write_text(json.dumps([row, row] if duplicate else [row]))
        (case / 'events.json').write_text(json.dumps([self.observation]))
        return evidence

    def make_run(self, version):
        return {'source': 'source_a', 'version': version, 'configuration': 'fixture',
                'case_ids': ['case'],
                'controller_sha256': hashlib.sha256(b'controller snapshot\n').hexdigest()}

    def test_missing_and_complete_batches_have_distinct_acceptance(self):
        runs = [self.make_run(version) for version in ('original', 'simplified')]
        with tempfile.TemporaryDirectory() as temporary:
            batch = Path(temporary)
            for run in runs:
                self.make_evidence(batch / run['source'] / run['version'] / run['configuration'], run)
            report = compare_batch(batch, {'runs': runs})
            self.assertEqual(report['acceptance']['source_a'], 'ACCEPTED_FOR_TESTED_TRACES')
            summary = next((batch / 'source_a/simplified').rglob('summary.json'))
            summary.unlink()
            report = compare_batch(batch, {'runs': runs})
            self.assertEqual(report['acceptance']['source_a'], 'NOT_ACCEPTED')
            self.assertEqual(report['counts']['INCONCLUSIVE'], 1)

    def test_wrong_source_snapshot_and_duplicate_cases_are_invalid(self):
        run = self.make_run('original')
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            evidence = self.make_evidence(directory, run, duplicate=True)
            with self.assertRaises(ValueError):
                load_run_evidence(directory, run)
            (evidence / 'controller_source.py').write_bytes(b'different controller')
            with self.assertRaises(ValueError):
                load_run_evidence(directory, run)

    def test_frozen_plan_contains_twenty_four_executions(self):
        plan = build_plan(PROJECT_DIRECTORY)
        self.assertEqual(plan['runner_launches'], 8)
        self.assertEqual(plan['case_executions'], 24)

    def test_frozen_trace_expectations_agree_with_physical_components(self):
        plan = build_plan(PROJECT_DIRECTORY)
        configurations = {config.name: config for config in load_configurations(
            PROJECT_DIRECTORY / plan['definition']['configuration_file'])}
        for fixture in plan['definition']['experiments']:
            config = configurations[fixture['configuration']]
            cases = json.loads((PROJECT_DIRECTORY / fixture['case_file']).read_text())
            self.assertEqual([case['id'] for case in cases], fixture['case_ids'])
            for case in cases:
                self.assertEqual(case['stage'], 'base')
                for step in case.get('steps', []):
                    self.assertIn(step['op'], {'learn', 'cache', 'observe'})
                    if step['op'] == 'cache':
                        self.assertTrue(config.hosts_connected(step['source'], step['destination']))
                    elif step['op'] == 'observe':
                        self.assertEqual(set(step['expect']), set(config.host_names) - {step['source']})
                        for host, should_receive in step['expect'].items():
                            self.assertEqual(should_receive, host == step['destination'] and
                                             config.hosts_connected(step['source'], host))


if __name__ == '__main__':
    unittest.main()
