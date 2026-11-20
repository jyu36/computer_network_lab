"""Local checks for the paired-evidence comparator; no Mininet is simulated."""

import copy
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from Helpers.topology import load_configurations
from controller_simplification.Helpers.compare_results import (
    build_plan, compare_batch, compare_case, load_run_evidence, prepare_component_recheck,
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
        return {'source': 'ryu_reference', 'version': version, 'configuration': 'fixture',
                'case_ids': ['case'],
                'controller_sha256': hashlib.sha256(b'controller snapshot\n').hexdigest()}

    def test_missing_and_complete_batches_have_distinct_acceptance(self):
        runs = [self.make_run(version) for version in ('original', 'simplified')]
        with tempfile.TemporaryDirectory() as temporary:
            batch = Path(temporary)
            for run in runs:
                self.make_evidence(batch / run['source'] / run['version'] / run['configuration'], run)
            report = compare_batch(batch, {'runs': runs})
            self.assertEqual(report['acceptance']['ryu_reference'], 'ACCEPTED_FOR_TESTED_TRACES')
            summary = next((batch / 'ryu_reference/simplified').rglob('summary.json'))
            summary.unlink()
            report = compare_batch(batch, {'runs': runs})
            self.assertEqual(report['acceptance']['ryu_reference'], 'NOT_ACCEPTED')
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

    def test_learned_unicast_and_unknown_component_flooding_are_distinct(self):
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
                        self.assertTrue(any(previous['op'] == 'learn'
                                            for previous in case['steps'][:case['steps'].index(step)]))
                        for host, should_receive in step['expect'].items():
                            # ARP learns every host in this component, but cannot
                            # teach a remote-component destination. Its unknown
                            # MAC is flooded locally; isolation applies at the
                            # destination, not at all bystanders.
                            destination_known = config.hosts_connected(step['source'], step['destination'])
                            expected = (host == step['destination'] if destination_known
                                        else config.hosts_connected(step['source'], host))
                            self.assertEqual(should_receive, expected)

    def test_disconnected_target_still_floods_to_local_bystanders(self):
        cases = json.loads((PROJECT_DIRECTORY / 'controller_simplification/comparison_tests/partition_test_cases.json').read_text())
        steps = next(case['steps'] for case in cases if case['id'] == 'preservation_repeated_component_delivery')
        cross_component = [step for step in steps if step['op'] == 'observe'
                           and step['source'] == 'h2' and step['destination'] == 'h4']
        self.assertEqual(len(cross_component), 2)
        for step in cross_component:
            self.assertEqual(step['expect'], {'h1': True, 'h3': True, 'h4': False})
        known_unicast = next(step for step in steps if step['op'] == 'observe'
                             and step['source'] == 'h2' and step['destination'] == 'h1')
        self.assertEqual(known_unicast['expect'], {'h1': True, 'h3': False, 'h4': False})

    def test_targeted_recheck_replaces_failed_case_without_reusing_it(self):
        plan = build_plan(PROJECT_DIRECTORY)
        affected_config = 'held_out_two_components_sparse_ports'
        affected_case = 'preservation_repeated_component_delivery'

        def write_run(directory, run, case_ids, previous=False):
            evidence = directory / 'timestamp_controller'
            evidence.mkdir(parents=True)
            shutil.copyfile(PROJECT_DIRECTORY / run['controller'], evidence / 'controller_source.py')
            (evidence / 'environment.json').write_text(json.dumps({
                'controller_sha256': run['controller_sha256']}))
            rows = []
            for case_id in case_ids:
                failed = previous and run['configuration'] == affected_config and case_id == affected_case
                rows.append({'configuration': run['configuration'], 'id': case_id,
                             'status': 'FAIL' if failed else 'PASS'})
                case_directory = evidence / run['configuration'] / case_id
                case_directory.mkdir(parents=True)
                (case_directory / 'events.json').write_text(json.dumps([self.observation]))
            (evidence / 'summary.json').write_text(json.dumps(rows))

        with tempfile.TemporaryDirectory() as temporary:
            previous = Path(temporary) / 'previous'
            current = Path(temporary) / 'current'
            shutil.copytree(PROJECT_DIRECTORY / 'controller_simplification/comparison_tests', previous / 'test_definitions')
            for run in plan['runs']:
                key = (run['source'], run['version'], run['configuration'])
                write_run(previous.joinpath(*key), run, run['case_ids'], previous=True)
                if run['configuration'] == affected_config:
                    write_run(current.joinpath(*key), run, [affected_case])
            recheck = prepare_component_recheck(plan, previous, PROJECT_DIRECTORY)
            self.assertEqual(recheck['runner_launches'], 4)
            self.assertEqual(recheck['case_executions'], 4)
            self.assertEqual(recheck['reused_case_executions'], 20)
            report = compare_batch(current, recheck)
            self.assertEqual(report['counts'], {'MATCH': 12, 'REJECT': 0, 'INCONCLUSIVE': 0})

            # Earlier Ubuntu batches keep their original names and archived
            # definitions. Renaming the project must not force a full rerun.
            legacy = Path(temporary) / 'legacy'
            shutil.copytree(previous, legacy)
            definition = legacy / 'test_definitions'
            definition.rename(legacy / 'evaluation_definition')
            definition = legacy / 'evaluation_definition'
            settings = json.loads((definition / 'settings.json').read_text())
            old_paths = {}
            for fixture in settings['experiments']:
                old_path = fixture['case_file']
                previous_filename = fixture['configuration'] + '_cases.json'
                (definition / Path(old_path).name).rename(definition / previous_filename)
                fixture['case_file'] = 'week_four/held_out/' + previous_filename
                old_paths[old_path] = fixture['case_file']
            old_config = settings['configuration_file']
            settings['configuration_file'] = 'week_four/held_out/network_configurations.json'
            old_paths[old_config] = settings['configuration_file']
            settings['asset_sha256'] = {old_paths[key]: value for key, value in settings['asset_sha256'].items()}
            (definition / 'settings.json').unlink()
            (definition / 'manifest.json').write_text(json.dumps(settings))
            (legacy / 'ryu_reference').rename(legacy / 'source_a')
            (legacy / 'attempt_01').rename(legacy / 'source_b')
            legacy_recheck = prepare_component_recheck(plan, legacy, PROJECT_DIRECTORY)
            self.assertEqual(compare_batch(current, legacy_recheck)['counts']['MATCH'], 12)

            # If a new corrected-case result is missing, the old FAIL must not
            # silently take its place or allow acceptance.
            next((current / 'ryu_reference/simplified').rglob('summary.json')).unlink()
            report = compare_batch(current, recheck)
            self.assertEqual(report['acceptance']['ryu_reference'], 'NOT_ACCEPTED')

            # Passing old evidence cannot be reused if another case changed.
            definition = previous / 'test_definitions'
            old_manifest = json.loads((definition / 'settings.json').read_text())
            fixture = old_manifest['experiments'][0]
            path = definition / Path(fixture['case_file']).name
            cases = json.loads(path.read_text())
            cases[0]['unexpected_change'] = True
            path.write_text(json.dumps(cases))
            old_manifest['asset_sha256'][fixture['case_file']] = hashlib.sha256(path.read_bytes()).hexdigest()
            (definition / 'settings.json').write_text(json.dumps(old_manifest))
            with self.assertRaisesRegex(ValueError, 'unchanged case'):
                prepare_component_recheck(plan, previous, PROJECT_DIRECTORY)


if __name__ == '__main__':
    unittest.main()
