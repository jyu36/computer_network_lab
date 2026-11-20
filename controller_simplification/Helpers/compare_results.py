"""Validate frozen evaluation inputs and compare endpoint packet evidence."""

import hashlib
import json
from pathlib import Path


PACKET_FIELDS = ('source', 'destination', 'receiver', 'sent', 'received', 'allowed')
RECHECK_CONFIGURATION = 'held_out_two_components_sparse_ports'
RECHECK_CASE = 'preservation_repeated_component_delivery'


def build_plan(project_directory):
    """Check frozen hashes and enumerate the matched controller/fixture runs."""
    project_directory = Path(project_directory)
    experiment = json.loads((project_directory / 'controller_simplification/experiment_settings.json').read_text())
    test_settings_path = project_directory / experiment['comparison_test_settings']
    if hashlib.sha256(test_settings_path.read_bytes()).hexdigest() != experiment['comparison_test_settings_sha256']:
        raise ValueError('Comparison test settings changed')
    test_settings = json.loads(test_settings_path.read_text())
    for relative_path, expected_hash in test_settings['asset_sha256'].items():
        if hashlib.sha256((project_directory / relative_path).read_bytes()).hexdigest() != expected_hash:
            raise ValueError('Frozen evaluation asset changed: ' + relative_path)
    runs = []
    for label, source in experiment['controllers'].items():
        for version, path_key, hash_key in (
            ('original', 'original_controller', 'original_sha256'),
            ('simplified', 'simplified_controller', 'simplified_sha256'),
        ):
            controller = source[path_key]
            expected_hash = source[hash_key]
            if hashlib.sha256((project_directory / controller).read_bytes()).hexdigest() != expected_hash:
                raise ValueError('Frozen controller changed: ' + controller)
            for fixture in test_settings['experiments']:
                runs.append(dict(fixture, source=label, version=version,
                                 controller=controller, controller_sha256=expected_hash,
                                 previous_result_label=source.get('previous_result_label', label),
                                 configuration_file=test_settings['configuration_file']))
    case_count = sum(len(run['case_ids']) for run in runs)
    if (not runs or len(runs) != test_settings['runner_launches']
            or case_count != test_settings['case_executions']):
        raise ValueError('Evaluation run/case counts differ from frozen definition')
    return {'runs': runs, 'definition': test_settings,
            'runner_launches': len(runs), 'case_executions': case_count}


def load_run_evidence(directory, run):
    """Require complete, uniquely identified runner output and its source snapshot."""
    summaries = list(Path(directory).glob('*/summary.json'))
    if len(summaries) != 1:
        raise ValueError('Expected exactly one runner summary in ' + str(directory))
    evidence_directory = summaries[0].parent
    environment = json.loads((evidence_directory / 'environment.json').read_text())
    source_hash = hashlib.sha256((evidence_directory / 'controller_source.py').read_bytes()).hexdigest()
    if source_hash != run['controller_sha256'] or environment['controller_sha256'] != source_hash:
        raise ValueError('Evaluated controller snapshot/hash does not match frozen input')
    rows = json.loads(summaries[0].read_text())
    expected = {(run['configuration'], case_id) for case_id in run['case_ids']}
    observed = [(row['configuration'], row['id']) for row in rows]
    if len(observed) != len(expected) or set(observed) != expected:
        raise ValueError('Missing, duplicate or unexpected case results')
    evidence = {}
    for row in rows:
        events_path = evidence_directory / row['configuration'] / row['id'] / 'events.json'
        # A setup/cleanup error may leave no packet evidence. Do not turn that
        # absence into an empty observation list that can match another failure.
        events = json.loads(events_path.read_text()) if events_path.exists() else []
        packets = [{key: event[key] for key in PACKET_FIELDS}
                   for event in events if all(key in event for key in PACKET_FIELDS)]
        evidence[row['id']] = {
            'status': row['status'], 'packets': packets,
            'table_checks': row.get('forwarding_table_checks', {}),
        }
    return evidence


def compare_case(original, simplified):
    """Accept matching required packet outcomes only when both cases passed."""
    statuses = [original['status'], simplified['status']]
    if any(status in {'ERROR', 'NOT_RUN'} for status in statuses):
        return 'INCONCLUSIVE', 'Execution error or incomplete evaluation'
    if statuses != ['PASS', 'PASS']:
        return 'REJECT', 'At least one controller violated a tested requirement'
    if any(item.get('table_checks', {}).get('FAIL', 0) for item in (original, simplified)):
        return 'REJECT', 'A definite forwarding-table violation was reported'
    if not original['packets'] or not simplified['packets']:
        return 'INCONCLUSIVE', 'No comparable endpoint packet evidence'
    for item in (original, simplified):
        for packet in item['packets']:
            expected = packet['sent'] if packet['allowed'] else 0
            if packet['received'] != expected:
                return 'REJECT', 'Packet evidence contradicts required delivery'
    if original['packets'] != simplified['packets']:
        return 'REJECT', 'Ordered endpoint packet observations differ'
    return 'MATCH', 'Both passed and endpoint packet observations match'


def prepare_component_recheck(plan, previous_batch, project_directory):
    """Reuse unchanged passing cases; rerun only the corrected partition case.

    Verify old frozen definitions and controller snapshots. No evidence from a
    changed case is reused, and any other definition change prevents reuse.
    """
    previous_batch, project_directory = Path(previous_batch).resolve(), Path(project_directory)
    previous_definition = previous_batch / 'test_definitions'
    if not previous_definition.exists():
        previous_definition = previous_batch / 'evaluation_definition'
    settings_path = previous_definition / 'settings.json'
    if not settings_path.exists():
        settings_path = previous_definition / 'manifest.json'
    old_manifest = json.loads(settings_path.read_text())
    for relative_path, expected_hash in old_manifest['asset_sha256'].items():
        archived = previous_definition / Path(relative_path).name
        if hashlib.sha256(archived.read_bytes()).hexdigest() != expected_hash:
            raise ValueError('Previous frozen evaluation asset hash mismatch')
    definition = plan['definition']
    previous_fixtures = {fixture['configuration']: fixture for fixture in old_manifest['experiments']}
    if {name: fixture['case_ids'] for name, fixture in previous_fixtures.items()} != {
            fixture['configuration']: fixture['case_ids'] for fixture in definition['experiments']}:
        raise ValueError('Previous fixture/case selection differs; run a full evaluation')
    config_name = Path(definition['configuration_file']).name
    if (previous_definition / config_name).read_bytes() != (project_directory / definition['configuration_file']).read_bytes():
        raise ValueError('Network definitions changed; cannot reuse previous results')
    for fixture in definition['experiments']:
        current = json.loads((project_directory / fixture['case_file']).read_text())
        old_case_file = previous_fixtures[fixture['configuration']]['case_file']
        previous = json.loads((previous_definition / Path(old_case_file).name).read_text())
        if len(current) != len(previous):
            raise ValueError('Case definitions changed; cannot reuse previous results')
        for old_case, new_case in zip(previous, current):
            if (fixture['configuration'], new_case['id']) != (RECHECK_CONFIGURATION, RECHECK_CASE):
                if old_case != new_case:
                    raise ValueError('An unchanged case definition differs; cannot reuse')
            elif old_case['id'] != new_case['id']:
                raise ValueError('Corrected case identity differs')
    execution_runs = []
    for run in plan['runs']:
        old_evidence = load_run_evidence(find_run_directory(previous_batch, run), run)
        for case_id, evidence in old_evidence.items():
            if (run['configuration'], case_id) != (RECHECK_CONFIGURATION, RECHECK_CASE):
                if evidence['status'] != 'PASS' or not evidence['packets']:
                    raise ValueError('An unchanged case lacks passing packet evidence; cannot reuse')
        if run['configuration'] == RECHECK_CONFIGURATION:
            execution_runs.append(dict(run, case_ids=[RECHECK_CASE]))
    if len(execution_runs) != 4:
        raise ValueError('Expected exactly four corrected-case evaluations')
    return dict(plan, previous_batch=str(previous_batch), execution_runs=execution_runs,
                runner_launches=4, case_executions=4, reused_case_executions=20)


def find_run_directory(batch_directory, run):
    """Read new descriptive folder names or the earlier source_a/source_b names."""
    directory = Path(batch_directory) / run['source'] / run['version'] / run['configuration']
    if directory.exists():
        return directory
    return Path(batch_directory) / run.get('previous_result_label', run['source']) / run['version'] / run['configuration']


def compare_batch(batch_directory, plan):
    """Build a paired report; missing or failed evidence cannot imply acceptance."""
    batch_directory = Path(batch_directory)
    loaded = {}
    for run in plan['runs']:
        key = (run['source'], run['version'], run['configuration'])
        try:
            previous_batch = plan.get('previous_batch')
            directory = find_run_directory(previous_batch, run) if previous_batch else batch_directory.joinpath(*key)
            evidence = load_run_evidence(directory, run)
            if previous_batch and run['configuration'] == RECHECK_CONFIGURATION:
                replacement = load_run_evidence(
                    batch_directory.joinpath(*key), dict(run, case_ids=[RECHECK_CASE]))
                evidence[RECHECK_CASE] = replacement[RECHECK_CASE]
            loaded[key] = (evidence, None)
        except (OSError, ValueError, KeyError, TypeError) as error:
            loaded[key] = (None, str(error))
    comparisons = []
    for run in plan['runs']:
        if run['version'] != 'original':
            continue
        source, configuration = run['source'], run['configuration']
        original, original_error = loaded[(source, 'original', configuration)]
        simplified, simplified_error = loaded[(source, 'simplified', configuration)]
        for case_id in run['case_ids']:
            row = {'source': source, 'configuration': configuration, 'case': case_id}
            if original_error or simplified_error:
                row.update(status='INCONCLUSIVE', reason='Missing or invalid run evidence',
                           original_error=original_error, simplified_error=simplified_error)
            else:
                status, reason = compare_case(original[case_id], simplified[case_id])
                row.update(status=status, reason=reason,
                           original_observation_count=len(original[case_id]['packets']),
                           simplified_observation_count=len(simplified[case_id]['packets']),
                           original_table_checks=original[case_id]['table_checks'],
                           simplified_table_checks=simplified[case_id]['table_checks'])
            comparisons.append(row)
    acceptance = {
        source: ('ACCEPTED_FOR_TESTED_TRACES'
                 if all(row['status'] == 'MATCH' for row in comparisons if row['source'] == source)
                 else 'NOT_ACCEPTED')
        for source in dict.fromkeys(run['source'] for run in plan['runs'])
    }
    return {
        'acceptance': acceptance, 'comparisons': comparisons,
        'reused_from_previous_batch': plan.get('previous_batch'),
        'counts': {status: sum(row['status'] == status for row in comparisons)
                   for status in ('MATCH', 'REJECT', 'INCONCLUSIVE')},
        'limitations': [
            'Matching concrete traces is test evidence, not proof of general equivalence.',
            'Inconclusive forwarding-table analyses remain unverified.',
            'Comparison tests were defined after simplified versions were saved; this is exploratory.',
            'Evaluation duration does not measure AI implementation effort.',
        ],
    }
