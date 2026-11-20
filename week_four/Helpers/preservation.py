"""Validate frozen evaluation inputs and compare endpoint packet evidence."""

import hashlib
import json
from pathlib import Path


PACKET_FIELDS = ('source', 'destination', 'receiver', 'sent', 'received', 'allowed')


def build_plan(project_directory):
    """Check frozen hashes and enumerate the matched controller/fixture runs."""
    project_directory = Path(project_directory)
    experiment = json.loads((project_directory / 'week_four/experiment_manifest.json').read_text())
    held_out_path = project_directory / experiment['held_out_manifest']
    if hashlib.sha256(held_out_path.read_bytes()).hexdigest() != experiment['held_out_manifest_sha256']:
        raise ValueError('Frozen held-out manifest changed')
    held_out = json.loads(held_out_path.read_text())
    for relative_path, expected_hash in held_out['asset_sha256'].items():
        if hashlib.sha256((project_directory / relative_path).read_bytes()).hexdigest() != expected_hash:
            raise ValueError('Frozen evaluation asset changed: ' + relative_path)
    runs = []
    for label, source in experiment['source_mapping_researcher_only'].items():
        for version, path_key, hash_key in (
            ('original', 'original_snapshot', 'original_sha256'),
            ('simplified', 'proposal_snapshot', 'proposal_sha256'),
        ):
            controller = source[path_key]
            expected_hash = source[hash_key]
            if hashlib.sha256((project_directory / controller).read_bytes()).hexdigest() != expected_hash:
                raise ValueError('Frozen controller changed: ' + controller)
            for fixture in held_out['experiments']:
                runs.append(dict(fixture, source=label, version=version,
                                 controller=controller, controller_sha256=expected_hash,
                                 configuration_file=held_out['configuration_file']))
    case_count = sum(len(run['case_ids']) for run in runs)
    if (not runs or len(runs) != held_out['runner_launches']
            or case_count != held_out['case_executions']):
        raise ValueError('Evaluation run/case counts differ from frozen definition')
    return {'runs': runs, 'definition': held_out,
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


def compare_batch(batch_directory, plan):
    """Build a paired report; missing or failed evidence cannot imply acceptance."""
    batch_directory = Path(batch_directory)
    loaded = {}
    for run in plan['runs']:
        key = (run['source'], run['version'], run['configuration'])
        directory = batch_directory.joinpath(*key)
        try:
            loaded[key] = (load_run_evidence(directory, run), None)
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
        'counts': {status: sum(row['status'] == status for row in comparisons)
                   for status in ('MATCH', 'REJECT', 'INCONCLUSIVE')},
        'limitations': [
            'Matching concrete traces is test evidence, not proof of general equivalence.',
            'Inconclusive forwarding-table analyses remain unverified.',
            'Evaluation definitions were made after proposals were frozen; this is exploratory.',
            'Evaluation duration does not measure AI implementation effort.',
        ],
    }
