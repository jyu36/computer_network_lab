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

ROOT = Path(__file__).resolve().parent
TARGETS = {'wrong_port': ('base', 'B02_known_forward'),
           'stale_mapping': ('movement', 'M01_move_after_cache'),
           'cached_bypass': ('runtime', 'R01_block_unblock_cached')}


def classify(returncode, results, expected_ids):
    if {r['id'] for r in results} != set(expected_ids) or len(results) != len(expected_ids):
        return 'INVALID'
    if any(r['status'] not in {'PASS', 'FAIL'} for r in results):
        return 'INVALID'
    if all(r['status'] == 'PASS' for r in results):
        return 'PASS' if returncode == 0 else 'INVALID'
    return 'FAIL' if returncode == 1 else 'INVALID'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ryu-manager', required=True)
    parser.add_argument('--variants', type=Path, default=ROOT / 'variants')
    parser.add_argument('--repeats', type=int, default=3)
    args = parser.parse_args()
    if args.repeats < 1:
        parser.error('repeats must be positive')
    directory = ROOT / 'results' / ('mutation_' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ'))
    directory.mkdir(parents=True)
    report = {'runs': [], 'complete': False, 'note': 'Curated defects only; not a general correctness guarantee'}
    cases = json.loads((ROOT / 'cases.json').read_text())

    def save():
        (directory / 'mutation_report.json').write_text(json.dumps(report, indent=2) + '\n')

    def execute(variant, stage, case, repetition):
        output = directory / ('%s_%d' % (variant, repetition))
        command = [sys.executable, str(ROOT / 'network.py'), '--controller', str(args.variants / (variant + '.py')),
                   '--stage', stage, '--ryu-manager', args.ryu_manager, '--output', str(output)]
        if case:
            command += ['--case', case]
        # Each run has a hard outer bound as well as per-operation timeouts.
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, start_new_session=True)
        try:
            log, _ = proc.communicate(timeout=900)
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            # Interrupt Python first so its finally block tears down Mininet.
            proc.send_signal(signal.SIGINT)
            try:
                log, _ = proc.communicate(timeout=30)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                log, _ = proc.communicate()
            log += '\nOUTER TIMEOUT: invalid run; check VM cleanup before retrying.\n'
            rc = -1
        (directory / ('%s_%d.log' % (variant, repetition))).write_text(log)
        summaries = list(output.glob('*/summary.json'))
        expected = [case] if case else [c['id'] for c in cases]
        results = json.loads(summaries[0].read_text()) if len(summaries) == 1 else []
        status = classify(rc, results, expected)
        row = {'variant': variant, 'repetition': repetition, 'outcome': status,
               'returncode': rc, 'cases': results, 'command': command}
        report['runs'].append(row)
        save()
        print(variant, repetition, status, flush=True)
        return status

    save()
    for repeat in range(1, args.repeats + 1):
        if execute('good', 'runtime', None, repeat) != 'PASS':
            print('Good control did not pass. Mutation evidence is invalid. Inspect', directory)
            return 2
        for variant, (stage, case) in TARGETS.items():
            if execute(variant, stage, case, repeat) != 'FAIL':
                print('Mutant survived or run was invalid. Inspect', directory)
                return 2
    report.update(complete=True, detected_distinct=3, attempted_distinct=3,
                  repeated_runs_per_variant=args.repeats)
    save()
    print('All curated defects detected on every repetition. Evidence:', directory)
    return 0


if __name__ == '__main__':
    sys.exit(main())
