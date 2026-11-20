#!/usr/bin/env python3
"""Run frozen baseline traces on both original and simplified controllers, then compare."""

import argparse
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

PROJECT_DIRECTORY = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_DIRECTORY))

from controller_simplification.Helpers.compare_results import build_plan, compare_batch, prepare_component_recheck


def main():
    """Keep every run sequential, save evidence, and report bounded acceptance."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ryu-manager', default=str(Path.home() / 'sdn-project/.venv/bin/ryu-manager'))
    parser.add_argument('--plan', action='store_true', help='Validate hashes and show counts without starting networks')
    parser.add_argument('--recheck-from', type=Path,
                        help='Reuse verified unchanged passing evidence from this original batch; rerun only the corrected partition case')
    arguments = parser.parse_args()
    plan = build_plan(PROJECT_DIRECTORY)
    if arguments.recheck_from:
        plan = prepare_component_recheck(plan, arguments.recheck_from, PROJECT_DIRECTORY)
    if arguments.plan:
        print(json.dumps(plan, indent=2))
        return 0
    ryu_manager = Path(arguments.ryu_manager).expanduser().resolve()
    if sys.platform != 'linux' or not os.access(ryu_manager, os.X_OK):
        parser.error('Run in Ubuntu with an executable --ryu-manager path')
    if subprocess.run(['sudo', '-v']).returncode:
        return 2
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    batch_directory = PROJECT_DIRECTORY / 'controller_simplification/test_results' / ('comparison_' + timestamp)
    batch_directory.mkdir(parents=True)
    shutil.copytree(PROJECT_DIRECTORY / 'controller_simplification/comparison_tests', batch_directory / 'test_definitions')
    (batch_directory / 'run_plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    print('%d runner launches; %d case executions; sequential, fresh network per case.'
          % (plan['runner_launches'], plan['case_executions']), flush=True)
    executions = []
    execution_error = False
    execution_runs = plan.get('execution_runs', plan['runs'])
    try:
        for number, run in enumerate(execution_runs, 1):
            # Recheck frozen inputs before every launch, including long batches.
            build_plan(PROJECT_DIRECTORY)
            output_directory = batch_directory / run['source'] / run['version'] / run['configuration']
            output_directory.mkdir(parents=True)
            command = [
                'sudo', '/usr/bin/python3', str(PROJECT_DIRECTORY / 'network_validation/run_network_tests.py'),
                '--controller', str(PROJECT_DIRECTORY / run['controller']), '--suite', 'base',
                '--configuration-file', str(PROJECT_DIRECTORY / run['configuration_file']),
                '--configuration', run['configuration'],
                '--case-file', str(PROJECT_DIRECTORY / run['case_file']),
                '--ryu-manager', str(ryu_manager), '--results-directory', str(output_directory), '--verbose',
            ]
            if arguments.recheck_from:
                command.extend(['--case-id', run['case_ids'][0]])
            print('\n[%d/%d] %s / %s / %s' % (number, len(execution_runs), run['source'], run['version'], run['configuration']), flush=True)
            with (output_directory / 'terminal.log').open('w') as log:
                with subprocess.Popen(command, cwd=PROJECT_DIRECTORY, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True, errors='replace') as process:
                    for line in process.stdout:
                        log.write(line)
                        log.flush()
                        print(line, end='', flush=True)
                    return_code = process.wait()
            executions.append(dict(run, exit_code=return_code))
            (batch_directory / 'executions.json').write_text(json.dumps(executions, indent=2) + '\n')
            if return_code not in (0, 1):
                execution_error = True
                print('Execution error: stopping; incomplete pairs will be inconclusive.', flush=True)
                break
    finally:
        # Restore ownership of only this newly created batch, not the repository.
        if subprocess.run(['sudo', 'chown', '-R', '%d:%d' % (os.getuid(), os.getgid()), str(batch_directory)]).returncode:
            execution_error = True
    report = compare_batch(batch_directory, plan)
    (batch_directory / 'paired_comparison.json').write_text(json.dumps(report, indent=2) + '\n')
    print('\nPaired comparison:', report['counts'])
    for source, outcome in report['acceptance'].items():
        print(source + ': ' + outcome)
    print('Matching packet traces do not prove general equivalence; inconclusive tables remain unverified.')
    print('Results saved in:', batch_directory)
    if execution_error or report['counts']['INCONCLUSIVE']:
        return 2
    return 1 if report['counts']['REJECT'] else 0


if __name__ == '__main__':
    sys.exit(main())
