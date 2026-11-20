#!/usr/bin/env bash
# Evaluate the two saved simplified controllers. This is the baseline acceptance screen;
# additional behavior comparisons are still required before accepting a cleanup.
set -uo pipefail

project_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
cd "$project_directory" || exit 2
ryu_manager="${1:-$HOME/sdn-project/.venv/bin/ryu-manager}"
if [ ! -x "$ryu_manager" ]; then
  echo "Ryu executable not found: $ryu_manager" >&2
  exit 2
fi

# Refuse evaluation if the simplified controllers changed after the researcher froze them.
/usr/bin/python3 - <<'PY' || exit 2
import hashlib
import json
from pathlib import Path

manifest = json.loads(Path('controller_simplification/experiment_settings.json').read_text())
for label, record in manifest['controllers'].items():
    source = Path(record['simplified_controller'])
    if hashlib.sha256(source.read_bytes()).hexdigest() != record['simplified_sha256']:
        raise SystemExit('Saved simplified controller hash mismatch: ' + label)
PY

sudo -v || exit 2
batch_directory="$project_directory/controller_simplification/test_results/baseline_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$batch_directory" || exit 2
overall_status=0

for source_label in ryu_reference attempt_01; do
  echo "Evaluating simplified baseline: $source_label"
  sudo /usr/bin/python3 network_validation/run_network_tests.py \
    --controller "controller_simplification/controllers/$source_label/simplified.py" \
    --suite base \
    --ryu-manager "$ryu_manager" \
    --results-directory "$batch_directory/$source_label" \
    --verbose \
    2>&1 | tee "$batch_directory/$source_label.terminal.log"

  pipeline_status=("${PIPESTATUS[@]}")
  test_status=${pipeline_status[0]}
  logging_status=${pipeline_status[1]}
  if ! echo "$source_label: test exit code $test_status; log exit code $logging_status" \
    | tee -a "$batch_directory/batch_summary.txt"; then
    logging_status=1
  fi
  if [ "$test_status" -gt 1 ] || [ "$logging_status" -ne 0 ]; then
    overall_status=2
    echo "Execution or logging error; stopping for investigation." >&2
    break
  elif [ "$test_status" -eq 1 ]; then
    overall_status=1
  fi
done

if ! sudo chown -R "$(id -un):$(id -gn)" "$batch_directory"; then
  overall_status=2
fi
echo "Results saved in: $batch_directory"
exit "$overall_status"
