#!/usr/bin/env bash
# Evaluate the two frozen proposals. This is the baseline acceptance screen;
# held-out behavior comparisons are still required before accepting a cleanup.
set -uo pipefail

project_directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)" || exit 2
cd "$project_directory" || exit 2
ryu_manager="${1:-$HOME/sdn-project/.venv/bin/ryu-manager}"
if [ ! -x "$ryu_manager" ]; then
  echo "Ryu executable not found: $ryu_manager" >&2
  exit 2
fi

# Refuse evaluation if the proposals changed after the researcher froze them.
/usr/bin/python3 - <<'PY' || exit 2
import hashlib
import json
from pathlib import Path

manifest = json.loads(Path('week_four/experiment_manifest.json').read_text())
for label, record in manifest['source_mapping_researcher_only'].items():
    source = Path(record['proposal_snapshot'])
    if hashlib.sha256(source.read_bytes()).hexdigest() != record['proposal_sha256']:
        raise SystemExit('Frozen proposal hash mismatch: ' + label)
PY

sudo -v || exit 2
batch_directory="$project_directory/week_four/evaluation_results/baseline_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$batch_directory" || exit 2
overall_status=0

for source_label in source_a source_b; do
  echo "Evaluating simplified baseline: $source_label"
  sudo /usr/bin/python3 network_validation/run_network_tests.py \
    --controller "week_four/proposals/$source_label/controller.py" \
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
