# Week 2 checker

For cloning into Ubuntu and the edit/push/pull/test commands, start with
[the Git workflow](../GIT_WORKFLOW.md). The machine-specific `MY_UBUNTU_SETUP.md`
also remains in the original Mac folder but is excluded from Git.
For an explanation of the project folders, see [the project guide](../README.md).

This folder prepares the Week 2 experiment described in the first-month plan.
It checks packet delivery, forbidden delivery, learning, installed rules, host movement,
and policy updates. It is not yet a validated checker: Linux integration runs are pending.

The existing draft was audited and used as scaffolding for `network.py`, `probe.py`,
and the control template. The original `testing/` folder is untouched. Changes here
include independent physical mutants, repeated mutation reporting, six-direction
unicast checks with simultaneous leakage checks, an unknown-destination policy case,
reserve event traces, source snapshots, capture-loss handling, and a stock-base mode.

## Start with the actual downloaded controller

The controller and Mininet run inside Ubuntu. The Mac can hold/edit the test files,
but cannot run these Linux network tests directly. Copy this entire folder into Ubuntu
using your VM's shared folder or file-transfer facility. Do not overwrite the downloaded
controller or edit files inside its installed Python package.

In Ubuntu, locate the controller and the working Ryu executable:

```bash
find ~ -type f \( -name 'simple_switch_13.py' -o -name 'example_switch_13.py' -o -name 'ryu-manager' \) 2>/dev/null
command -v ryu-manager
```

If `command -v` prints nothing, activate the virtual environment used in Week 1 first.
Keep that working environment; do not install or upgrade Ryu just to run these tests.
Record its dependency versions, the controller's Git commit if available, and its source.

For an unchanged Ryu OpenFlow 1.3 learning switch:

```bash
cd /your/copied/week2_checker
RYU_MANAGER=/absolute/path/to/working/venv/bin/ryu-manager
CONTROLLER=/absolute/path/to/downloaded/simple_switch_13.py
sudo /usr/bin/python3 network.py --controller "$CONTROLLER" --stock-base --stage base --ryu-manager "$RYU_MANAGER"
```

Replace both example paths. `--stock-base` skips the proposed HTTP interface and uses
real packet captures and OpenFlow flow-table evidence. The controller must install a
controller table-miss rule and destination forwarding rules visible in OVS flow dumps.
It supports the Ryu simple/example learning-switch pattern, not every possible controller.
POX/OpenFlow 1.0 needs a different launcher and checker adaptation; do not launch it with Ryu.

The runner launches the controller itself. Exit your manual Mininet session and stop
your manual controller first. It refuses to reuse `s1` or occupied ports; it never calls
`mn -c`. Required Linux tools: system Python with Mininet, OVS, tcpdump, and the working
Ryu executable. Root is needed for network namespaces and packet capture.

A base controller does not implement later requirements yet. Failure of a blocklist,
movement, or runtime-update test against the unchanged base is not evidence of a regression.
Create and validate a passing implementation for each accumulated stage first.

## Independent copies and deliberate bugs

`variants/good.py` is an AI-assisted control candidate implementing all four stages.
The name means intended control, not an observed pass. It is not a human-authored reference.
The three other files each differ from it by one deliberate defect. Their `.patch` files
show the exact edits, and `manifest.json` records hashes. No runtime bug flag is used.
Your downloaded source is not modified by these variants.

| Copy | Deliberate change | Expected detecting case |
|---|---|---|
| wrong_port.py | Send known unicast to another physical port | B02_known_forward |
| stale_mapping.py | Never update an already learned source location | M01_move_after_cache |
| cached_bypass.py | Change the blocklist without installing switch drop rules | R01_block_unblock_cached |

To rebuild these copies in a new directory, use Python 3.9+ on the Mac:

```bash
python3 make_variants.py --output variants_new
```

The generated controller files and network runner support Python 3.8+. The generator
only targets the included template. Do not apply its mutations blindly to GitHub code.
For the real downloaded controller, copy its exact source into your experiment folder,
make each equivalent one-defect edit separately, and save each diff. Use a passing
movement implementation for a stale-mapping mutation and a passing runtime-policy
implementation for cached-policy bypass. Those features do not exist in a base switch.

## Run and validate the control before testing the bugs

Review `INTERFACE.md` before later-stage tests. Its HTTP endpoints, strict input rules,
and port-renumbering movement model are proposed engineering choices, not requirements
quoted from the assignment. The downloaded stock controller has no such API.

Start small in Ubuntu:

```bash
sudo /usr/bin/python3 network.py --controller variants/good.py --stage base --ryu-manager "$RYU_MANAGER"
sudo /usr/bin/python3 network.py --controller variants/good.py --stage blocklist --ryu-manager "$RYU_MANAGER"
sudo /usr/bin/python3 network.py --controller variants/good.py --stage movement --ryu-manager "$RYU_MANAGER"
sudo /usr/bin/python3 network.py --controller variants/good.py --stage runtime --ryu-manager "$RYU_MANAGER"
```

After every stage passes, run the repeated control/mutant experiment:

```bash
sudo /usr/bin/python3 check_mutations.py --ryu-manager "$RYU_MANAGER" --repeats 3
```

Each repetition runs all nine development cases on the good control, then each mutant's
specific detecting case. Every independent case starts a fresh controller and network.
The report stops if the good control fails, a mutant survives, or a run is invalid.
Inspect `results/mutation_*/mutation_report.json` and the packet evidence before
claiming detection. There are currently no observed mutation results.

`FAIL` is a behavior assertion failure. `ERROR`, crashes, absent cases, capture loss,
preflight failure, and timeouts are invalid experiments, never successful bug detection.
The mutation report is valid only if the control passes and all three intended cases
fail on every repetition. Even then, 3/3 measures these three chosen defects only.

## Behavior coverage

| Requirement | Development evidence |
|---|---|
| Unknown destination floods | B01: both other hosts receive the same tagged frame |
| Learn and cache known destinations | B02: six ordered host pairs; cached destination rule |
| Known unicast does not leak | B02: destination and third host captured in the same burst |
| ARP and ICMP interoperate | B03: every ordered ping pair succeeds |
| Destination-only policy, known and unknown | P01/P02: drops plus allowed and blocked-source controls |
| Movement after cached traffic | M01: observed new source port, stale rule removed, traffic restored |
| Movement retains destination policy | M02: movement plus blocked destination remains blocked |
| Block/unblock affects existing and new traffic | R01: cached path, new ingress pair, allowed paths, repeated updates |
| Invalid update leaves policy unchanged | R02: bad types/MACs/keys, status and packet behavior |

This is requirement/sequence coverage, not a percentage of all possible behavior or
source branches. A high line-coverage number cannot establish absence of forwarding
bugs. The cached-policy sequence is the subtle failure for the Week 2 demo: fresh
pings can pass while an old installed rule still bypasses the new policy.

Each run saves the controller source and SHA-256, environment versions, per-case
controller logs, pcaps, decoded packet counts, API exchanges, flow/port dumps, and results.
Packet tags distinguish test traffic from ARP and ICMP replies. tcpdump must report
zero kernel drops. Non-delivery means zero matching packets within the observation
window (default one second after sending), not a proof about arbitrarily delayed traffic.
`--observe-seconds` adjusts that bound; freeze it before comparing implementations.
Do not run with Python `-O`, which disables assertions; the runner refuses it.

## Reserve evaluation cases and research limits

`../week2_researcher_evaluation/` contains reserve traces. Run its cases with the same
`--cases` option after development tests pass. Keep that directory, controls, results,
future requirements, and this full researcher workspace outside coding-agent sandboxes.
A folder name alone provides no secrecy. Do not include the control variants in an agent's
workspace. Give agents only their current code, current contract, and current-stage
visible tests. The prepared reserve cases still need review and independent expansion.

Before the pilot: validate controls and mutants in the actual VM; review the contract,
completion semantics and tests with Soudeh; freeze passing per-stage snapshots and
pin the Linux environment. The combined control here is not four independently
validated minimal controls. Physical cable reattachment, repeated moves to arbitrary
ports, multiple switches, IPv6, fault recovery, performance and formal correctness
are outside this checker. Movement currently renumbers the same OVS host port to 4.

## What has been checked on the Mac

```bash
python3 -m unittest discover -s . -p test_tools.py -v
python3 network.py --controller variants/good.py --stage runtime --list
```

Local tooling checks validate deterministic variant generation and result classification.
They do not validate forwarding, Ryu event ordering, OVS behavior, or mutant detection.
