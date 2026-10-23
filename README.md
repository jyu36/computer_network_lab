# Computer network lab

Automated behavior tests for a Ryu OpenFlow 1.3 learning switch, using one OVS
switch and three Mininet hosts. Edit on the Mac, push to GitHub, then pull and
run in Ubuntu. The harness starts and stops Ryu and Mininet for each independent
case; movement and policy-update sequences preserve state within a case.

## Project structure

| Path | Purpose |
|---|---|
| `controllers/example_switch_13.py` | Copy of the original installed Ryu controller |
| `network_validation/run_network_tests.py` | Main network-test runner |
| `network_validation/development_cases.json` | Nine visible test cases |
| `network_validation/send_test_packets.py` | Generates tagged ARP and ICMP packets |
| `network_validation/run_mutation_tests.py` | Compares the prepared reference and buggy controllers |
| `network_validation/controller_template.py` | Expanded controller template |
| `network_validation/generate_controller_variants.py` | Builds controller variants, diffs, and source hashes |
| `network_validation/controller_variants/` | Generated reference and three deliberate controller defects |
| `network_validation/test_validation_tools.py` | Local tooling regression tests |
| [Controller interface](network_validation/INTERFACE.md) | Proposed behavior and update-completion contract |
| `researcher_evaluation/evaluation_cases.json` | Local-only reserve event sequences, excluded from Git |

`NetworkTestEnvironment` manages one case. Its main sequence is
`start_network_and_controller()` → `run_test_scenario()` → `cleanup()`.
Functions such as `assert_packet_delivery()`, `establish_cached_forwarding()`,
`relocate_host_port()`, and `replace_destination_blocklist()` perform the test actions.
The old `week2_checker/` folder is now named `network_validation/`.

## Git workflow

On the Mac, review and upload your changes:

```bash
cd ~/Desktop/Computer_Network
git status
git add -A
git diff --cached
git commit -m "Describe your changes"
git push
```

On Ubuntu, clone once into the existing project directory:

```bash
cd ~/sdn-project
git clone https://github.com/jyu36/computer_network_lab.git
```

For later sessions, enter that clone and run `git pull --ff-only`. Commit and
push Ubuntu edits before pulling them onto the Mac. Changes to the installed
Ryu package outside this repository are not tracked; edit experiment copies
inside `controllers/` instead.

## Run the original controller's base tests in Ubuntu

Connect using your usual SSH command (`ssh jyu164@192.168.2.4` for the current VM).
First exit any manual Mininet session and stop manual Ryu. If stale Mininet
state remains after ending other experiments, run `sudo mn -c` inside Ubuntu.

```bash
cd ~/sdn-project/computer_network_lab
git pull --ff-only
source ~/sdn-project/.venv/bin/activate
cd network_validation
sudo /usr/bin/python3 run_network_tests.py \
  --stock-controller \
  --stage base \
  --controller ../controllers/example_switch_13.py \
  --ryu-manager "$HOME/sdn-project/.venv/bin/ryu-manager"
```

System Python needs Mininet; Ubuntu also needs OVS and tcpdump. Ryu uses the
existing virtual environment. Do not start a separate controller or network.
The previous CLI spellings such as `--stock-base` and `--cases` remain aliases.

## Coverage and deliberate bugs

Stages are cumulative: base selects 3 cases, blocklist 5, movement 7, and runtime 9.
B01–B03 cover flooding, known forwarding without leakage, and all-pairs ping.
P01/P02 check destination blocking before and after learning. M01/M02 simulate
movement by renumbering a host's OVS port to 4 and check policy preservation.
R01 checks repeated block/unblock updates on cached and new paths; R02 checks
invalid updates. These are sequence checks, not a measured coverage percentage.

The prepared variants come from the AI-assisted expanded template, not the
original controller copy. `reference_controller.py` is an intended passing
control that still needs validation. The defects are `wrong_output_port.py`,
`stale_host_location.py`, and `cached_policy_bypass.py`. Their patches and
`source_manifest.json` record the exact source differences and hashes.

After validating the reference, run the mutation experiment from `network_validation/`:

```bash
sudo /usr/bin/python3 run_mutation_tests.py \
  --ryu-manager "$HOME/sdn-project/.venv/bin/ryu-manager" \
  --repetitions 1
```

For reserve evaluation, select `--case-file ../researcher_evaluation/evaluation_cases.json`
with the expanded reference and `--stage runtime`. Keep reserve cases, controls,
and results outside future coding agents' accessible workspaces.

## Evidence and current limitations

Runs save summaries, controller logs/source, environment versions, flow/port dumps,
and packet captures for tagged observations under `network_validation/results/`.
PASS means the implemented assertions passed; FAIL is an assertion failure;
ERROR is an execution or cleanup failure. Non-delivery is measured within a
bounded observation window, one second after sending by default.

The original controller passed three base cases in one reported Ubuntu run.
The renamed harness, later-stage tests, and mutation detections still need
Ubuntu integration validation. Known checker gaps remain: mutation failure
attribution, stale-rule output parsing, and complete cached-rule verification.
This setup does not establish multi-switch behavior, IPv6 support, performance,
physical cable reattachment, or formal correctness.

Local checks, runnable from the repository root:

```bash
python3 -m unittest discover -s network_validation -p test_validation_tools.py -v
```

`.gitignore` excludes environments, generated results/captures, reserve cases,
and the original assignment document. Preserve the assignment and experiment
evidence locally. After pulling the folder rename, historical Ubuntu results
may remain under `week2_checker/results/`; Git does not move ignored files.
