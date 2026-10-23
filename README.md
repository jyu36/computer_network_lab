# Computer network lab

Week 2 tests for a Ryu OpenFlow 1.3 learning switch using one OVS switch and
three Mininet hosts. Edit on the Mac, push to GitHub, then pull and run inside
Ubuntu. See [GIT_WORKFLOW.md](GIT_WORKFLOW.md) for setup and commands.

## Project files

| Path | Purpose |
|---|---|
| `week2_checker/` | Current checker, visible development cases, proposed control and three deliberate mutants |
| `week2_checker/README.md` | Test requirements, commands, coverage and limitations |
| `week2_checker/INTERFACE.md` | Proposed interface for later blocklist, movement and runtime-update stages |
| `GIT_WORKFLOW.md` | Initial Ubuntu clone and the daily edit/push/pull/test workflow |

The old `testing/` folder and draft ZIP are not required by this checker.

## Start with the base controller

Use your existing Ryu installation and `ryu.app.example_switch_13` for the
first automated base run. Stop manual Ryu and Mininet sessions before running
the checker: it launches both itself. Later stages need implementations of
the additional requirements and their update-completion interface.

## Validation status

Local tooling checks pass on the Mac. Actual forwarding tests and mutation
detections still need validation in the Ubuntu VM. `variants/good.py` is an
AI-assisted control candidate, not an observed passing or human-authored reference.

To run local tooling checks from the repository root:

```bash
python3 -m unittest discover -s week2_checker -p test_tools.py -v
```

## Files kept local

`.gitignore` excludes generated captures and results, Python environments,
reserve evaluation traces, the original assignment document, and the
machine-specific `MY_UBUNTU_SETUP.md` notes. These files can remain in the Mac
folder but will not appear in a fresh clone. Reserve cases need separate
evaluator storage outside future coding agents' workspaces; do not push them
into this development repository.
