# Git workflow between the Mac and Ubuntu

Repository: https://github.com/jyu36/computer_network_lab

The Mac and Ubuntu each have a local copy. GitHub transfers committed source
changes between them. Saving a file alone does not upload it.

## One-time Ubuntu setup

Connect to your Ubuntu VM using your usual SSH command. Keep using the working
Ryu environment in `~/sdn-project/.venv`; cloning this project does not replace it.

Inside Ubuntu:

```bash
cd ~/sdn-project
git clone https://github.com/jyu36/computer_network_lab.git
cd computer_network_lab
git status
```

Do this once. For future sessions, enter the existing folder and pull instead
of cloning again. If the repository is private, Ubuntu needs GitHub authentication.
Do not put a password or token in the repository URL or commit one into a file.

## After editing tests on the Mac

Run these commands in a **Mac terminal**:

```bash
cd ~/Desktop/Computer_Network
git status
git add README.md GIT_WORKFLOW.md .gitignore week2_checker
git diff --cached
git commit -m "Improve learning switch tests"
git push
```

`git diff --cached` shows what will be committed. Use a message describing your
change. If there is nothing to commit, there are no new tracked changes to upload.
Results and other ignored files remain local.

## Pull and test in Ubuntu

In your SSH session inside **Ubuntu**:

```bash
cd ~/sdn-project/computer_network_lab
git pull --ff-only
source ~/sdn-project/.venv/bin/activate
RYU_MANAGER="$HOME/sdn-project/.venv/bin/ryu-manager"
CONTROLLER=$(python -c 'import importlib.util; print(importlib.util.find_spec("ryu.app.example_switch_13").origin)')
cd week2_checker
sudo /usr/bin/python3 network.py --stock-base --stage base --controller "$CONTROLLER" --ryu-manager "$RYU_MANAGER"
```

First exit manual Mininet with `exit` and stop manual Ryu with Control+C. The
checker starts them itself. It requires system Python with Mininet, OVS, and
tcpdump, alongside the working Ryu environment. Evidence is saved under
`week2_checker/results/` on Ubuntu and is intentionally excluded from Git.

`git pull --ff-only` stops if the two copies have diverged instead of making
an automatic merge. If you have uncommitted Ubuntu edits, commit them or resolve
them deliberately before pulling. Do not discard changes to get past an error.

## If you edit controller copies on Ubuntu

Installed Ryu files outside this repository are not tracked. Make an experiment
copy inside the repository instead of modifying the installed package:

```bash
cd ~/sdn-project/computer_network_lab
mkdir -p controllers
cp "$CONTROLLER" controllers/example_switch_13.py
```

The `CONTROLLER` variable above must have been set in this SSH session. After
editing the copy, commit and push it from Ubuntu:

```bash
git add controllers/example_switch_13.py
git commit -m "Add experiment controller copy"
git push
```

Use `--controller ../controllers/example_switch_13.py` when running from
`week2_checker/`. `--stock-base` only supports the base stage; later stages
need the agreed API. Pull on the Mac before editing again. Ubuntu may ask you
to configure your Git author name/email before its first commit.

The daily cycle is **Mac edit → commit → push → Ubuntu pull → test**. If you
edit on Ubuntu too, push there and pull on the Mac before continuing.
