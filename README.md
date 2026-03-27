Built following discussion in CRIU checkpointctl issue #211.

# Forensic analysis tool for CRIU container checkpoints

**forensic-checkpointctl** is a small Python tool that analyzes JSON produced by [**checkpointctl**](https://github.com/checkpoint-restore/checkpointctl) (`inspect --all --format=json`). It applies **explicit, heuristic** checks for suspicious processes, sensitive file paths, and basic socket/port patterns—useful for triage, not as a final verdict.

## Overview

The tool:

- Loads a JSON file whose root is an **array** of checkpoint objects (same shape as checkpointctl output).
- Normalizes processes, open file paths, and sockets from that JSON.
- Emits a **short plain-text report** with three sections: suspicious processes, sensitive file access, network activity.
- Uses **only the Python standard library** (no pip dependencies).

It does **not** read checkpoint archives or CRIU images directly; **checkpointctl remains the extraction layer**.

## Motivation: extract once, analyze many times

Container checkpoints can be **large** and **slow to parse**. A practical workflow (as discussed on the checkpointctl side, e.g. [#211](https://github.com/checkpoint-restore/checkpointctl/issues/211)) is:

| Layer | Role |
|-------|------|
| **checkpointctl** | Parse the archive once; produce structured JSON (process tree, FDs, sockets, metadata). |
| **forensic-checkpointctl** (this tool) | Read that JSON **many times** with lightweight rules—no repeated tarball/CRIU cost. |

That separation keeps heavy I/O and format handling in checkpointctl and keeps analysis **fast, repeatable, and easy to change** here.

## Installation

- **Python 3.10 or newer**
- Clone the repository; **no `pip install` is required** for normal use.

```bash
git clone https://github.com/<you>/forensic-checkpointctl.git
cd forensic-checkpointctl
```

## Usage

**1. Produce JSON with checkpointctl** (one-time cost on the checkpoint archive):

```bash
checkpointctl inspect --all --format=json my-checkpoint.tar > checkpoint.json
```

**2. Analyze with this tool** (defaults to the **first** checkpoint in the array):

```bash
python cli.py checkpoint.json
```

**Multiple checkpoints** in one JSON file—select by index:

```bash
python cli.py checkpoint.json --index 1
```

**Run from any directory** (use absolute paths):

```bash
python /path/to/forensic-checkpointctl/cli.py /path/to/checkpoint.json
```

**Module entry** (from the **repository root**):

```bash
cd forensic-checkpointctl
python -m forensic_checkpointctl checkpoint.json
```

Errors exit with a non-zero status and print `error: ...` to **stderr**.

## Example output

Below is **representative** output from the bundled fixture `tests/fixtures/sample_full.json` (not from a live production checkpoint):

```text
Checkpoint forensic report (MVP)
==================================================
Container: demo
Engine:    Podman
Image:     docker.io/library/alpine:latest
ID:        abc123deadbeef
Counts:    processes=2 open_paths=2 connections=2

Suspicious Processes
------------------------------
  • pid=1 command='bash' cmdline='bash -c /bin/sh -c wget http://x/'
    Process name or command line contains suspicious substring(s): bash, sh, wget. These often appear in shells or common download/reverse-shell tooling.
  • pid=42 command='nc' cmdline='nc -l -p 4444'
    Process name or command line contains suspicious substring(s): nc. These often appear in shells or common download/reverse-shell tooling.

Sensitive File Access
------------------------------
  • pid=1 path=/etc/passwd
    Open file path matches sensitive pattern(s): /etc/passwd (credentials, keys, or privileged paths).
  • pid=1 path=/root/.bash_history
    Open file path matches sensitive pattern(s): /root (credentials, keys, or privileged paths).

Network Activity
------------------------------
  • pid=42 TCP 0.0.0.0:4444 -> 0.0.0.0:0 state=LISTEN
    Socket / connection from checkpoint CRIU data.
  • pid=42 TCP 0.0.0.0:4444 -> 0.0.0.0:0 state=LISTEN
    Port(s) outside common set {80, 443, 22}: [4444]. Review in context of the workload.
  • pid=42 TCP 10.0.0.2:443 -> 93.184.216.34:443 state=ESTABLISHED
    Socket / connection from checkpoint CRIU data.
```

Sections with no matches state that explicitly.

## Design principles

- **Lightweight** — stdlib only, small codebase, easy to review.
- **Heuristic-based** — fixed substring and port rules; **no** machine learning; every flag should be explainable.
- **Modular** — `normalize` → `rules` → `report`; CLI is a thin wrapper (`cli.py` + `forensic_checkpointctl/main.py`).

Legitimate workloads may trigger false positives (e.g. `curl`, `/root` bind mounts). Treat output as **triage**.

## Project structure

```text
forensic-checkpointctl/
  LICENSE
  README.md
  pyproject.toml
  cli.py                      # entry from any cwd (uses absolute path to repo)
  forensic_checkpointctl/
    __init__.py
    __main__.py               # python -m forensic_checkpointctl
    main.py                   # CLI and pipeline
    normalize.py              # JSON → dataclasses
    rules.py                  # findings
    report.py                 # text report
  tests/fixtures/             # sample JSON for manual checks
```

## Manual checks

```bash
cd forensic-checkpointctl
python cli.py tests/fixtures/sample_full.json
python cli.py tests/fixtures/edge_not_list.json   # expect exit code 1
```

After you publish, validate once against **real** `checkpointctl inspect --all --format=json` output from your environment.

## License

MIT — see [`LICENSE`](LICENSE).
