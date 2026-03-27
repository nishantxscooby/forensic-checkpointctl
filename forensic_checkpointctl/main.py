"""CLI: JSON file → normalize → rules → report."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .normalize import load_json_array, normalize_checkpoint
from .report import render_report
from .rules import run_all_rules


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="forensic-checkpointctl",
        description=(
            "Analyze checkpointctl JSON (from 'inspect --all --format=json') "
            "with simple forensic heuristics."
        ),
    )
    parser.add_argument(
        "json_path",
        type=Path,
        help="Path to JSON file (array of checkpoint objects)",
    )
    parser.add_argument(
        "--index",
        type=int,
        default=0,
        metavar="N",
        help="Index of checkpoint in the JSON array (default: 0)",
    )
    args = parser.parse_args(argv)

    path: Path = args.json_path
    if not path.is_file():
        print(f"error: not a file: {path}", file=sys.stderr)
        return 1

    try:
        data = load_json_array(str(path.resolve()))
    except OSError as exc:
        print(f"error: cannot read file: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON ({exc})", file=sys.stderr)
        return 1

    if len(data) == 0:
        print("error: JSON array is empty (no checkpoints).", file=sys.stderr)
        return 1

    if args.index < 0 or args.index >= len(data):
        print(
            f"error: --index {args.index} out of range "
            f"(array has {len(data)} element(s))",
            file=sys.stderr,
        )
        return 1

    raw = data[args.index]
    if not isinstance(raw, dict):
        print("error: checkpoint at index is not a JSON object", file=sys.stderr)
        return 1

    norm = normalize_checkpoint(raw)
    findings = run_all_rules(norm)
    print(render_report(norm, findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
