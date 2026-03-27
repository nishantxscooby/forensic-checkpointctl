#!/usr/bin/env python3
"""
Launch the analyzer from any working directory.

  python path/to/forensic-checkpointctl/cli.py checkpoint.json
"""

from __future__ import annotations

import sys
from pathlib import Path

# Project root = directory that contains the `forensic_checkpointctl` package.
_PROJECT_ROOT = Path(__file__).resolve().parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from forensic_checkpointctl.main import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
