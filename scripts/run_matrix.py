#!/usr/bin/env python3
"""Validation matrix: every lab profile x every test, versus the profiles' ``expected:`` maps.

Same as ``leakprobe matrix``; needs root (or scripts/sandbox.sh) unless --from-dir is given.

    sudo -E .venv/bin/python scripts/run_matrix.py --trials 5 -o matrix.md
    scripts/sandbox.sh uv run scripts/run_matrix.py --save-dir reports/
    uv run scripts/run_matrix.py --from-dir reports/      # re-score saved reports, no root
"""

import sys

from leakprobe.cli import app


def main() -> None:
    """Forward the arguments to ``leakprobe matrix``."""
    app(["matrix", *sys.argv[1:]], prog_name="run_matrix.py")


if __name__ == "__main__":
    main()
