#!/usr/bin/env python3
"""Entry point used by the Claude skill. Works without installing the package:

    python scripts/scan.py example.com --json
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinelscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
