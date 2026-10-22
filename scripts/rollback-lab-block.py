#!/usr/bin/env python3
"""Remove one public address from the lab blocklist file."""

import sys

from soc_automation.config import settings
from soc_automation.response import LabResponse

if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python scripts/rollback-lab-block.py <public-ip>")
    print(LabResponse(settings).rollback(sys.argv[1]))
