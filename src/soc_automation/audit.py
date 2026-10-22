"""Append-only JSONL audit events with UTC timestamps."""

from __future__ import annotations

import json
import logging
import os
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger(__name__)


class AuditLog:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: dict) -> None:
        row = {"timestamp": datetime.now(UTC).isoformat(), **event}
        try:
            with self.path.open("a", encoding="utf-8") as output:
                output.write(json.dumps(row, sort_keys=True) + "\n")
                output.flush()
                os.fsync(output.fileno())
        except OSError:
            log.exception("Could not persist audit event")
            raise
