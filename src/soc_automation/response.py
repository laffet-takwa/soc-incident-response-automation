"""Safe lab-only response action with a matching rollback command."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path


class LabResponse:
    def __init__(self, settings):
        self.settings = settings
        self.path = Path(settings.blocklist_path)

    def execute(self, action: str, target: str, dry_run: bool | None = None) -> dict:
        if action != "block_ip":
            raise ValueError("Only block_ip is supported in the lab")
        address = ipaddress.ip_address(target)
        if not address.is_global:
            raise ValueError("Only public IPs may enter the lab blocklist demo")
        run_dry = self.settings.dry_run if dry_run is None else dry_run
        if run_dry:
            return {"status": "dry_run", "action": action, "target": str(address)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        existing = (
            set(self.path.read_text(encoding="utf-8").splitlines()) if self.path.exists() else set()
        )
        existing.add(str(address))
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text("\n".join(sorted(existing)) + "\n", encoding="utf-8")
        os.replace(temporary, self.path)
        return {
            "status": "executed",
            "action": action,
            "target": str(address),
            "rollback": f"python scripts/rollback-lab-block.py {address}",
        }

    def rollback(self, target: str) -> dict:
        address = ipaddress.ip_address(target)
        if not self.path.exists():
            return {"status": "not_found", "target": str(address)}
        rows = [
            line
            for line in self.path.read_text(encoding="utf-8").splitlines()
            if line.strip() != str(address)
        ]
        self.path.write_text("\n".join(rows) + ("\n" if rows else ""), encoding="utf-8")
        return {"status": "rolled_back", "target": str(address)}
