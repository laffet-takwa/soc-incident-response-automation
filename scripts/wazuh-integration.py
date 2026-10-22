#!/usr/bin/env python3
"""Wazuh custom integration using the Integrator alert-file/argument contract."""

import json
import os
import sys

import requests


def main():
    if len(sys.argv) < 4:
        raise ValueError("expected alert-file, API token, and webhook URL arguments")
    with open(sys.argv[1], encoding="utf-8") as alert_file:
        alert = json.load(alert_file)
    rule = alert.get("rule", {})
    if int(rule.get("level", 0)) < int(os.getenv("MIN_RULE_LEVEL", "7")):
        return 0
    hook_url = sys.argv[3]
    response = requests.post(
        hook_url,
        json=alert,
        headers={"Authorization": f"Bearer {sys.argv[2]}"},
        timeout=10,
    )
    response.raise_for_status()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"soc automation integration failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1) from exc
