"""Replay synthetic fixture alerts and persist honest per-stage measurements."""

from __future__ import annotations

import argparse
import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from statistics import median

import requests


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", type=int, default=30)
    parser.add_argument("--url", default="http://127.0.0.1:8080/webhook/wazuh")
    parser.add_argument("--output", default="benchmark-results.json")
    args = parser.parse_args()
    if args.count < 30:
        parser.error("--count must be at least 30")
    fixtures = json.loads(Path("tests/fixtures/wazuh-alerts.json").read_text(encoding="utf-8"))
    token = os.getenv("AUTOMATION_API_TOKEN", "local-demo-token")
    runs, errors, api_failures, api_timeouts = [], 0, 0, 0
    for index in range(args.count):
        alert = fixtures[index % len(fixtures)].copy()
        alert["id"] = f"synthetic-{index:04d}"
        alert["timestamp"] = datetime.now(UTC).isoformat()
        started = time.perf_counter()
        try:
            response = requests.post(
                args.url, json=alert, headers={"Authorization": f"Bearer {token}"}, timeout=30
            )
            elapsed = time.perf_counter() - started
            response.raise_for_status()
            result = response.json()
            api_failures += sum(result.get("api_failures", {}).values())
            api_timeouts += result.get("api_timeouts", 0)
            runs.append(
                {
                    "index": index,
                    "status": result["status"],
                    "elapsed_seconds": elapsed,
                    "score": result.get("score", {}).get("score"),
                    "stages": result.get("stages", {}),
                }
            )
        except (requests.RequestException, ValueError) as exc:
            errors += 1
            runs.append({"index": index, "status": "error", "error": type(exc).__name__})
    times = sorted(row["elapsed_seconds"] for row in runs if row.get("elapsed_seconds") is not None)
    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": "synthetic fixture replay",
        "requested_alerts": args.count,
        "completed": len(times),
        "errors": errors,
        "api_enrichment_enabled": os.getenv("ENRICH_PUBLIC_IOCS", "false").lower() == "true",
        "api_failures": api_failures,
        "api_timeouts": api_timeouts,
        "false_positive_labeled_count": None,
        "average_seconds": sum(times) / len(times) if times else None,
        "median_seconds": median(times) if times else None,
        "p95_seconds": times[min(len(times) - 1, int(len(times) * 0.95))] if times else None,
        "runs": runs,
    }
    Path(args.output).write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                key: summary[key]
                for key in (
                    "requested_alerts",
                    "completed",
                    "errors",
                    "average_seconds",
                    "median_seconds",
                    "p95_seconds",
                )
            },
            indent=2,
        )
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
