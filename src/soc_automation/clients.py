"""Threat intelligence clients and SQLite cache with safe degradation."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from urllib.parse import quote

import requests

log = logging.getLogger(__name__)


class Cache:
    def __init__(self, path: str, ttl_seconds: int = 3600):
        self.path, self.ttl_seconds = path, ttl_seconds
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with sqlite3.connect(path) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT, created REAL)"
            )

    def get(self, key: str):
        with self.lock, sqlite3.connect(self.path) as db:
            row = db.execute("SELECT value, created FROM cache WHERE key=?", (key,)).fetchone()
        if not row or time.time() - row[1] > self.ttl_seconds:
            return None
        return json.loads(row[0])

    def put(self, key: str, value):
        with self.lock, sqlite3.connect(self.path) as db:
            db.execute(
                "INSERT OR REPLACE INTO cache VALUES (?, ?, ?)",
                (key, json.dumps(value), time.time()),
            )


class VTGate:
    """Process-wide serialized 4 requests/minute public API limiter."""

    lock = threading.Lock()
    calls: list[float] = []

    @classmethod
    def wait(cls):
        with cls.lock:
            now = time.monotonic()
            cls.calls = [stamp for stamp in cls.calls if now - stamp < 60]
            if len(cls.calls) >= 4:
                time.sleep(max(0.0, 60 - (now - cls.calls[0])))
                now = time.monotonic()
                cls.calls = [stamp for stamp in cls.calls if now - stamp < 60]
            cls.calls.append(time.monotonic())


class EnrichmentClients:
    def __init__(self, settings, cache: Cache, session=None):
        self.settings, self.cache = settings, cache
        self.session = session or requests.Session()

    def _get_json(self, key: str, url: str, headers: dict, params: dict | None = None, vt=False):
        cached = self.cache.get(key)
        if cached is not None:
            return {"status": "cached", **cached}
        if vt:
            VTGate.wait()
        last_error = "request_failed"
        for attempt in range(3):
            try:
                response = self.session.get(
                    url, headers=headers, params=params, timeout=self.settings.request_timeout
                )
                if response.status_code == 429:
                    last_error = "rate_limited"
                    if attempt < 2:
                        retry_after = response.headers.get("Retry-After", "1")
                        try:
                            time.sleep(min(float(retry_after), 30))
                        except ValueError:
                            time.sleep(1)
                        continue
                    break
                response.raise_for_status()
                payload = response.json()
                self.cache.put(key, payload)
                return {"status": "ok", "raw": payload}
            except requests.Timeout:
                last_error = "timeout"
            except requests.RequestException as exc:
                last_error = f"http_error:{getattr(exc.response, 'status_code', 'unknown')}"
                if getattr(exc.response, "status_code", 0) >= 500 and attempt < 2:
                    time.sleep(0.25 * (attempt + 1))
                    continue
                break
            except (ValueError, json.JSONDecodeError):
                last_error = "invalid_json"
                break
        log.warning("Enrichment source failure: %s", last_error)
        return {"status": "error", "error": last_error}

    def virustotal(self, ioc: dict) -> dict:
        key = self.settings.vt_api_key
        if not key:
            return {"status": "disabled"}
        kind, value = ioc["type"], ioc["value"]
        if kind == "ip":
            path = f"ip_addresses/{quote(value, safe='')}"
        elif kind == "domain":
            path = f"domains/{quote(value, safe='')}"
        elif kind == "url":
            # VT URL objects use the URL-safe identifier, not an upload/scan operation.
            import base64

            url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
            path = f"urls/{url_id}"
        elif kind == "hash":
            path = f"files/{quote(value, safe='')}"
        else:
            return {"status": "unsupported"}
        result = self._get_json(
            f"vt:{kind}:{value}",
            f"https://www.virustotal.com/api/v3/{path}",
            {"x-apikey": key},
            vt=True,
        )
        if result["status"] not in {"ok", "cached"}:
            return result
        raw = result.get("raw", {})
        stats = raw.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        total = sum(int(value or 0) for value in stats.values())
        return {
            "status": result["status"],
            "malicious": malicious,
            "total": total,
            "malicious_ratio": malicious / total if total else 0.0,
        }

    def abuseipdb(self, ioc: dict) -> dict:
        if ioc["type"] != "ip":
            return {"status": "not_applicable"}
        key = self.settings.abuseipdb_api_key
        if not key:
            return {"status": "disabled"}
        result = self._get_json(
            f"abuseipdb:{ioc['value']}",
            "https://api.abuseipdb.com/api/v2/check",
            {"Key": key, "Accept": "application/json"},
            {"ipAddress": ioc["value"], "maxAgeInDays": 90},
        )
        if result["status"] not in {"ok", "cached"}:
            return result
        data = result.get("raw", {}).get("data", {})
        return {
            "status": result["status"],
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
        }

    def otx(self, ioc: dict) -> dict:
        key = self.settings.otx_api_key
        if not key:
            return {"status": "disabled"}
        type_map = {"ip": "IPv4", "domain": "domain", "url": "url", "hash": "file"}
        if ioc["type"] not in type_map:
            return {"status": "unsupported"}
        url = (
            "https://otx.alienvault.com/api/v1/indicators/"
            f"{type_map[ioc['type']]}/{quote(ioc['value'], safe='')}/general"
        )
        result = self._get_json(f"otx:{ioc['type']}:{ioc['value']}", url, {"X-OTX-API-KEY": key})
        if result["status"] not in {"ok", "cached"}:
            return result
        pulse_count = result.get("raw", {}).get("pulse_info", {}).get("count", 0)
        return {"status": result["status"], "pulse_count": int(pulse_count or 0)}

    def enrich(self, ioc: dict) -> dict:
        return {
            "virustotal": self.virustotal(ioc),
            "abuseipdb": self.abuseipdb(ioc),
            "otx": self.otx(ioc),
        }
