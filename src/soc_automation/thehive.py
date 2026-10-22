"""TheHive 5 alert creation (TheHive 4 is not currently targeted)."""

from __future__ import annotations

import logging

import requests

log = logging.getLogger(__name__)


class TheHiveClient:
    def __init__(self, settings, session=None):
        self.settings = settings
        self.session = session or requests.Session()

    def create_alert(
        self,
        alert_id: str,
        title: str,
        description: str,
        score: dict,
        iocs: list[dict],
        severity: int,
    ) -> dict:
        if not self.settings.thehive_url or not self.settings.thehive_api_key:
            return {"status": "disabled"}
        observables = []
        type_map = {"ip": "ip", "domain": "domain", "url": "url", "hash": "hash"}
        for item in iocs:
            observables.append(
                {
                    "dataType": type_map[item["type"]],
                    "data": item["value"],
                    "tags": ["soc-automation", "synthetic-lab"],
                }
            )
        payload = {
            "type": "wazuh-alert",
            "source": "soc-incident-response-automation",
            "sourceRef": alert_id,
            "title": title[:512],
            "description": description[:8000],
            "severity": min(4, max(1, severity)),
            "tlp": 2,
            "pap": 2,
            "tags": ["wazuh", "automation", "human-approval-required"],
            "summary": (
                f"Risk score: {score.get('score')}; "
                f"source coverage: {', '.join(score.get('coverage', [])) or 'none'}"
            ),
            "observables": observables,
        }
        headers = {
            "Authorization": f"Bearer {self.settings.thehive_api_key}",
            "Content-Type": "application/json",
        }
        if self.settings.thehive_org:
            headers["X-Organisation"] = self.settings.thehive_org
        try:
            response = self.session.post(
                f"{self.settings.thehive_url.rstrip('/')}/api/v1/alert",
                json=payload,
                headers=headers,
                timeout=self.settings.request_timeout,
            )
            response.raise_for_status()
            body = response.json() if response.content else {}
            return {"status": "ok", "id": body.get("_id"), "url": self.settings.thehive_url}
        except (requests.RequestException, ValueError) as exc:
            log.warning("TheHive alert creation failed: %s", type(exc).__name__)
            return {"status": "error", "error": type(exc).__name__}
