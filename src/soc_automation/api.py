"""Flask webhook and explicit human approval API."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask, jsonify, request

from .audit import AuditLog
from .clients import Cache, EnrichmentClients
from .config import settings
from .extraction import extract_iocs, safe_alert_id
from .notifications import Notifier
from .response import LabResponse
from .scoring import score_alert, score_ioc, severity
from .thehive import TheHiveClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger(__name__)
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
audit = AuditLog(settings.audit_path)
cache = Cache(settings.cache_path)
enrichment = EnrichmentClients(settings, cache)
thehive = TheHiveClient(settings)
notifier = Notifier(settings)
response_action = LabResponse(settings)
approvals: dict[str, dict] = {}
APPROVAL_TTL = 24 * 60 * 60


def _authorized() -> bool:
    return hmac.compare_digest(
        request.headers.get("Authorization", ""), f"Bearer {settings.api_token}"
    )


def _allowlist() -> set[str]:
    path = Path(settings.allowlist_path)
    if not path.exists():
        return set()
    return {
        line.split("#", 1)[0].strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.split("#", 1)[0].strip()
    }


def _stage() -> dict:
    return {"time": datetime.now(UTC).isoformat(), "monotonic": time.perf_counter()}


@app.get("/health")
def health():
    return jsonify({"status": "ok", "mode": "dry-run" if settings.dry_run else "lab-file-response"})


@app.post("/webhook/wazuh")
def wazuh_webhook():
    if not _authorized():
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"error": "expected JSON object"}), 400
    stages = {"received": _stage()}
    rule = payload.get("rule") if isinstance(payload.get("rule"), dict) else {}
    try:
        level = int(rule.get("level", 0))
    except (ValueError, TypeError):
        level = 0
    if level < settings.min_rule_level:
        audit.write({"event": "alert_ignored", "reason": "below_rule_threshold", "level": level})
        return jsonify({"status": "ignored", "reason": "below_rule_threshold"}), 202

    # Only alert content fields are scanned; sensitive metadata is not sent to public APIs.
    raw_content = json.dumps(
        {key: payload.get(key) for key in ("rule", "data", "full_log", "location")},
        ensure_ascii=False,
        default=str,
    )
    iocs = extract_iocs(raw_content, _allowlist())
    stages["extraction_sanitization"] = _stage()
    ioc_results = []
    failures: dict[str, int] = {}
    timeouts = 0
    for ioc in iocs:
        results = (
            enrichment.enrich(ioc)
            if settings.enrich_public_iocs
            else {source: {"status": "disabled"} for source in ("virustotal", "abuseipdb", "otx")}
        )
        for source, result in results.items():
            if result.get("status") == "error":
                failures[source] = failures.get(source, 0) + 1
                if result.get("error") == "timeout":
                    timeouts += 1
        ioc_results.append({"ioc": ioc, "enrichment": results, "score": score_ioc(results)})
    stages["enrichment_scoring"] = _stage()
    overall = score_alert(ioc_results)

    source_id = str(payload.get("id", "missing-id"))[:256]
    alert_id = safe_alert_id(
        f"{source_id}:{payload.get('timestamp', '')}:{payload.get('rule', {})}"
    )
    description = (
        f"Score: {overall['score']}\nIOC count: {len(iocs)}\n"
        f"Scored: {overall['scored_ioc_count']}\n"
        f"Source coverage: {', '.join(overall['coverage']) or 'none'}\n"
        f"API errors: {failures}\n\nSynthetic lab automation. Approval required before response."
    )
    hive = thehive.create_alert(
        alert_id,
        str(rule.get("description", "Wazuh alert")),
        description,
        overall,
        iocs,
        severity(overall["score"]),
    )
    stages["thehive"] = _stage()
    expiry = int(time.time()) + APPROVAL_TTL
    approvals[alert_id] = {
        "expires": expiry,
        "status": "pending",
        "iocs": iocs,
        "score": overall,
        "source_ref": alert_id,
    }
    notification = notifier.send(
        alert_id, str(rule.get("description", "Wazuh alert")), overall, hive
    )
    stages["notification"] = _stage()
    audit.write(
        {
            "event": "alert_processed",
            "alert_id": alert_id,
            "level": level,
            "ioc_count": len(iocs),
            "score": overall,
            "api_failures": failures,
            "api_timeouts": timeouts,
            "thehive_status": hive.get("status"),
            "notification": notification,
            "stages": stages,
        }
    )
    return jsonify(
        {
            "status": "processed",
            "alert_id": alert_id,
            "score": overall,
            "iocs": ioc_results,
            "thehive": hive,
            "api_failures": failures,
            "api_timeouts": timeouts,
            "approval_expires": expiry,
            "stages": stages,
        }
    ), 200


def _decide(alert_id: str, decision: str, actor: str):
    item = approvals.get(alert_id)
    if not item:
        return jsonify({"error": "unknown or expired approval"}), 404
    if item["expires"] < int(time.time()):
        item["status"] = "expired"
        audit.write(
            {
                "event": "approval_expired",
                "alert_id": alert_id,
                "decision": "expired",
                "response_actions": [],
            }
        )
        return jsonify({"error": "approval expired"}), 410
    if item["status"] != "pending":
        return jsonify({"error": "approval already decided"}), 409
    item["status"] = decision
    executed = []
    if decision == "approve":
        # Only public IP observables are eligible for this demo action.
        targets = [ioc["value"] for ioc in item["iocs"] if ioc["type"] == "ip"]
        for target in targets:
            executed.append(response_action.execute("block_ip", target))
    audit.write(
        {
            "event": "human_decision",
            "alert_id": alert_id,
            "decision": decision,
            "actor": actor[:128],
            "approved_at": datetime.now(UTC).isoformat(),
            "response_actions": executed,
            "dry_run": settings.dry_run,
        }
    )
    return jsonify({"status": decision, "response_actions": executed})


@app.post("/approval/<alert_id>")
def approval(alert_id: str):
    if not _authorized():
        return jsonify({"error": "unauthorized"}), 401
    payload = request.get_json(silent=True) or {}
    decision = payload.get("decision")
    if decision not in {"approve", "reject"}:
        return jsonify({"error": "decision must be approve or reject"}), 400
    return _decide(alert_id, decision, str(payload.get("actor", "manual-operator")))


@app.post("/approval/slack")
def slack_approval():
    if not settings.slack_signing_secret:
        return jsonify({"error": "Slack signatures are not configured"}), 503
    timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
    if not timestamp.isdigit() or abs(time.time() - int(timestamp)) > 300:
        return jsonify({"error": "stale request"}), 401
    base = b"v0:" + timestamp.encode() + b":" + request.get_data()
    expected = (
        "v0=" + hmac.new(settings.slack_signing_secret.encode(), base, hashlib.sha256).hexdigest()
    )
    if not hmac.compare_digest(expected, request.headers.get("X-Slack-Signature", "")):
        return jsonify({"error": "invalid signature"}), 401
    form = request.form.get("payload", "{}")
    try:
        payload = json.loads(form)
        action = payload["actions"][0]
        actor = payload.get("user", {}).get("username") or payload.get("user", {}).get(
            "id", "slack-user"
        )
        return _decide(action["value"], action["action_id"], actor)
    except (ValueError, KeyError, IndexError, TypeError):
        return jsonify({"error": "invalid interaction payload"}), 400


@app.post("/approval/telegram")
def telegram_approval():
    expected = settings.telegram_webhook_secret
    actual = request.headers.get("X-Telegram-Bot-Api-Secret-Token", "")
    if not expected or not hmac.compare_digest(actual, expected):
        return jsonify({"error": "invalid webhook secret"}), 401
    payload = request.get_json(silent=True) or {}
    callback = payload.get("callback_query", {})
    try:
        callback_id = str(callback["id"])
        action, alert_id = callback["data"].split(":", 1)
        actor = str(callback.get("from", {}).get("username") or callback.get("from", {}).get("id"))
        result = _decide(alert_id, action, actor)
        result_body = result.get_json() or {}
        notifier.answer_telegram_callback(callback_id, result_body.get("status", "Recorded"))
        return result
    except (ValueError, KeyError, TypeError):
        return jsonify({"error": "invalid callback"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
