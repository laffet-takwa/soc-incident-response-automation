import json
from types import SimpleNamespace

from soc_automation import api


def test_threshold_and_approval_reject_never_executes(monkeypatch, tmp_path):
    monkeypatch.setattr(
        api,
        "settings",
        SimpleNamespace(
            api_token="t", min_rule_level=7, audit_path=str(tmp_path / "audit.jsonl"), dry_run=True
        ),
    )
    monkeypatch.setattr(api, "audit", api.AuditLog(str(tmp_path / "audit.jsonl")))
    client = api.app.test_client()
    headers = {"Authorization": "Bearer t"}
    low = client.post("/webhook/wazuh", json={"rule": {"level": 2}}, headers=headers)
    assert low.status_code == 202

    api.approvals["pending-test"] = {
        "expires": 9999999999,
        "status": "pending",
        "iocs": [],
        "score": {},
    }
    reject = client.post(
        "/approval/pending-test", json={"decision": "reject", "actor": "analyst"}, headers=headers
    )
    assert reject.status_code == 200
    assert (
        json.loads((tmp_path / "audit.jsonl").read_text().splitlines()[-1])["decision"] == "reject"
    )
