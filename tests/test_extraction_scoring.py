from soc_automation.extraction import extract_iocs
from soc_automation.scoring import score_alert, score_ioc, severity


def test_extracts_public_iocs_and_skips_private_allowlisted_values():
    got = extract_iocs(
        "8.8.8.8 10.0.0.1 evil.example.net https://indicator.net/a "
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        {"evil.example.net"},
    )
    values = {item["value"] for item in got}
    assert "8.8.8.8" in values
    assert "10.0.0.1" not in values
    assert "evil.example.net" not in values
    assert "https://indicator.net/a" in values

    protected = extract_iocs(
        "internal.corp.example.com https://portal.corp.example.com/login",
        {"*.corp.example.com"},
    )
    assert protected == []


def test_scoring_renormalizes_available_sources_and_keeps_failure_unknown():
    score = score_ioc(
        {
            "virustotal": {"malicious_ratio": 0.5},
            "abuseipdb": {"status": "error"},
            "otx": {"status": "disabled"},
        }
    )
    assert score["score"] == 50
    assert score["coverage"] == ["virustotal"]
    assert score_ioc({})["score"] is None
    assert severity(None) == 1
    assert score_alert([{"score": score}])["score"] == 50
