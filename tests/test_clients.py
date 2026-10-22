from types import SimpleNamespace

from soc_automation.clients import Cache, EnrichmentClients, VTGate


class FakeResponse:
    status_code = 200
    headers = {}
    content = b"{}"

    def __init__(self, body):
        self.body = body

    def raise_for_status(self):
        pass

    def json(self):
        return self.body


class FakeSession:
    def get(self, url, **kwargs):
        if "virustotal" in url:
            return FakeResponse(
                {"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "harmless": 8}}}}
            )
        if "abuseipdb" in url:
            return FakeResponse({"data": {"abuseConfidenceScore": 72, "totalReports": 3}})
        return FakeResponse({"pulse_info": {"count": 2}})


def test_virustotal_client_normalizes_mock_response(tmp_path):
    config = SimpleNamespace(
        vt_api_key="x", abuseipdb_api_key="y", otx_api_key="z", request_timeout=1
    )
    clients = EnrichmentClients(config, Cache(str(tmp_path / "cache.sqlite")), FakeSession())
    VTGate.calls.clear()
    result = clients.virustotal({"type": "ip", "value": "8.8.8.8"})
    assert result["malicious_ratio"] == 0.2


def test_abuseipdb_only_scores_ip_and_otx_parses_pulses(tmp_path):
    config = SimpleNamespace(
        vt_api_key="x", abuseipdb_api_key="y", otx_api_key="z", request_timeout=1
    )
    clients = EnrichmentClients(config, Cache(str(tmp_path / "cache.sqlite")), FakeSession())
    assert (
        clients.abuseipdb({"type": "domain", "value": "example.net"})["status"] == "not_applicable"
    )
    assert clients.abuseipdb({"type": "ip", "value": "8.8.8.8"})["abuse_confidence_score"] == 72
    assert clients.otx({"type": "hash", "value": "a" * 64})["pulse_count"] == 2
