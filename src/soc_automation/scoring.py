"""Transparent, source-coverage-aware risk score (0-100)."""

WEIGHTS = {"virustotal": 0.50, "abuseipdb": 0.30, "otx": 0.20}


def score_ioc(results: dict[str, dict]) -> dict:
    """Weight available normalized signals; unavailable sources are omitted."""
    signals: dict[str, float] = {}
    vt = results.get("virustotal", {}).get("malicious_ratio")
    abuse = results.get("abuseipdb", {}).get("abuse_confidence_score")
    otx = results.get("otx", {}).get("pulse_count")
    if isinstance(vt, int | float) and 0 <= vt <= 1:
        signals["virustotal"] = float(vt) * 100
    if isinstance(abuse, int | float) and 0 <= abuse <= 100:
        signals["abuseipdb"] = float(abuse)
    if isinstance(otx, int | float) and otx >= 0:
        # A transparent logarithmic cap prevents raw community pulse volume dominating.
        signals["otx"] = min(100.0, 25.0 * otx)
    weight = sum(WEIGHTS[name] for name in signals)
    if not weight:
        return {"score": None, "coverage": [], "signals": signals, "unscored": True}
    score = sum(signals[name] * WEIGHTS[name] for name in signals) / weight
    return {
        "score": round(score, 2),
        "coverage": sorted(signals),
        "coverage_weight": round(weight, 2),
        "signals": signals,
        "unscored": False,
    }


def score_alert(ioc_results: list[dict]) -> dict:
    scores = [item["score"]["score"] for item in ioc_results if item["score"]["score"] is not None]
    coverage = sorted({source for item in ioc_results for source in item["score"]["coverage"]})
    return {
        "score": max(scores) if scores else None,
        "coverage": coverage,
        "ioc_count": len(ioc_results),
        "scored_ioc_count": len(scores),
        "unscored_ioc_count": len(ioc_results) - len(scores),
    }


def severity(score: float | None) -> int:
    """TheHive 5 severity mapping: 1 low, 2 medium, 3 high, 4 critical."""
    if score is None:
        return 1
    if score >= 90:
        return 4
    if score >= 70:
        return 3
    if score >= 40:
        return 2
    return 1
