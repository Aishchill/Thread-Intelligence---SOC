"""Risk scoring and SOC triage recommendation module."""
from __future__ import annotations
from typing import Any, Dict

def classify_score(score: int) -> str:
    score = max(0, min(score, 100))
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"

def recommendation(severity: str, ioc_type: str) -> str:
    if severity == "Critical":
        return (
            "Immediately escalate to L2/SOC lead. Validate affected assets, "
            "investigate related events, and consider containment according "
            "to incident-response procedures."
        )
    if severity == "High":
        return (
            "Prioritize investigation. Correlate the IOC with authentication, "
            "endpoint, DNS and network telemetry."
        )
    if severity == "Medium":
        return (
            "Perform additional contextual investigation and correlate with "
            "surrounding log activity."
        )
    return (
        "No immediate escalation based on available TI. Continue monitoring "
        "and preserve relevant context."
    )

def parse_vt(vt_data: Dict[str, Any]) -> Dict[str, Any]:
    result = {
        "malicious": 0, "suspicious": 0, "undetected": 0,
        "total": 0, "ratio": "0/0", "country": None, "reputation": None,
    }
    if not isinstance(vt_data, dict):
        return result
    attributes = vt_data.get("data", {}).get("attributes", {})
    stats = attributes.get("last_analysis_stats", {})
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    undetected = int(stats.get("undetected", 0))
    total = (
        malicious + suspicious + undetected
        + int(stats.get("harmless", 0))
        + int(stats.get("timeout", 0))
        + int(stats.get("type-unsupported", 0))
    )
    result.update({
        "malicious": malicious,
        "suspicious": suspicious,
        "undetected": undetected,
        "total": total,
        "ratio": f"{malicious}/{total}" if total else "0/0",
        "country": attributes.get("country"),
        "reputation": attributes.get("reputation"),
    })
    return result

def parse_abuseipdb(abuse_data: Dict[str, Any]) -> Dict[str, Any]:
    result = {
        "confidence_score": 0, "country": None, "isp": None,
        "domain": None, "usage_type": None,
    }
    if not isinstance(abuse_data, dict):
        return result
    data = abuse_data.get("data", {})
    result.update({
        "confidence_score": int(data.get("abuseConfidenceScore", 0)),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "usage_type": data.get("usageType"),
    })
    return result

def calculate_risk(enrichment: Dict[str, Any]) -> Dict[str, Any]:
    ioc_type = enrichment.get("type", "unknown")
    vt = parse_vt(enrichment.get("virustotal", {}))
    abuse = parse_abuseipdb(enrichment.get("abuseipdb", {}))
    score = 0

    abuse_score = abuse["confidence_score"]
    if abuse_score >= 90:
        score += 50
    elif abuse_score >= 75:
        score += 40
    elif abuse_score >= 50:
        score += 25
    elif abuse_score >= 25:
        score += 10

    malicious = vt["malicious"]
    if malicious >= 10:
        score += 50
    elif malicious >= 5:
        score += 40
    elif malicious >= 3:
        score += 30
    elif malicious >= 1:
        score += 20

    score += min(vt["suspicious"] * 3, 10)
    score = min(score, 100)
    severity = classify_score(score)

    return {
        "risk_score": score,
        "severity": severity,
        "geolocation": abuse.get("country") or vt.get("country"),
        "abuse_score": abuse_score,
        "vt_malicious": malicious,
        "vt_total": vt["total"],
        "vt_ratio": vt["ratio"],
        "recommendation": recommendation(severity, ioc_type),
    }
