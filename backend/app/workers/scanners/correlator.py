"""
Finding Correlator — reduces false positives by requiring multi-source evidence.
Sits between scanner output and scoring engine.
"""
import logging
import re
from collections import defaultdict
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

MIN_CONFIRMATION_SOURCES = 2

WEIGHT_EVIDENCE_SOURCES = 0.4
WEIGHT_CVSS_RELIABILITY = 0.3
WEIGHT_RESPONSE_CONSISTENCY = 0.2
WEIGHT_TOOL_REPUTATION = 0.1

TOOL_REPUTATION = {
    "nmap": 0.95,
    "nuclei": 0.85,
    "tls_scanner": 0.90,
    "ssl_scanner": 0.90,
    "header_scanner": 0.85,
    "exposure_scanner": 0.80,
    "injection_scanner": 0.75,
    "sqlmap": 0.90,
    "wpscan": 0.85,
    "whatweb": 0.70,
    "subfinder": 0.75,
    "gitleaks": 0.80,
    "trivy": 0.90,
    "zap": 0.80,
    "directory_scanner": 0.70,
    "internal": 0.50,
}

HIGH_CONFIDENCE_CATEGORIES = {"Server Hardening", "Security Headers"}


def correlate_findings(raw_findings: List[dict]) -> List[dict]:
    if not raw_findings:
        return []

    grouped = _group_by_topic(raw_findings)
    correlated = []

    for topic_key, findings_list in grouped.items():
        finding = _merge_findings(findings_list)
        confidence = _calculate_confidence(findings_list)
        finding["confidence"] = round(confidence, 2)

        if confidence >= 0.7:
            finding["correlation_status"] = "confirmed"
            correlated.append(finding)
        elif confidence >= 0.4:
            finding["correlation_status"] = "suspicious"
            correlated.append(finding)
        else:
            logger.debug(f"Dropped low-confidence finding: {topic_key} (confidence={confidence})")

    return correlated


def _group_by_topic(findings: List[dict]) -> Dict[str, List[dict]]:
    groups = defaultdict(list)
    for f in findings:
        key = _normalize_topic(f.get("title", ""))
        groups[key].append(f)
    return dict(groups)


def _normalize_topic(title: str) -> str:
    normalized = re.sub(r'^\[.*?\]\s*', '', title)
    normalized = normalized.lower().strip()
    normalized = re.sub(r'\bv?\d+\.\d+(\.\d+)?\b', '', normalized)
    return normalized.strip()


def _merge_findings(findings_list: List[dict]) -> dict:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(
        findings_list,
        key=lambda f: severity_order.get(f.get("severity", "info"), 5),
    )
    base = dict(sorted_findings[0])

    tools = list(dict.fromkeys(f.get("tool_name", "unknown") for f in findings_list))
    base["tool_name"] = "+".join(tools)

    base["evidence"] = {
        "sources": [
            {
                "tool": f.get("tool_name", "unknown"),
                "evidence": f.get("evidence", {}),
            }
            for f in findings_list
        ],
        "source_count": len(findings_list),
    }

    return base


def _calculate_confidence(findings_list: List[dict]) -> float:
    source_count = len(findings_list)
    source_score = min(source_count / MIN_CONFIRMATION_SOURCES, 1.0)

    cvss_scores = [f.get("cvss_score") for f in findings_list if f.get("cvss_score") is not None]
    if cvss_scores:
        cvss_score = 0.9
    else:
        cvss_score = 0.5

    consistency = min(len(findings_list) * 0.3, 1.0)

    reputations = [
        TOOL_REPUTATION.get(f.get("tool_name", "internal"), 0.5)
        for f in findings_list
    ]
    avg_reputation = sum(reputations) / len(reputations) if reputations else 0.5

    confidence = (
        source_score * WEIGHT_EVIDENCE_SOURCES
        + cvss_score * WEIGHT_CVSS_RELIABILITY
        + consistency * WEIGHT_RESPONSE_CONSISTENCY
        + avg_reputation * WEIGHT_TOOL_REPUTATION
    )

    return min(confidence, 1.0)
