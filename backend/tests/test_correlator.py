import pytest
from app.workers.scanners.correlator import (
    correlate_findings,
    _normalize_topic,
    _calculate_confidence,
)


class TestNormalizeTopic:
    def test_removes_tool_prefix(self):
        assert _normalize_topic("[Nuclei] XSS Vulnerability") == "xss vulnerability"

    def test_lowercases(self):
        assert _normalize_topic("Missing CSP Header") == "missing csp header"

    def test_removes_version(self):
        assert _normalize_topic("Apache 2.4.41 Detected") == "apache  detected"


class TestCalculateConfidence:
    def test_single_source_low_confidence(self):
        findings = [{"tool_name": "header_scanner", "cvss_score": None}]
        conf = _calculate_confidence(findings)
        assert conf < 0.7

    def test_dual_source_high_confidence(self):
        findings = [
            {"tool_name": "nmap", "cvss_score": 7.5},
            {"tool_name": "nuclei", "cvss_score": 7.2},
        ]
        conf = _calculate_confidence(findings)
        assert conf >= 0.7


class TestCorrelateFindings:
    def test_empty_findings(self):
        assert correlate_findings([]) == []

    def test_single_source_suspicious(self):
        raw = [
            {
                "title": "Suspicious Alert",
                "severity": "high",
                "category": "Test",
                "description": "test",
                "impact": "test",
                "remediation": "test",
                "tool_name": "internal",
            }
        ]
        result = correlate_findings(raw)
        assert len(result) == 1
        assert result[0]["correlation_status"] == "suspicious"

    def test_preserves_high_confidence(self):
        raw = [
            {
                "title": "SQL Injection Detected",
                "severity": "critical",
                "category": "Injection",
                "description": "test",
                "impact": "test",
                "remediation": "test",
                "tool_name": "nmap",
                "cvss_score": 9.8,
            },
            {
                "title": "SQL Injection Detected",
                "severity": "critical",
                "category": "Injection",
                "description": "test",
                "impact": "test",
                "remediation": "test",
                "tool_name": "sqlmap",
                "cvss_score": 9.8,
            },
        ]
        result = correlate_findings(raw)
        assert len(result) >= 1
        assert result[0]["confidence"] >= 0.7
        assert result[0]["correlation_status"] == "confirmed"
