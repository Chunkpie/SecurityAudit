import pytest
from app.workers.orchestrator import ScanOrchestrator


class TestScoring:
    def test_perfect_score_no_findings(self):
        orchestrator = ScanOrchestrator("https://example.com")
        orchestrator.findings = []
        score = orchestrator._calculate_score()
        assert score == 100.0

    def test_critical_finding_deducts_20(self):
        orchestrator = ScanOrchestrator("https://example.com")
        orchestrator.findings = [{"severity": "critical"}]
        score = orchestrator._calculate_score()
        assert score == 80.0

    def test_multiple_critical_capped_at_60(self):
        orchestrator = ScanOrchestrator("https://example.com")
        orchestrator.findings = [{"severity": "critical"} for _ in range(5)]
        score = orchestrator._calculate_score()
        assert score == 40.0  # 100 - min(5*20, 60) = 100 - 60

    def test_mixed_severities(self):
        orchestrator = ScanOrchestrator("https://example.com")
        orchestrator.findings = [
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
        ]
        score = orchestrator._calculate_score()
        assert score == 100 - 10 - 5 - 2

    def test_score_never_negative(self):
        orchestrator = ScanOrchestrator("https://example.com")
        orchestrator.findings = [{"severity": "critical"} for _ in range(20)]
        score = orchestrator._calculate_score()
        assert score >= 0.0


class TestVerdict:
    def test_no_go_on_critical(self):
        orchestrator = ScanOrchestrator("https://example.com")
        orchestrator.findings = [{"severity": "critical"}]
        verdict = orchestrator._determine_verdict(80.0)
        assert verdict == "NO_GO"

    def test_go_with_conditions_on_many_high(self):
        orchestrator = ScanOrchestrator("https://example.com")
        orchestrator.findings = [{"severity": "high"} for _ in range(4)]
        verdict = orchestrator._determine_verdict(75.0)
        assert verdict == "GO_WITH_CONDITIONS"

    def test_go_on_clean_scan(self):
        orchestrator = ScanOrchestrator("https://example.com")
        orchestrator.findings = [{"severity": "low"}]
        verdict = orchestrator._determine_verdict(95.0)
        assert verdict == "GO"

    def test_no_go_on_low_score(self):
        orchestrator = ScanOrchestrator("https://example.com")
        orchestrator.findings = []
        verdict = orchestrator._determine_verdict(45.0)
        assert verdict == "NO_GO"


class TestDomainExtraction:
    def test_extracts_domain_from_url(self):
        orchestrator = ScanOrchestrator("https://example.com/path?query=1")
        assert orchestrator.domain == "example.com"

    def test_extracts_domain_with_port(self):
        orchestrator = ScanOrchestrator("https://example.com:8443/path")
        assert orchestrator.domain == "example.com"
