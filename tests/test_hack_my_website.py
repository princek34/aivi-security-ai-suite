"""
Unit Tests for Hack My Website Security Scanner
"""

from hack_my_website.models import (
    SeverityLevel,
    VulnerabilityCategory,
    Finding,
    SecurityHeaderCheck,
    SecurityAuditReport
)
from hack_my_website.scanner import SecurityScanner
from hack_my_website.reporter import AuditReporter


def test_score_and_grade_calculation():
    # Test high score (A+)
    score_clean, grade_clean = SecurityScanner.calculate_score_and_grade([])
    assert score_clean == 100
    assert grade_clean == "A+"

    # Test penalty calculation with critical finding
    critical_finding = Finding(
        id="TEST-001",
        title="Critical Vulnerability",
        severity=SeverityLevel.CRITICAL,
        category=VulnerabilityCategory.CORS_MISCONFIG,
        description="Arbitrary origin reflection.",
        evidence="Origin: *",
        remediation="Restrict origin whitelist.",
        cvss_score=9.5
    )
    score_crit, grade_crit = SecurityScanner.calculate_score_and_grade([critical_finding])
    assert score_crit == 65
    assert grade_crit == "C"


def test_reporter_markdown_generation():
    report = SecurityAuditReport(
        target_url="https://test.local",
        scan_timestamp="2026-09-27T12:00:00Z",
        security_score=85,
        grade="A",
        total_findings=1,
        critical_count=0,
        high_count=0,
        medium_count=1,
        low_count=0,
        findings=[
            Finding(
                id="HDR-001",
                title="Missing X-Frame-Options",
                severity=SeverityLevel.MEDIUM,
                category=VulnerabilityCategory.SECURITY_HEADERS,
                description="Clickjacking protection missing.",
                evidence="None",
                remediation="Add X-Frame-Options: DENY",
                cvss_score=5.4
            )
        ],
        headers_analyzed=[
            SecurityHeaderCheck(
                header="X-Frame-Options",
                present=False,
                status="FAIL",
                recommendation="Add X-Frame-Options: DENY"
            )
        ],
        executive_summary="Target has good baseline posture."
    )

    md = AuditReporter.to_markdown(report)
    assert "# Web Application Security Audit Report" in md
    assert "https://test.local" in md
    assert "Missing X-Frame-Options" in md

    json_str = AuditReporter.to_json(report)
    assert '"security_score": 85' in json_str
    assert '"grade": "A"' in json_str
