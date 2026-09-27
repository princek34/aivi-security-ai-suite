"""
Hack My Website - AI Security Scanner Data Models
Pydantic v2 schemas for vulnerability findings, header security, and audit reports.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityCategory(str, Enum):
    SECURITY_HEADERS = "SECURITY_HEADERS"
    TLS_SSL = "TLS_SSL"
    COOKIE_SECURITY = "COOKIE_SECURITY"
    INJECTION_SURFACE = "INJECTION_SURFACE"
    CORS_MISCONFIG = "CORS_MISCONFIG"
    AI_PROMPT_INJECTION = "AI_PROMPT_INJECTION"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"


class Finding(BaseModel):
    """An individual security finding or vulnerability."""
    id: str = Field(..., description="Unique vulnerability identifier (e.g. SEC-001)")
    title: str = Field(..., description="Short descriptive vulnerability title")
    severity: SeverityLevel = Field(..., description="Risk severity rating")
    category: VulnerabilityCategory = Field(..., description="OWASP/CWE category classification")
    description: str = Field(..., description="Technical explanation of the flaw")
    evidence: str = Field(..., description="Raw observed evidence or HTTP header value")
    remediation: str = Field(..., description="Concrete actionable fix instructions")
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="Estimated CVSS v3.1 score")


class SecurityHeaderCheck(BaseModel):
    """Verification status for an essential HTTP security header."""
    header: str
    present: bool
    value: Optional[str] = None
    status: str  # PASS, FAIL, WARNING
    recommendation: str


class SecurityAuditReport(BaseModel):
    """Complete security assessment report for a target web application."""
    target_url: str
    scan_timestamp: str
    security_score: int = Field(..., ge=0, le=100, description="Overall security posture score (0-100)")
    grade: str = Field(..., description="Letter grade (A+, A, B, C, D, F)")
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[Finding]
    headers_analyzed: List[SecurityHeaderCheck]
    executive_summary: str
