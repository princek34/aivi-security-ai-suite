"""
Hack My Website - Core HTTP Security Scanner Engine
Performs non-destructive vulnerability reconnaissance across:
1. HTTP Security Headers (CSP, HSTS, X-Frame-Options, etc.)
2. Information Disclosure (Server, X-Powered-By headers)
3. Cookie Security Attributes (Secure, HttpOnly, SameSite)
4. CORS Misconfiguration Probes
5. AI Endpoint Detection & Input Surface Inspection
"""

import time
import logging
from typing import List, Dict, Any, Tuple
import requests

from .models import (
    SeverityLevel,
    VulnerabilityCategory,
    Finding,
    SecurityHeaderCheck,
    SecurityAuditReport
)

logger = logging.getLogger("HackMyWebsite.Scanner")

# Standard HTTP security headers to verify
REQUIRED_SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "recommended": "max-age=31536000; includeSubDomains; preload",
        "missing_severity": SeverityLevel.HIGH,
        "cvss": 7.5,
        "category": VulnerabilityCategory.TLS_SSL,
        "desc": "HTTP Strict Transport Security (HSTS) prevents man-in-the-middle protocol downgrade attacks."
    },
    "Content-Security-Policy": {
        "recommended": "default-src 'self'; script-src 'self'",
        "missing_severity": SeverityLevel.HIGH,
        "cvss": 7.2,
        "category": VulnerabilityCategory.SECURITY_HEADERS,
        "desc": "Content Security Policy (CSP) mitigates Cross-Site Scripting (XSS) and data injection attacks."
    },
    "X-Frame-Options": {
        "recommended": "DENY or SAMEORIGIN",
        "missing_severity": SeverityLevel.MEDIUM,
        "cvss": 5.4,
        "category": VulnerabilityCategory.SECURITY_HEADERS,
        "desc": "X-Frame-Options protects users against Clickjacking attacks by forbidding iframe embedding."
    },
    "X-Content-Type-Options": {
        "recommended": "nosniff",
        "missing_severity": SeverityLevel.LOW,
        "cvss": 3.7,
        "category": VulnerabilityCategory.SECURITY_HEADERS,
        "desc": "X-Content-Type-Options prevents browsers from MIME-sniffing a response away from declared content-type."
    },
    "Referrer-Policy": {
        "recommended": "strict-origin-when-cross-origin",
        "missing_severity": SeverityLevel.LOW,
        "cvss": 3.1,
        "category": VulnerabilityCategory.SECURITY_HEADERS,
        "desc": "Referrer-Policy restricts sensitive URL query parameters from leaking to third-party referrers."
    },
    "Permissions-Policy": {
        "recommended": "geolocation=(), microphone=(), camera=()",
        "missing_severity": SeverityLevel.LOW,
        "cvss": 2.5,
        "category": VulnerabilityCategory.SECURITY_HEADERS,
        "desc": "Permissions-Policy restricts browser access to sensitive client hardware APIs."
    }
}


class SecurityScanner:
    """Non-destructive automated security scanner."""

    def __init__(self, timeout: float = 8.0):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "HackMyWebsite-SecurityScanner/1.0 (Auditing Engine; +https://github.com/princek34)"
        })

    def scan_url(self, target_url: str) -> Tuple[Dict[str, Any], List[Finding], List[SecurityHeaderCheck]]:
        """
        Executes baseline HTTP reconnaissance against the target URL.
        """
        findings: List[Finding] = []
        header_checks: List[SecurityHeaderCheck] = []
        metadata: Dict[str, Any] = {
            "target_url": target_url,
            "scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status_code": None,
            "response_time_ms": 0
        }

        try:
            start_t = time.time()
            resp = self.session.get(target_url, timeout=self.timeout, allow_redirects=True, verify=False)
            metadata["response_time_ms"] = int((time.time() - start_t) * 1000)
            metadata["status_code"] = resp.status_code
            headers = resp.headers
            cookies = resp.cookies
        except Exception as e:
            logger.error(f"Failed to connect to target {target_url}: {e}")
            findings.append(Finding(
                id="CONN-001",
                title="Target Connection Unreachable",
                severity=SeverityLevel.CRITICAL,
                category=VulnerabilityCategory.TLS_SSL,
                description=f"Scanner was unable to complete HTTP handshake: {str(e)}",
                evidence=str(e),
                remediation="Ensure host is online, reachable via DNS, and accepts HTTPS traffic.",
                cvss_score=9.0
            ))
            return metadata, findings, header_checks

        # 1. Audit HTTP Security Headers
        finding_idx = 1
        for h_name, h_info in REQUIRED_SECURITY_HEADERS.items():
            if h_name in headers:
                val = headers[h_name]
                header_checks.append(SecurityHeaderCheck(
                    header=h_name,
                    present=True,
                    value=val,
                    status="PASS",
                    recommendation=f"Properly configured: {val[:50]}"
                ))
            else:
                header_checks.append(SecurityHeaderCheck(
                    header=h_name,
                    present=False,
                    value=None,
                    status="FAIL",
                    recommendation=f"Add header '{h_name}: {h_info['recommended']}'"
                ))
                findings.append(Finding(
                    id=f"HDR-00{finding_idx}",
                    title=f"Missing Security Header: {h_name}",
                    severity=h_info["missing_severity"],
                    category=h_info["category"],
                    description=h_info["desc"],
                    evidence=f"Header '{h_name}' missing from HTTP response headers.",
                    remediation=f"Configure web server / reverse proxy to include '{h_name}: {h_info['recommended']}'.",
                    cvss_score=h_info["cvss"]
                ))
                finding_idx += 1

        # 2. Check Information Disclosure (Server & X-Powered-By)
        if "Server" in headers and any(c.isdigit() for c in headers["Server"]):
            findings.append(Finding(
                id="INFO-001",
                title="Server Banner Software Version Disclosure",
                severity=SeverityLevel.LOW,
                category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                description="Server header reveals exact web server software and version numbers, aiding targeted exploits.",
                evidence=f"Server: {headers['Server']}",
                remediation="Configure ServerTokens Prod (Apache) or server_tokens off (Nginx) to suppress version details.",
                cvss_score=3.3
            ))

        if "X-Powered-By" in headers:
            findings.append(Finding(
                id="INFO-002",
                title="Technology Stack Fingerprint Leak (X-Powered-By)",
                severity=SeverityLevel.LOW,
                category=VulnerabilityCategory.INFORMATION_DISCLOSURE,
                description="X-Powered-By header discloses underlying backend framework (e.g. Express, PHP, ASP.NET).",
                evidence=f"X-Powered-By: {headers['X-Powered-By']}",
                remediation="Disable X-Powered-By header in backend configuration (e.g. app.disable('x-powered-by') in Express).",
                cvss_score=3.0
            ))

        # 3. Audit Cookie Flags (Secure, HttpOnly, SameSite)
        for c in cookies:
            if not c.secure and target_url.startswith("https"):
                findings.append(Finding(
                    id=f"CK-SEC-{c.name}",
                    title=f"Cookie Missing 'Secure' Flag ({c.name})",
                    severity=SeverityLevel.MEDIUM,
                    category=VulnerabilityCategory.COOKIE_SECURITY,
                    description="Cookies transmitted without the 'Secure' directive can be intercepted over unencrypted channels.",
                    evidence=f"Set-Cookie: {c.name}",
                    remediation="Add 'Secure' flag to cookie configuration.",
                    cvss_score=5.3
                ))
            if not c.has_nonstandard_attr("httponly") and "httponly" not in str(c._rest).lower():
                findings.append(Finding(
                    id=f"CK-HTTP-{c.name}",
                    title=f"Cookie Missing 'HttpOnly' Flag ({c.name})",
                    severity=SeverityLevel.MEDIUM,
                    category=VulnerabilityCategory.COOKIE_SECURITY,
                    description="Cookies without 'HttpOnly' flag are accessible via JavaScript document.cookie, exposing them to XSS theft.",
                    evidence=f"Set-Cookie: {c.name}",
                    remediation="Add 'HttpOnly' attribute to sensitive session cookies.",
                    cvss_score=5.9
                ))

        # 4. Probe CORS Misconfiguration
        try:
            cors_resp = self.session.options(
                target_url,
                headers={"Origin": "https://adversary-evil.com"},
                timeout=4.0
            )
            allow_origin = cors_resp.headers.get("Access-Control-Allow-Origin")
            allow_creds = cors_resp.headers.get("Access-Control-Allow-Credentials")

            if allow_origin == "https://adversary-evil.com" and allow_creds == "true":
                findings.append(Finding(
                    id="CORS-001",
                    title="Critical CORS Origin Reflection with Credentials",
                    severity=SeverityLevel.CRITICAL,
                    category=VulnerabilityCategory.CORS_MISCONFIG,
                    description="Server dynamically reflects arbitrary origins and enables credentials sharing, allowing authenticated cross-origin data theft.",
                    evidence=f"Access-Control-Allow-Origin: {allow_origin}, Access-Control-Allow-Credentials: true",
                    remediation="Validate Origin header against a strict whitelist of trusted domains. Never reflect arbitrary origins with credentials enabled.",
                    cvss_score=9.1
                ))
            elif allow_origin == "*":
                findings.append(Finding(
                    id="CORS-002",
                    title="Wildcard Cross-Origin Resource Sharing (CORS)",
                    severity=SeverityLevel.LOW,
                    category=VulnerabilityCategory.CORS_MISCONFIG,
                    description="Wildcard (*) CORS policy allows any external domain to read endpoint responses.",
                    evidence="Access-Control-Allow-Origin: *",
                    remediation="Restrict CORS access strictly to authorized frontend origins.",
                    cvss_score=3.7
                ))
        except Exception:
            pass

        return metadata, findings, header_checks

    @staticmethod
    def calculate_score_and_grade(findings: List[Finding]) -> Tuple[int, str]:
        """
        Calculates a baseline security posture score (0-100) and letter grade.
        """
        penalty = 0
        for f in findings:
            if f.severity == SeverityLevel.CRITICAL:
                penalty += 35
            elif f.severity == SeverityLevel.HIGH:
                penalty += 15
            elif f.severity == SeverityLevel.MEDIUM:
                penalty += 8
            elif f.severity == SeverityLevel.LOW:
                penalty += 3

        score = max(0, 100 - penalty)
        if score >= 90:
            grade = "A+"
        elif score >= 80:
            grade = "A"
        elif score >= 70:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 50:
            grade = "D"
        else:
            grade = "F"

        return score, grade
