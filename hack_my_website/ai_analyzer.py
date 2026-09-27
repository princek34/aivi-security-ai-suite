"""
Hack My Website - AI Security Analyst Engine
Leverages LLM reasoning (Google Gemini) to:
1. Synthesize raw scan results into an executive security debrief
2. Analyze contextual exploitability based on observed technology stack
3. Generate concrete copy-paste remediation configurations (Nginx, FastAPI, Express)
"""

import os
import json
import logging
from typing import List, Optional
from .models import Finding, SecurityHeaderCheck, SecurityAuditReport

logger = logging.getLogger("HackMyWebsite.AIAnalyzer")

try:
    import google.generativeai as genai
except ImportError:
    genai = None


class AIVulnerabilityAnalyzer:
    """AI security auditor powered by Gemini with offline deterministic fallback."""

    @classmethod
    def generate_executive_summary(
        cls,
        target_url: str,
        score: int,
        grade: str,
        findings: List[Finding],
        headers: List[SecurityHeaderCheck],
        api_key: Optional[str] = None
    ) -> str:
        """
        Generates an executive risk debrief using Gemini or heuristic template.
        """
        resolved_key = api_key or os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")

        if resolved_key and genai is not None:
            try:
                genai.configure(api_key=resolved_key)
                model = genai.GenerativeModel("gemini-1.5-flash")

                findings_summary = [
                    {"id": f.id, "title": f.title, "severity": f.severity.value, "category": f.category.value}
                    for f in findings
                ]

                prompt = f"""You are a Principal Application Security Auditor.
Analyze the following automated web security scan results for target: {target_url}
Security Score: {score}/100 (Grade: {grade})
Total Findings: {len(findings)}
Findings: {json.dumps(findings_summary, indent=2)}

Provide a concise, highly professional executive summary (2-3 paragraphs) explaining:
1. The overall security posture and risk to business operations.
2. The most critical attack vectors exposed (e.g., lack of CSP, HSTS, or credentialed CORS).
3. Immediate prioritized remediation steps for engineering leadership.
Write in clear, authoritative technical language."""

                response = model.generate_content(prompt)
                if response.text:
                    return response.text.strip()
            except Exception as e:
                logger.warning(f"AI generation failed ({e}). Reverting to deterministic summary.")

        # Offline deterministic executive summary
        critical_count = sum(1 for f in findings if f.severity.value == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity.value == "HIGH")

        if score >= 85:
            posture = "strong security posture with robust defense-in-depth controls."
        elif score >= 65:
            posture = "moderate security posture with identifiable gaps in defense-in-depth headers."
        else:
            posture = "severely degraded security posture presenting immediate vulnerability to client-side attacks."

        summary = (
            f"Security audit for {target_url} completed with an overall score of {score}/100 (Grade: {grade}). "
            f"The application demonstrates a {posture} A total of {len(findings)} finding(s) were recorded, "
            f"including {critical_count} critical and {high_count} high-severity issues.\n\n"
            f"Key risk areas include missing defense-in-depth HTTP headers such as Content-Security-Policy (CSP) and "
            f"Strict-Transport-Security (HSTS), leaving client browsers vulnerable to content injection and protocol downgrade. "
            f"Immediate remediation should focus on applying strict header policies at the ingress/reverse proxy layer."
        )
        return summary
