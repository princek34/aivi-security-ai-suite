"""
Hack My Website - Command Line Interface (CLI)
Scans a target URL and produces a comprehensive security report.
"""

import sys
import argparse
import logging
from .scanner import SecurityScanner
from .ai_analyzer import AIVulnerabilityAnalyzer
from .reporter import AuditReporter
from .models import SecurityAuditReport

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def run_scan(target_url: str, output_format: str = "terminal", output_file: str = None):
    print(f"\n[*] Initiating Security Audit against: {target_url}")
    scanner = SecurityScanner()

    meta, findings, header_checks = scanner.scan_url(target_url)
    score, grade = scanner.calculate_score_and_grade(findings)

    print("[*] Generating AI Security Analysis & Executive Debrief...")
    summary = AIVulnerabilityAnalyzer.generate_executive_summary(
        target_url=target_url,
        score=score,
        grade=grade,
        findings=findings,
        headers=header_checks
    )

    report = SecurityAuditReport(
        target_url=target_url,
        scan_timestamp=meta["scan_timestamp"],
        security_score=score,
        grade=grade,
        total_findings=len(findings),
        critical_count=sum(1 for f in findings if f.severity.value == "CRITICAL"),
        high_count=sum(1 for f in findings if f.severity.value == "HIGH"),
        medium_count=sum(1 for f in findings if f.severity.value == "MEDIUM"),
        low_count=sum(1 for f in findings if f.severity.value == "LOW"),
        findings=findings,
        headers_analyzed=header_checks,
        executive_summary=summary
    )

    if output_format == "terminal":
        AuditReporter.print_terminal_summary(report)
    elif output_format == "markdown":
        content = AuditReporter.to_markdown(report)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] Markdown report saved to: {output_file}")
        else:
            print(content)
    elif output_format == "json":
        content = AuditReporter.to_json(report)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] JSON report saved to: {output_file}")
        else:
            print(content)


def main():
    parser = argparse.ArgumentParser(description="Hack My Website - Autonomous AI Security Scanner")
    parser.add_argument("url", nargs="?", default="https://example.com", help="Target URL to audit")
    parser.add_argument("--format", choices=["terminal", "markdown", "json"], default="terminal", help="Report format")
    parser.add_argument("--output", "-o", default=None, help="Output file path")

    args = parser.parse_args()
    run_scan(args.url, output_format=args.format, output_file=args.output)


if __name__ == "__main__":
    main()
