"""
AIVI Campus OS - Command Line Interface (CLI)
Provides an interactive or file-based terminal interface for evaluating resumes.
"""

import sys
import json
import logging
from .matcher import evaluate_resume

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


def run_cli_demo():
    print("=" * 80)
    print("AIVI CAMPUS OS - PLACEMENT MATCHING ENGINE (CLI)")
    print("=" * 80)

    sample_jd = """
Role: Senior Cloud & Backend Engineer
Requirements:
- 4+ years building distributed backend services with Python, Go, or Java.
- Strong proficiency in PostgreSQL database modeling and query optimization.
- Hands-on experience with Docker, Kubernetes, and Helm charts.
- Deep familiarity with AWS services (EKS, RDS, S3, IAM).
- Solid grasp of CI/CD pipelines (GitHub Actions, ArgoCD) and automated testing.
"""

    sample_resume = """
Priya Sharma
Senior Software Engineer - 4.5 Years Experience
Technical Skills: Python, Go, PostgreSQL, Redis, Docker, Kubernetes, AWS (EKS, RDS, S3), GitHub Actions.
Experience:
- Architected high-volume payment processing microservices using Python (FastAPI) and PostgreSQL, handling 12,000 requests/minute.
- Managed Kubernetes deployments on AWS EKS using Helm and established CI/CD pipelines with GitHub Actions.
- Mentored 4 junior engineers on distributed data consistency and unit testing best practices.
"""

    print("\nEvaluating Sample Candidate...")
    result, prep = evaluate_resume(sample_resume, sample_jd)

    print("\n--- PREPROCESSING REPORT ---")
    print(f"Character Count  : {prep.character_count}")
    print(f"Legibility Grade : {prep.legibility_status.value}")
    print(f"Injection Risk   : {prep.injection_risk.value}")

    print("\n--- EVALUATION RESULT ---")
    print(f"Match Score   : {result.match_score}/100")
    print(f"Top Strengths : {result.top_strengths}")
    print(f"Missing Skills: {result.missing_skills}")
    print(f"Summary       : {result.summary}")
    print("\nJSON Output:")
    print(json.dumps(result.model_dump(), indent=2))


if __name__ == "__main__":
    run_cli_demo()
