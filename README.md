# AIVI Campus OS & Hack My Website: AI Evaluation & Security Suite

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Pydantic v2](https://img.shields.io/badge/Pydantic-v2.11-green.svg)](https://docs.pydantic.dev/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.128-teal.svg)](https://fastapi.tiangolo.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub](https://img.shields.io/badge/GitHub-princek34-181717.svg?logo=github)](https://github.com/princek34)

A lightweight, enterprise-grade AI engineering repository auditing and implementing two flagship systems:
1. **AIVI Campus OS:** An AI resume-parsing and campus placement recommendation engine built with strict JSON-only schema guarantees, adversarial prompt-injection resistance, OCR legibility gating, and Hinglish multilingual normalization.
2. **Hack My Website:** An autonomous AI-powered web security scanner and vulnerability auditor performing non-destructive security header inspections, cookie policy audits, CORS misconfiguration probes, and AI-driven executive debriefs.

---

## Repository Structure

```text
aivi-security-ai-suite/
│
├── aivi_campus_os/                   # Project 1: AI Placement Engine
│   ├── __init__.py                   # Package exports
│   ├── models.py                     # Pydantic v2 schema models (ResumeMatchResult, etc.)
│   ├── preprocessor.py               # OCR density gate, injection scanner, Hinglish normalizer
│   ├── matcher.py                    # Core Gemini engine, prompt architecture & offline fallback
│   ├── api.py                        # FastAPI REST service (single, batch, scan endpoints)
│   └── cli.py                        # Standalone CLI evaluation tool
│
├── hack_my_website/                  # Project 2: AI Security Scanner
│   ├── __init__.py                   # Package exports
│   ├── models.py                     # Pydantic v2 schemas (Finding, AuditReport, Headers)
│   ├── scanner.py                    # HTTP reconnaissance, headers, cookies, CORS probes
│   ├── ai_analyzer.py                # Gemini-powered executive debrief & remediation adviser
│   ├── reporter.py                   # Formatted Markdown, JSON, and Terminal reporters
│   └── cli.py                        # Scanner CLI interface
│
├── reports/                          # Audit Deliverables & Documentation
│   ├── DELIVERABLE_1_ADVERSARIAL_STRESS_TEST.md    # Detailed audit report on 3 edge cases
│   └── DELIVERABLE_2_SYSTEM_PROMPT_ARCHITECTURE.md # System prompt & fallback architecture
│
├── tests/                            # Automated Pytest Suite
│   ├── __init__.py
│   ├── test_aivi_campus.py           # Unit tests for matching, sanitizing, and guardrails
│   └── test_hack_my_website.py       # Unit tests for scoring, findings, and reporting
│
├── run_suite.py                      # Interactive master CLI runner
├── requirements.txt                  # Minimal, lightweight dependencies
├── .gitignore                        # Git exclusion rules
└── README.md                         # Complete project documentation
```

---

## Key Engineering Features

### 1. AIVI Campus OS (Placement Engine)
* **Pydantic v2 Guaranteed Schemas:** Enforces strict typed JSON output (`match_score: int 0-100`, `top_strengths: list[str] max 5`, `missing_skills: list[str] max 5`, `summary: str exactly 2 sentences`).
* **Adversarial Prompt Injection Defense:** Employs control-plane vs data-plane isolation with structural `<untrusted_candidate_resume>` tags and pre-LLM heuristic detection.
* **OCR Legibility Gating:** Identifies zero-text scanned PDFs and corrupted byte streams before LLM invocation, preventing silent context-void hallucinations.
* **Hinglish Multilingual Normalization:** Canonicalizes Romanized Hindi code-switching and campus tech jargon (`"Paython"`, `"Reddis"`, `"K8s"`, `"kaam kiya"`) into standard technical English.
* **Rate-Limit & Timeout Resilience:** Full jitter exponential backoff on HTTP 429 and token-compressed retries on timeouts with structured degradation.
* **Offline Deterministic Fallback:** Runs locally with high accuracy even without a Gemini API key.

### 2. Hack My Website (AI Security Scanner)
* **Non-Destructive HTTP Reconnaissance:** Audits critical security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
* **Cookie & Session Hygiene:** Scans for `Secure`, `HttpOnly`, and `SameSite` compliance on session identifiers.
* **CORS Attack Surface Verification:** Probes origin reflection and credential exposure risks.
* **AI-Assisted Executive Debrief:** Leverages Google Gemini to synthesize findings into actionable executive debriefs with concrete remediation configurations.
* **Multi-Format Reporting:** Generates Markdown reports, JSON deliverables, or ANSI terminal dashboards.

---

## Quickstart & Installation

### 1. Clone & Set Up Environment
```bash
# Clone the repository
git clone https://github.com/princek34/aivi-security-ai-suite.git
cd aivi-security-ai-suite

# Install lightweight dependencies
pip install -r requirements.txt
```

### 2. Optional: Configure Gemini API Key
To enable live LLM evaluation with Google Gemini, set your API key (if omitted, the system seamlessly uses its deterministic offline engine):
```bash
# PowerShell
$env:GEMINI_API_KEY="your-api-key-here"

# Linux / macOS
export GEMINI_API_KEY="your-api-key-here"
```

---

## Running the Applications

### 1. Interactive Master Launcher
Run the unified menu to launch demos, run scans, or execute tests:
```bash
python run_suite.py
```

Or pass direct command shortcuts:
```bash
python run_suite.py aivi   # Run AIVI Campus OS demo on 4 stress cases
python run_suite.py scan   # Run Hack My Website security scanner
python run_suite.py test   # Run full automated test suite
python run_suite.py api    # Launch FastAPI REST API server
```

### 2. Run AIVI Campus OS (FastAPI REST Service)
Start the REST API server:
```bash
uvicorn aivi_campus_os.api:app --reload
```
Interactive API docs (Swagger UI) will be live at: **`http://127.0.0.1:8000/docs`**

#### Example API Request (cURL):
```bash
curl -X POST "http://127.0.0.1:8000/evaluate" \
     -H "Content-Type: application/json" \
     -d '{
       "candidate": {
         "candidate_id": "cand_101",
         "name": "Priya Sharma",
         "resume_text": "Experienced Python and FastAPI backend developer with Docker and PostgreSQL expertise."
       },
       "job_description": {
         "job_id": "job_001",
         "title": "Backend Engineer",
         "jd_text": "Seeking Python Backend Engineer with FastAPI, Docker, and PostgreSQL experience."
       }
     }'
```

### 3. Run Hack My Website (Security Scanner CLI)
Scan any public or local URL:
```bash
# Terminal summary
python -m hack_my_website.cli https://example.com

# Export Markdown Report
python -m hack_my_website.cli https://example.com --format markdown -o audit_report.md

# Export JSON Report
python -m hack_my_website.cli https://example.com --format json -o audit_report.json
```

### 4. Run Automated Unit Tests
```bash
pytest tests -v
```

---

## GitHub Setup & Pushing to `princek34`

The local repository is initialized with `origin` set to `https://github.com/princek34/aivi-security-ai-suite.git`.

To publish to your GitHub profile:
1. Create a new empty repository on GitHub named **`aivi-security-ai-suite`** at [github.com/new](https://github.com/new) (leave "Initialize with README" unchecked).
2. Run the following command from the project root:
   ```bash
   git add .
   git commit -m "feat: complete production implementation of AIVI Campus OS and Hack My Website"
   git branch -M main
   git push -u origin main
   ```

---

## Author & Credits
- **Author:** Prince Kumar ([@princek34](https://github.com/princek34))
- **Role:** AI Engineer Candidate
- **Assignment Context:** Technical Audit and Implementation for AIVI Campus OS & Hack My Website
