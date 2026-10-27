# 🛡️ Agent Guardrail Firewall

> **Zero-Trust Security Gateway, Policy Enforcement, and Cryptographic Audit Chain for AI Agents.**  
> Built with Python, Streamlit, SQLite, and SHA-256. Fully self-contained — **zero paid APIs or external services required.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit Ready](https://img.shields.io/badge/streamlit-1.30+-FF4B4B.svg)](https://streamlit.io/)
[![Tests Passing](https://img.shields.io/badge/pytest-21%20passed-brightgreen.svg)](https://pytest.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## ⚠️ Important Prototype & Security Notice

> [!WARNING]
> **SIMULATION & PROTOTYPE NOTICE:**  
> All agent actions, tool calls, and egress streams evaluated in this application are **strictly simulated** in a sandboxed demonstration environment.  
> This project demonstrates defense-in-depth security principles (heuristic injection filters, zero-trust policies, human-in-the-loop approvals, PII scanners, and cryptographic hash chains).  
> **It is not a certified production firewall or compliance certification.** Do not expose live production credentials or unencrypted confidential infrastructure to this prototype.

---

## 📖 Table of Contents
1. [Overview & Threat Model](#overview--threat-model)
2. [Architecture Diagram](#architecture-diagram)
3. [Core Security Modules](#core-security-modules)
4. [Streamlit Dashboard Features](#streamlit-dashboard-features)
5. [Quickstart (Local Installation)](#quickstart-local-installation)
6. [Running the Automated Tests](#running-the-automated-tests)
7. [Deployment to Streamlit Community Cloud](#deployment-to-streamlit-community-cloud)
8. [Persistence & Cloud Considerations](#persistence--cloud-considerations)
9. [Project Directory Structure](#project-directory-structure)

---

## Overview & Threat Model

Autonomous AI agents equipped with tools (file I/O, database queries, shell execution, external API webhooks) face severe security threats:
- **Indirect & Direct Prompt Injections:** Adversarial inputs tricking the agent into overriding foundational directives.
- **Unauthorized Tool & Resource Escalation:** Agents attempting destructive actions (`delete`, `execute`, `drop`) on sensitive infrastructure.
- **Untrusted Source Confusion:** Acting on untrusted third-party inputs as though they were internal trusted commands.
- **Sensitive Data Exfiltration (PII/Financial Leakage):** Exposing confidential customer identifiers (PAN, emails, phone numbers) in egress responses.
- **Retroactive Audit Log Tampering:** Attackers or rogue administrators modifying logs to hide unauthorized actions.

**Agent Guardrail Firewall** provides a defense-in-depth shield with five layers of protection:
```
                      [ Agent Input / Prompt ]
                                 │
                                 ▼
               ┌───────────────────────────────────┐
               │ 1. Heuristic Injection Detector   │ ──(Injection Detected)──► [ BLOCKED ]
               └───────────────────────────────────┘
                                 │ Clean Prompt
                                 ▼
               ┌───────────────────────────────────┐
               │ 2. Zero-Trust Policy Engine       │ ──(Forbidden Action)────► [ BLOCKED ]
               └───────────────────────────────────┘
                                 │
                 ┌───────────────┴───────────────┐
                 ▼                               ▼
       (Sensitive / Untrusted)             (Safe Action)
                 │                               │
                 ▼                               ▼
      ┌──────────────────────┐              [ ALLOWED ]
      │ 3. Human Approval    │                   │
      │    Governance Queue  │                   │
      └──────────────────────┘                   │
                 │                               │
        [ Approve / Reject ]                     │
                 │                               │
                 └───────────────┬───────────────┘
                                 │
                                 ▼
               ┌───────────────────────────────────┐
               │ 4. Outgoing Data (PII) Scanner    │ ──(Sensitive Data)──────► [ EGRESS BLOCKED ]
               └───────────────────────────────────┘
                                 │ Clean / Redacted
                                 ▼
               ┌───────────────────────────────────┐
               │ 5. SHA-256 Cryptographic Audit    │
               │    Append-Only Hash Chain         │
               └───────────────────────────────────┘
```

---

## Core Security Modules

### 1. Zero-Trust Policy Engine (`security/policy_engine.py`)
- Evaluates four vectors: `prompt`, `action`, `resource`, and `resource_source`.
- Returns structured decision: `ALLOWED`, `BLOCKED`, or `APPROVAL REQUIRED`.
- **Enforcement Rules:**
  - **Forbidden Actions:** Destructive operations (`delete`, `execute`, `drop`, `kill`, `rm`, `eval`, `shell`) are **hard-blocked**.
  - **Input Validation:** Empty resources or unrecognized actions are safely rejected with `BLOCKED`.
  - **Sensitive Resources:** Operations touching keywords (`credential`, `salary`, `financial`, `production_db`, `admin`, `confidential`, `contract`) require supervisor approval.
  - **Untrusted Origins:** Requests originating outside trusted domains (`untrusted_external`, `anonymous_user`) require human approval.
  - **Safe Actions:** Only explicitly configured safe read operations (`read`, `search`, `query`, `summarize`, `view`) on non-sensitive assets from trusted sources are `ALLOWED`.

### 2. Heuristic Prompt Injection Detector (`security/prompt_injection.py`)
- Fast, deterministic regex detection for known adversarial patterns:
  - Instruction override / memory reset ("ignore previous instructions", "disregard prior directives")
  - System prompt extraction & secret leakage ("reveal system prompt", "show api_key", "dump credentials")
  - Safety filter bypasses & jailbreak personas ("DAN mode", "jailbreak", "bypass security", "developer mode")
  - Delimiter / role spoofing (`<|im_start|>`, `--- BEGIN SYSTEM PROMPT ---`, `system: you are`)
- **Limitation Notice:** Documented within the module that heuristic regex cannot detect semantic token smuggling or multi-turn conversational drift; it serves as a lightweight first line of defense.
- **Benign Precision:** Tuned to avoid false positives on legitimate requests (e.g. "Please ignore the typo in my previous query").

### 3. Human-in-the-Loop Governance (`security/approval_manager.py`)
- Queues requests requiring human review (`APPROVAL REQUIRED`).
- **Critical Invariants:**
  - **Hard-Block Non-Override:** Hard-block decisions (`delete`, injection attacks) **CAN NEVER be approved**, even by an administrator.
  - **Replay Protection:** Once approved or rejected, a request cannot be processed again.
  - **Decision Only:** Human approval records governance authorization; it **does NOT execute live tools or system commands**.

### 4. Outgoing Data Scanner (`security/data_scanner.py`)
- Scans simulated outgoing payloads for sensitive Personally Identifiable Information:
  - **Indian Permanent Account Number (PAN):** Canonical alphanumeric regex (`[A-Z]{5}[0-9]{4}[A-Z]{1}`)
  - **Payment Card Primary Account Number (PAN):** 16-digit card patterns
  - **Email Addresses:** Standard RFC-compliant address patterns
  - **Indian Mobile Numbers:** 10-digit mobile numbers starting with 6-9, with optional `+91`, `91`, or `0` prefix
- **Privacy Guarantee:** Exposes and logs **ONLY masked snippets** (e.g., `AB****34F`, `u***r@domain.com`, `+91 98****3210`). The full sensitive token is never displayed in logs.
- Automatically redacts sensitive tokens with `[REDACTED_*]` tags and blocks transmission when enabled.

### 5. Cryptographic Audit Logger (`security/audit_logger.py`)
- Maintains an append-only audit trail in SQLite using a **SHA-256 hash chain**.
- Each record's hash is computed from:
  $$\text{record\_hash} = \text{SHA256}(\text{id} \parallel \text{timestamp} \parallel \text{event\_type} \parallel \text{request\_id} \parallel \text{action} \parallel \text{decision} \parallel \text{details\_json} \parallel \text{previous\_hash})$$
- **Tamper Detection:** `verify_chain()` scans from the genesis block (`0000...`) and detects any retroactive row modification, insertion, or deletion.
- **Zero Raw Payload Guarantee:** Raw prompts and sensitive payloads are **NEVER stored** in SQLite. Only prompt lengths and SHA-256 hashes are persisted.
- Configurable database path via `GUARDRAIL_AUDIT_DB` environment variable with in-memory fallback.

---

## Streamlit Dashboard Features

The dashboard (`app.py`) provides a four-tab cybersecurity console:

1. **Test an Agent Action:**
   - Interactive request simulator with pre-configured attack and benign scenarios.
   - Live policy decision card (`ALLOWED`, `BLOCKED`, `APPROVAL REQUIRED`).
   - Detailed risk breakdown, reason, and request ID.
2. **Pending Approvals:**
   - Dedicated queue for supervisor review.
   - Reviewer identity and comment tracking.
   - Approve / Reject buttons with immediate feedback.
   - Governance history audit trail.
3. **Outgoing Data Scanner:**
   - Egress payload simulator with pre-loaded synthetic PII test payloads.
   - Real-time detection, masked snippet preview, and safe redacted preview.
   - Policy toggle to block egress on sensitive detection.
4. **Cryptographic Audit Trail:**
   - Live audit event log viewer.
   - **One-click "Verify Hash Chain Integrity"** button running SHA-256 chain verification.
   - **Interactive "Simulate Database Tampering"** demonstration button: shows how unauthorized database modifications are instantly caught by the cryptographic chain.
   - JSON export for audit logs.

---

## Quickstart (Local Installation)

### Prerequisites
- Python 3.10, 3.11, 3.12, 3.13, or 3.14
- Git (optional)

### 1. Clone or Open the Workspace
```bash
git clone https://github.com/<your-username>/agent-guardrail-firewall.git
cd agent-guardrail-firewall
```

### 2. Set Up a Virtual Environment (Recommended)
On macOS / Linux:
```bash
python3 -m venv venv
source venv/bin/activate
```
On Windows:
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Streamlit Application
```bash
streamlit run app.py
```
Open your browser to `http://localhost:8501`.

---

## Running the Automated Tests

The project includes an automated test suite (`tests/test_security.py`) covering all functional requirements, security invariants, edge cases, and cryptographic checks.

Run pytest from the repository root:
```bash
python -m pytest tests/test_security.py -v
```

### Verified Test Suite
| Test Name | Verification Focus | Status |
| :--- | :--- | :---: |
| `test_safe_request_allowed` | Normal read action on public docs allowed | ✅ PASSED |
| `test_forbidden_action_blocked` | Forbidden actions (`delete`, `execute`) hard-blocked | ✅ PASSED |
| `test_sensitive_resource_requires_approval` | Accessing salary / credentials triggers review | ✅ PASSED |
| `test_untrusted_source_requires_approval` | External origins require human approval | ✅ PASSED |
| `test_invalid_action_or_missing_resource_rejected` | Missing resource or bad verb safely blocked | ✅ PASSED |
| `test_prompt_injection_detection` | Injection & jailbreak patterns flagged and blocked | ✅ PASSED |
| `test_benign_prompt_not_falsely_flagged` | Benign queries with keywords not falsely blocked | ✅ PASSED |
| `test_pan_like_identifier_detected` | Indian PAN & Payment Card PAN detected & masked | ✅ PASSED |
| `test_email_detected` | Email addresses detected and redacted | ✅ PASSED |
| `test_indian_mobile_number_detected` | Indian mobile numbers (+91) detected and masked | ✅ PASSED |
| `test_clean_outgoing_text_allowed` | Clean egress text allowed through scanner | ✅ PASSED |
| `test_approval_and_rejection` | Approval & rejection workflow and anti-replay | ✅ PASSED |
| `test_hard_block_cannot_be_approved` | Hard-block decisions cannot be approved | ✅ PASSED |
| `test_valid_audit_chain` | SHA-256 hash chain mathematically valid | ✅ PASSED |
| `test_tampered_audit_record_detected` | Database alteration detected as tampering | ✅ PASSED |
| `test_zero_raw_payload_in_audit_storage` | Raw user prompts never stored in SQLite | ✅ PASSED |
| `test_audit_chain_detects_deletion` | Record deletion detected via sequence gap and broken hash link | ✅ PASSED |
| `test_audit_chain_detects_ordering_change` | Record order alteration detected by hash verification | ✅ PASSED |
| `test_audit_logger_defensive_pii_sanitization` | Defensive redaction and prompt hashing in audit logs | ✅ PASSED |
| `test_empty_and_whitespace_inputs` | Safe handling of empty, whitespace, and None inputs | ✅ PASSED |
| `test_duplicate_rejection_prevented` | Prevents re-rejection or double-processing of requests | ✅ PASSED |

---

## Deployment to Streamlit Community Cloud

Deploying this prototype to **Streamlit Community Cloud** is completely free and takes under 3 minutes:

1. **Push your code to GitHub:**
   ```bash
   git init
   git add .
   git commit -m "Initial commit: Agent Guardrail Firewall"
   git branch -M main
   git remote add origin https://github.com/<your-github-username>/agent-guardrail-firewall.git
   git push -u origin main
   ```

2. **Connect to Streamlit Cloud:**
   - Navigate to [share.streamlit.io](https://share.streamlit.io/) and sign in with your GitHub account.
   - Click **"New app"**.
   - Select your repository (`agent-guardrail-firewall`), branch (`main`), and set **Main file path** to `app.py`.
   - Click **"Deploy!"**.

3. **Deployment Verification:**
   - Streamlit Cloud automatically detects `requirements.txt` and installs `streamlit` and `pytest`.
   - The application will launch with zero configuration required.

---

## Persistence & Cloud Considerations

> [!NOTE]
> **Ephemeral Storage on Streamlit Community Cloud:**  
> By default, the application writes audit events to a local SQLite database (`audit_trail.db`).  
> On Streamlit Community Cloud containers, local disk storage is **ephemeral**. This means:
> - Data persists across user sessions while the container remains warm.
> - If the application reboots, updates, or sleeps due to inactivity, the local SQLite database resets.
> - For persistent production deployments, set the `GUARDRAIL_AUDIT_DB` environment variable or connect to an external managed database (e.g., PostgreSQL or Supabase).

---

## Project Directory Structure

```
AGENT GUARDRAIL FIREWALL/
├── app.py                      # Main Streamlit dashboard application (Dark Navy Cyber Theme)
├── requirements.txt            # Minimal dependencies (streamlit, pytest)
├── README.md                   # Comprehensive documentation & deployment guide
├── DEMO_GUIDE.md               # 3-5 minute live hackathon demonstration script
├── PRESENTATION.md             # Slide notes, architecture summary & 5 judge Q&As
├── ARCHITECTURE.md             # Mermaid architecture diagrams & component breakdown
├── .gitignore                  # Git ignore rules for caches, envs, and DBs
├── security/                   # Core security engine modules
│   ├── __init__.py             # Security package exports
│   ├── policy_engine.py        # Zero-trust policy evaluation & decision logic
│   ├── prompt_injection.py     # Heuristic prompt injection & jailbreak detector
│   ├── approval_manager.py     # Human-in-the-loop review queue & invariants
│   ├── data_scanner.py         # Outgoing PII / PAN / Email / Phone scanner
│   └── audit_logger.py         # SQLite SHA-256 cryptographic hash-chain logger
└── tests/                      # Automated test suite
    └── test_security.py        # 21 unit & integration tests
```

---

## License

This project is licensed under the MIT License — feel free to use and adapt it for hackathons, security research, and prototyping.
