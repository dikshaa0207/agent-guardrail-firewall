# 🛡️ Agent Guardrail Firewall: Project Presentation

> **Presentation Deck & Talking Notes for Hackathon Evaluators**  
> *Zero-Trust Security, Policy Enforcement & Cryptographic Audit for AI Agents*

---

## 1. Problem Statement

Autonomous AI agents are increasingly entrusted with tools to interact with real systems—querying databases, summarizing documents, invoking APIs, and executing commands. However, existing agent deployments suffer from critical security gaps:

1. **Prompt Injection & Instruction Hijacking:** Adversarial text embedded in user prompts or third-party web pages can manipulate the agent into ignoring instructions or leaking internal rules.
2. **Excessive Agency & Unbounded Verbs:** Agents granted arbitrary access can perform destructive actions (`delete`, `drop`, `execute`) without deterministic safety checks.
3. **Sensitive Asset Exposure:** Agents lack granular context on whether an asset is confidential (e.g. salaries, credentials, contracts) versus public.
4. **Data Exfiltration (PII / Financial Egress):** Unmonitored agent responses can leak customer tax identifiers (PAN), payment cards, mobile numbers, and emails.
5. **Vulnerable Audit Logging:** Traditional log files are mutable and can be altered or deleted by attackers to erase audit trails.

---

## 2. Proposed Solution

**Agent Guardrail Firewall** is a deterministic, defense-in-depth security gateway that intercepts, evaluates, and audits agent actions before and after tool execution:

- **Pre-Execution Shield:** Inspects prompts for injection patterns and enforces zero-trust policy rules on requested verbs, resources, and origins.
- **Human-in-the-Loop Governance:** Automatically routes sensitive operations to a supervisor queue, ensuring hard-blocked actions can never be authorized.
- **Egress Inspection Guard:** Scans outgoing responses for Personally Identifiable Information (Indian PAN, credit cards, emails, Indian mobile numbers) and applies safe redaction.
- **Cryptographic Auditability:** Chains every decision using SHA-256 block hashes into SQLite, enabling mathematical proof of audit trail integrity.
- **Self-Contained & Zero External Cost:** Built entirely with standard Python libraries, regular expressions, SQLite, and Streamlit—no paid APIs or API keys required.

---

## 3. Architecture & Data Flow

```
[ User / External Environment ]
              │
              ▼ (Prompt, Verb, Resource, Source)
┌────────────────────────────────────────────────────────┐
│               AGENT GUARDRAIL FIREWALL                 │
├────────────────────────────────────────────────────────┤
│ 1. Heuristic Prompt Injection Detector                 │
│    └── Matches instruction override & leak patterns   │
│                                                        │
│ 2. Zero-Trust Policy Engine                            │
│    ├── Input Validation (missing resource, invalid verb)│
│    ├── Forbidden Actions Check (delete, execute)       │
│    ├── Sensitive Asset & Untrusted Source Rules        │
│    └── Safe Read Allowed                               │
│                                                        │
│ 3. Human Approval Manager                              │
│    ├── Queue for Sensitive / Untrusted Operations      │
│    ├── Anti-Replay Guard (No duplicate approvals)      │
│    └── Hard-Block Non-Override Invariant               │
│                                                        │
│ 4. Outgoing Data Scanner                               │
│    ├── Indian PAN, Card PAN, Email, Phone Regex        │
│    ├── Masked Preview (Full values never logged)      │
│    └── Automatic Redaction Stream                      │
│                                                        │
│ 5. Cryptographic Audit Logger                          │
│    ├── SQLite Append-Only Storage                      │
│    ├── SHA-256 Hash Chaining (Genesis -> Current)     │
│    └── Zero Raw Prompt Exposure Guarantee              │
└────────────────────────────────────────────────────────┘
              │
              ▼
    [ Simulated Outcome / Dashboard ]
```

---

## 4. Technology Stack

- **Application & Dashboard:** Python 3.10+, Streamlit (custom dark navy theme with cyan accents)
- **Security Logic:** Pure Python regular expressions (`re`) and dataclasses
- **Data Persistence:** SQLite3 (standard library, zero installation)
- **Cryptographic Engine:** Python standard library `hashlib` (SHA-256 digest calculation)
- **Testing Framework:** `pytest` (automated testing suite covering 21 security behaviors)
- **Dependencies:** Minimal footprint (`streamlit`, `pytest`)

---

## 5. Key Security Controls & Invariants

| Security Control | Implementation Mechanism | Invariant Enforced |
| :--- | :--- | :--- |
| **Forbidden Action Hard-Block** | Deterministic verb filter in `policy_engine.py` | Actions like `delete` or `execute` are always blocked. |
| **Prompt Injection Filter** | Heuristic regex matching in `prompt_injection.py` | Flags known prompt override, jailbreak, and extraction patterns. |
| **Zero-Trust Review Escalation** | Resource and origin analysis in `policy_engine.py` | Sensitive assets or untrusted origins require human supervisor review. |
| **Hard-Block Non-Override** | State validation in `approval_manager.py` | Supervisors can never approve a request marked as a hard block. |
| **Anti-Replay Protection** | Concurrency-locked state in `approval_manager.py` | A request cannot be processed more than once. |
| **PII / PAN Egress Guard** | Regex scanner and masking in `data_scanner.py` | Masks sensitive identifiers; blocks unauthorized outgoing transmission. |
| **Tamper-Evident Audit Chain** | Sequential SHA-256 hashing in `audit_logger.py` | Detects any database modification, deletion, or reordering. |
| **Privacy by Design** | Hash digest logging in `audit_logger.py` | Raw prompts, emails, and PANs are never persisted in the database. |

---

## 6. Limitations & Future Improvements

### Current Prototype Scope
- **Heuristic Pattern Matching:** The prompt injection detector uses regular expressions for common patterns. It cannot catch adversarial token smuggling, homoglyph attacks, or multi-turn conversational drift.
- **Simulated Tool Execution:** All actions and tool invocations are simulated within the prototype to guarantee safe evaluation.
- **Ephemeral Cloud Persistence:** On free platforms like Streamlit Community Cloud, local SQLite database storage resets if the container reboots.

### Production Roadmap & Future Improvements
1. **Semantic Injection Classifiers:** Integrate lightweight on-device classifier models (e.g. DeBERTa or ONNX models) to augment heuristic regex rules.
2. **Dynamic Tool Sandbox Isolation:** Pair policy enforcement with containerized microVM sandboxes (e.g., gVisor, Firecracker) for real tool execution.
3. **Distributed Cryptographic Notarization:** Anchor the hash chain root to external immutable transparency logs (e.g. Sigstore / Rekor) or enterprise databases.
4. **Attribute-Based Access Control (ABAC):** Introduce fine-grained role-based policies and user session tokens.

---

## 7. Five Likely Judge Questions & Simple Answers

### Q1: "Why use deterministic regex rules instead of an LLM to evaluate agent actions?"
> **Answer:**  
> Deterministic rules provide guaranteed, low-latency, and un-hackable boundaries for critical constraints. An LLM evaluator can itself be tricked by prompt injection, introduces non-deterministic behavior, adds network latency, and requires paid API keys. Our architecture uses deterministic zero-trust policies for foundational boundaries and recommends layering semantic models as an additional defense line.

---

### Q2: "Can a supervisor in the Pending Approvals tab override a hard-blocked delete action?"
> **Answer:**  
> No. We enforce a strict security invariant: hard-blocked actions (destructive verbs like `delete` or detected prompt injections) can **never** be approved, even by a supervisor. The approval manager inspects the `is_hard_block` flag and rejects any override attempt.

---

### Q3: "How does the SHA-256 hash chain detect if an attacker modifies or deletes a log row?"
> **Answer:**  
> Each audit block stores `previous_hash` pointing to the SHA-256 digest of the prior record, and computes its own `record_hash` over its contents combined with `previous_hash`. If an attacker modifies a row's decision, its content hash changes and breaks the link to subsequent records. If an attacker deletes a row, the sequence IDs break and the next record's `previous_hash` fails to match the prior block.

---

### Q4: "What privacy safeguards prevent user prompts or customer PII from leaking into the audit log?"
> **Answer:**  
> We enforce a **Zero Raw Payload** policy. The audit logger stores only the length and SHA-256 digest of prompts, and only category counts and masked previews of egress data. The database additionally features an internal defensive sanitizer that strips raw prompts and redacts PII before disk serialization.

---

### Q5: "What makes this prototype ready for immediate deployment and testing?"
> **Answer:**  
> The project has zero external dependencies, requires no paid API keys, and includes 21 automated unit and integration tests covering all security invariants. It runs natively on Streamlit Community Cloud or locally with a single `streamlit run app.py` command.
