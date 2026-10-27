"""
Heuristic Prompt Injection Detector
===================================
Detects common prompt injection, jailbreak, and instruction-override patterns
in incoming agent prompts using pattern matching.

DISCLAIMER & LIMITATION NOTICE:
-------------------------------
This is a heuristic, regular-expression-based detector designed for educational,
demonstration, and first-line defense prototyping. It CANNOT detect every adversarial attack,
such as:
- Sophisticated token smuggling or homoglyph substitutions
- Multi-turn conversational drift and state confusion
- Novel jailbreaks, metaphorical prompt manipulation, or multilingual attacks
- Context-dependent indirect prompt injections embedded in retrieved documents
For production systems, combine heuristic filtering with semantic classifier models,
system-level isolation, least-privilege tool design, and active monitoring.
"""

from dataclasses import dataclass, field
import re
from typing import List, Tuple


@dataclass
class InjectionDetectionResult:
    """Structured result from prompt injection analysis."""
    is_injection: bool
    risk_level: str  # "CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    confidence: float  # 0.0 to 1.0
    matched_patterns: List[str] = field(default_factory=list)
    explanation: str = "No suspicious patterns detected."


# Compiled heuristic rules: (Regex pattern, Category description, Risk level, Weight)
SUSPICIOUS_PATTERNS: List[Tuple[re.Pattern, str, str, float]] = [
    # 1. Instruction override / reset
    (
        re.compile(
            r"\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(previous|prior|above|system|existing)\s+(instructions|directives|prompts|rules|commands|guidelines)\b",
            re.IGNORECASE,
        ),
        "Instruction Override: Attempt to discard prior system rules",
        "CRITICAL",
        0.95,
    ),
    (
        re.compile(
            r"\b(forget|clear)\s+(everything\s+)?(you\s+(were\s+told|know)|your\s+instructions)\b",
            re.IGNORECASE,
        ),
        "Memory Reset: Attempt to wipe instruction context",
        "HIGH",
        0.85,
    ),
    # 2. Secret and system prompt extraction
    (
        re.compile(
            r"\b(reveal|show|print|display|leak|repeat|dump|output)\s+(your\s+)?(system\s+prompt|initial\s+instructions|hidden\s+rules|api[_\s-]?key|secret[_\s-]?key|master\s+password|credentials?)\b",
            re.IGNORECASE,
        ),
        "Secret Extraction: Attempt to leak system prompt or credentials",
        "CRITICAL",
        0.95,
    ),
    (
        re.compile(
            r"\bwhat\s+(is|are)\s+your\s+(initial|original|hidden|system)\s+(prompt|instructions|system\s+message)\b",
            re.IGNORECASE,
        ),
        "System Prompt Probing: Direct inquiry into foundational instructions",
        "HIGH",
        0.80,
    ),
    # 3. Security bypass / jailbreak
    (
        re.compile(
            r"\b(bypass|disable|turn\s+off|circumvent|override)\s+(the\s+)?(security|guardrails?|safety\s+filters?|restrictions?|policies|policy)\b",
            re.IGNORECASE,
        ),
        "Security Bypass: Explicit attempt to disable safety guardrails",
        "CRITICAL",
        0.95,
    ),
    (
        re.compile(
            r"\b(dan\s+mode|jailbreak|jailbroken|unrestricted\s+ai|do\s+anything\s+now|developer\s+mode\s+enabled)\b",
            re.IGNORECASE,
        ),
        "Jailbreak Persona: Invocation of known jailbreak constructs (e.g. DAN/Developer Mode)",
        "CRITICAL",
        0.90,
    ),
    (
        re.compile(
            r"\bpretend\s+(you\s+have\s+no\s+(rules|restrictions|limits|guidelines)|there\s+are\s+no\s+rules)\b",
            re.IGNORECASE,
        ),
        "Roleplay Bypass: Attempt to simulate rule-free persona",
        "HIGH",
        0.85,
    ),
    # 4. Delimiter manipulation / simulated system role
    (
        re.compile(
            r"(<\|im_start\|>|<\|im_end\|>|---\s*BEGIN\s+SYSTEM\s+PROMPT\s*---|---\s*END\s+SYSTEM\s+PROMPT\s*---|\[SYSTEM_INSTRUCTION\])",
            re.IGNORECASE,
        ),
        "Delimiter Injection: Attempt to fake system-level chat markers",
        "CRITICAL",
        0.95,
    ),
    (
        re.compile(
            r"^\s*(system|admin|root)\s*:\s*(you\s+are|override|execute|ignore)",
            re.IGNORECASE | re.MULTILINE,
        ),
        "Role Spoofing: Simulating system/admin header prefix",
        "HIGH",
        0.85,
    ),
]


def detect_prompt_injection(prompt: str) -> InjectionDetectionResult:
    """
    Evaluates an incoming prompt against known heuristic injection patterns.

    Args:
        prompt: Raw user or agent input string to inspect.

    Returns:
        InjectionDetectionResult containing classification, confidence,
        matched categories, and a human-readable explanation.
    """
    if not prompt or not prompt.strip():
        return InjectionDetectionResult(
            is_injection=False,
            risk_level="CLEAN",
            confidence=0.0,
            matched_patterns=[],
            explanation="Empty prompt. No injection detected.",
        )

    matched_categories: List[str] = []
    max_confidence = 0.0
    highest_risk = "CLEAN"

    risk_hierarchy = {"CLEAN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    for pattern, description, risk_level, confidence in SUSPICIOUS_PATTERNS:
        if pattern.search(prompt):
            matched_categories.append(description)
            if confidence > max_confidence:
                max_confidence = confidence
            if risk_hierarchy[risk_level] > risk_hierarchy[highest_risk]:
                highest_risk = risk_level

    if matched_categories:
        explanation = (
            f"Detected {len(matched_categories)} suspicious injection pattern(s): "
            + "; ".join(matched_categories)
        )
        return InjectionDetectionResult(
            is_injection=True,
            risk_level=highest_risk,
            confidence=round(max_confidence, 2),
            matched_patterns=matched_categories,
            explanation=explanation,
        )

    return InjectionDetectionResult(
        is_injection=False,
        risk_level="CLEAN",
        confidence=0.0,
        matched_patterns=[],
        explanation="No suspicious heuristic patterns matched.",
    )
