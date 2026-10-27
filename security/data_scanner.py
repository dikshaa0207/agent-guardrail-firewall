"""
Outgoing Data Scanner
=====================
Inspects outgoing agent responses and retrieved payload streams for
sensitive Personally Identifiable Information (PII) and financial tokens.

Safety Requirements:
- Uses regular expressions for Indian PAN, Payment Card PAN, Email, and Indian Mobile Numbers.
- Displays and logs ONLY sanitized/masked snippets (NEVER raw sensitive values).
- Blocks simulated outgoing content when matched rules detect sensitive data.
- Produces fully redacted content for safe logging and display.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Pattern, Tuple


@dataclass
class ScanResult:
    """Structured report returned by the Outgoing Data Scanner."""
    is_clean: bool
    is_blocked: bool
    categories_detected: List[str] = field(default_factory=list)
    total_findings: int = 0
    redacted_text: str = ""
    findings_summary: List[Dict[str, Any]] = field(default_factory=list)
    reason: str = "Clean text. No sensitive data detected."

    def to_dict(self) -> dict:
        return {
            "is_clean": self.is_clean,
            "is_blocked": self.is_blocked,
            "categories_detected": self.categories_detected,
            "total_findings": self.total_findings,
            "redacted_text": self.redacted_text,
            "findings_summary": self.findings_summary,
            "reason": self.reason,
        }


def mask_sensitive_value(value: str, category: str) -> str:
    """
    Produces a safe, masked representation of sensitive tokens.
    Never exposes full values.
    """
    clean_val = value.strip()
    length = len(clean_val)
    if length <= 4:
        return "****"

    if "pan" in category.lower():
        # ABCDE1234F -> AB****34F
        return f"{clean_val[:2]}****{clean_val[-2:]}"
    elif "email" in category.lower():
        # alice.smith@domain.com -> a***h@domain.com
        if "@" in clean_val:
            user, domain = clean_val.split("@", 1)
            masked_user = f"{user[0]}***{user[-1]}" if len(user) > 2 else "***"
            return f"{masked_user}@{domain}"
        return f"{clean_val[:2]}****{clean_val[-2:]}"
    elif "mobile" in category.lower() or "phone" in category.lower():
        # +91 9876543210 -> +91 98****3210
        return f"{clean_val[:5]}****{clean_val[-3:]}"
    else:
        return f"{clean_val[:2]}****{clean_val[-2:]}"


class OutgoingDataScanner:
    """
    Scans simulated outgoing agent communications to prevent sensitive data exfiltration.
    """

    # Regex definitions: (Category, Compiled Pattern, Redaction Tag)
    SCAN_RULES: List[Tuple[str, Pattern, str]] = [
        # 1. Indian Permanent Account Number (PAN) (e.g. ABCDE1234F)
        (
            "Indian PAN Card",
            re.compile(r"\b[A-Za-z]{5}[0-9]{4}[A-Za-z]{1}\b"),
            "[REDACTED_INDIAN_PAN]",
        ),
        # 2. Payment Card Primary Account Number (PAN) (16-digit card formats)
        (
            "Payment Card PAN",
            re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),
            "[REDACTED_CARD_PAN]",
        ),
        # 3. Email addresses
        (
            "Email Address",
            re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"),
            "[REDACTED_EMAIL]",
        ),
        # 4. Indian Mobile Numbers (+91/91/0 prefix optional, 10 digits starting 6-9)
        (
            "Indian Mobile Number",
            re.compile(
                r"\b(?:\+91[\-\s]?|91[\-\s]?|0)?[6-9]\d{4}[\-\s]?\d{5}\b|\b(?:\+91[\-\s]?|91[\-\s]?|0)?[6-9]\d{9}\b"
            ),
            "[REDACTED_INDIAN_PHONE]",
        ),
    ]

    def __init__(self, block_on_detection: bool = True):
        self.block_on_detection = block_on_detection

    def scan(self, text: str) -> ScanResult:
        """
        Scans candidate outgoing text for sensitive patterns.

        Args:
            text: Outgoing response payload or tool return data.

        Returns:
            ScanResult containing detection metrics, masked sample previews,
            redacted payload, and block status.
        """
        if not text or not text.strip():
            return ScanResult(
                is_clean=True,
                is_blocked=False,
                categories_detected=[],
                total_findings=0,
                redacted_text="",
                findings_summary=[],
                reason="Empty content payload. No sensitive data detected.",
            )

        redacted_text = text
        categories_detected: List[str] = []
        findings_summary: List[Dict[str, Any]] = []
        total_findings = 0

        for category, pattern, placeholder in self.SCAN_RULES:
            # Find all matching raw strings
            matches = pattern.findall(text)
            if matches:
                # Handle possible tuple return if regex groups exist
                raw_matches = [
                    m[0] if isinstance(m, tuple) else m
                    for m in matches
                    if (m[0] if isinstance(m, tuple) else m).strip()
                ]
                count = len(raw_matches)
                if count > 0:
                    categories_detected.append(category)
                    total_findings += count

                    # Generate safe, non-revealing masked preview samples
                    masked_samples = [
                        mask_sensitive_value(m, category) for m in raw_matches[:3]
                    ]

                    findings_summary.append({
                        "category": category,
                        "count": count,
                        "masked_samples": masked_samples,
                    })

                    # Apply redaction to outgoing text
                    redacted_text = pattern.sub(placeholder, redacted_text)

        if total_findings > 0:
            is_blocked = self.block_on_detection
            reason = (
                f"Blocked simulated egress: Detected {total_findings} sensitive item(s) "
                f"across categories: {', '.join(categories_detected)}."
            )
            return ScanResult(
                is_clean=False,
                is_blocked=is_blocked,
                categories_detected=categories_detected,
                total_findings=total_findings,
                redacted_text=redacted_text,
                findings_summary=findings_summary,
                reason=reason,
            )

        return ScanResult(
            is_clean=True,
            is_blocked=False,
            categories_detected=[],
            total_findings=0,
            redacted_text=text,
            findings_summary=[],
            reason="Payload clean. No sensitive identifiers or patterns detected.",
        )
