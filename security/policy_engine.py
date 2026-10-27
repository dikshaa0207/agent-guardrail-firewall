"""
Zero-Trust Policy Engine for AI Agents
======================================
Evaluates simulated agent requests based on action, target resource,
resource origin/source, and input prompt. Enforces least-privilege,
zero-trust access control, and defense-in-depth safety boundaries.
"""

from dataclasses import dataclass, field
import enum
import re
import uuid
from typing import List, Optional, Set

from .prompt_injection import detect_prompt_injection, InjectionDetectionResult


class PolicyDecision(str, enum.Enum):
    """Enforceable decision states."""
    ALLOWED = "ALLOWED"
    BLOCKED = "BLOCKED"
    APPROVAL_REQUIRED = "APPROVAL REQUIRED"


@dataclass
class PolicyResult:
    """Structured decision output from policy evaluation."""
    request_id: str
    decision: PolicyDecision
    reason: str
    detected_risks: List[str] = field(default_factory=list)
    action: str = ""
    resource: str = ""
    resource_source: str = ""
    prompt_risk: bool = False
    requires_human_review: bool = False
    is_hard_block: bool = False

    def to_dict(self) -> dict:
        """Convert result to serializable dictionary."""
        return {
            "request_id": self.request_id,
            "decision": self.decision.value,
            "reason": self.reason,
            "detected_risks": self.detected_risks,
            "action": self.action,
            "resource": self.resource,
            "resource_source": self.resource_source,
            "prompt_risk": self.prompt_risk,
            "requires_human_review": self.requires_human_review,
            "is_hard_block": self.is_hard_block,
        }


class PolicyEngine:
    """
    Zero-Trust policy enforcement point for agentic tool use and resource access.
    
    Default rules:
    - Block forbidden destructive actions (delete, execute, drop, kill, etc.)
    - Safely reject invalid/unrecognized actions or missing resources
    - Block detected prompt injection attacks
    - Require human approval for sensitive resources and untrusted origins
    - Allow only explicitly configured safe actions under trusted conditions
    """

    # Actions considered safe for read-only / informational retrieval
    DEFAULT_SAFE_ACTIONS: Set[str] = {
        "read",
        "search",
        "query",
        "summarize",
        "view",
        "fetch",
        "list",
        "describe",
    }

    # Destructive or arbitrary execution actions strictly prohibited
    DEFAULT_FORBIDDEN_ACTIONS: Set[str] = {
        "delete",
        "execute",
        "run",
        "drop",
        "kill",
        "eval",
        "exec",
        "rm",
        "shell",
        "format",
        "wipe",
        "shutdown",
    }

    # All known valid actions that the firewall recognizes
    DEFAULT_VALID_ACTIONS: Set[str] = DEFAULT_SAFE_ACTIONS | DEFAULT_FORBIDDEN_ACTIONS | {
        "update",
        "write",
        "create",
        "export",
        "send",
        "modify",
    }

    # Sensitive resource keywords / classifications
    DEFAULT_SENSITIVE_KEYWORDS: Set[str] = {
        "credential",
        "secret",
        "password",
        "salary",
        "financial",
        "production_db",
        "admin",
        "audit_log",
        "pii",
        "auth_token",
        "master_key",
        "private_key",
        "customer_credit",
        "ssn",
        "confidential",
        "restricted",
        "contract",
    }

    # Origins treated as trusted
    DEFAULT_TRUSTED_SOURCES: Set[str] = {
        "internal",
        "authenticated_user",
        "trusted_system",
        "verified_service",
        "admin_console",
    }

    def __init__(
        self,
        safe_actions: Optional[Set[str]] = None,
        forbidden_actions: Optional[Set[str]] = None,
        sensitive_keywords: Optional[Set[str]] = None,
        trusted_sources: Optional[Set[str]] = None,
    ):
        self.safe_actions = set(safe_actions) if safe_actions is not None else set(self.DEFAULT_SAFE_ACTIONS)
        self.forbidden_actions = set(forbidden_actions) if forbidden_actions is not None else set(self.DEFAULT_FORBIDDEN_ACTIONS)
        self.sensitive_keywords = set(sensitive_keywords) if sensitive_keywords is not None else set(self.DEFAULT_SENSITIVE_KEYWORDS)
        self.trusted_sources = set(trusted_sources) if trusted_sources is not None else set(self.DEFAULT_TRUSTED_SOURCES)
        self.valid_actions = self.safe_actions | self.forbidden_actions | set(self.DEFAULT_VALID_ACTIONS)

    def is_resource_sensitive(self, resource: str) -> bool:
        """Determines if the given resource name contains sensitive keywords."""
        if not resource:
            return False
        normalized = resource.lower().replace("-", "_").replace(" ", "_")
        for kw in self.sensitive_keywords:
            if kw in normalized:
                return True
        return False

    def is_source_trusted(self, source: str) -> bool:
        """Determines if the resource origin is trusted."""
        if not source:
            return False
        return source.strip().lower() in self.trusted_sources

    def evaluate(
        self,
        prompt: str,
        action: str,
        resource: str,
        resource_source: str,
    ) -> PolicyResult:
        """
        Evaluate an agent request against security policies.

        Args:
            prompt: Text prompt or instruction driving the action.
            action: Verb/tool operation (e.g. read, delete, execute, search).
            resource: Target entity, table, file, or endpoint.
            resource_source: Origin of request/resource (e.g. internal, untrusted).

        Returns:
            PolicyResult with ALLOWED, BLOCKED, or APPROVAL REQUIRED decision.
        """
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        detected_risks: List[str] = []

        # 1. Validation: Missing Resource Check
        clean_resource = (resource or "").strip()
        if not clean_resource:
            detected_risks.append("Input Validation: Target resource is missing or empty")
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.BLOCKED,
                reason="Invalid request: Missing target resource. Requests without a valid resource cannot be evaluated.",
                detected_risks=detected_risks,
                action=action or "",
                resource="",
                resource_source=resource_source or "",
                is_hard_block=True,
            )

        # 2. Validation: Action Validation Check
        clean_action = (action or "").strip().lower()
        if not clean_action or clean_action not in self.valid_actions:
            # Action must be a recognized valid action without forbidden characters
            detected_risks.append(f"Input Validation: Unrecognized or invalid action '{action}'")
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.BLOCKED,
                reason=f"Invalid action: '{action}' is not in the configured catalog of recognized agent operations.",
                detected_risks=detected_risks,
                action=clean_action,
                resource=clean_resource,
                resource_source=resource_source or "",
                is_hard_block=True,
            )

        # 3. Prompt Injection Analysis
        injection_result: InjectionDetectionResult = detect_prompt_injection(prompt or "")
        if injection_result.is_injection:
            for pat in injection_result.matched_patterns:
                detected_risks.append(f"Prompt Security: {pat}")
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.BLOCKED,
                reason=f"Prompt Injection Detected: {injection_result.explanation}",
                detected_risks=detected_risks,
                action=clean_action,
                resource=clean_resource,
                resource_source=resource_source or "",
                prompt_risk=True,
                is_hard_block=True,
            )

        # 4. Forbidden Action Check (Hard Block)
        if clean_action in self.forbidden_actions:
            risk_desc = f"Forbidden Action: Execution of '{clean_action}' is strictly prohibited by security policy"
            detected_risks.append(risk_desc)
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.BLOCKED,
                reason=f"Action '{clean_action}' violates safety constraints (destructive or arbitrary command execution).",
                detected_risks=detected_risks,
                action=clean_action,
                resource=clean_resource,
                resource_source=resource_source or "",
                is_hard_block=True,
            )

        # 5. Sensitive Resource Check
        resource_is_sensitive = self.is_resource_sensitive(clean_resource)
        if resource_is_sensitive:
            detected_risks.append(f"Sensitive Asset: Target resource '{clean_resource}' contains sensitive/confidential data")

        # 6. Untrusted Source Check
        source_is_trusted = self.is_source_trusted(resource_source)
        if not source_is_trusted:
            detected_risks.append(f"Untrusted Origin: Source '{resource_source}' is not in trusted origins list")

        # 7. Escalation: Sensitive Resource or Untrusted Source -> APPROVAL REQUIRED
        if resource_is_sensitive or not source_is_trusted:
            reasons = []
            if resource_is_sensitive:
                reasons.append("resource is designated as sensitive")
            if not source_is_trusted:
                reasons.append(f"origin '{resource_source}' is untrusted")
            reason_str = "Human review required because " + " and ".join(reasons) + "."

            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.APPROVAL_REQUIRED,
                reason=reason_str,
                detected_risks=detected_risks,
                action=clean_action,
                resource=clean_resource,
                resource_source=resource_source or "",
                requires_human_review=True,
                is_hard_block=False,
            )

        # 8. Safe Action Verification
        if clean_action in self.safe_actions:
            return PolicyResult(
                request_id=request_id,
                decision=PolicyDecision.ALLOWED,
                reason=f"Safe action '{clean_action}' on non-sensitive resource from trusted source '{resource_source}'.",
                detected_risks=[],
                action=clean_action,
                resource=clean_resource,
                resource_source=resource_source or "",
                is_hard_block=False,
            )

        # 9. Default-Deny for unclassified neutral actions (e.g., 'update', 'send', 'export')
        detected_risks.append(f"Policy Default: Neutral action '{clean_action}' requires supervisor approval")
        return PolicyResult(
            request_id=request_id,
            decision=PolicyDecision.APPROVAL_REQUIRED,
            reason=f"Action '{clean_action}' is not in the pre-approved safe read list and requires verification.",
            detected_risks=detected_risks,
            action=clean_action,
            resource=clean_resource,
            resource_source=resource_source or "",
            requires_human_review=True,
            is_hard_block=False,
        )
