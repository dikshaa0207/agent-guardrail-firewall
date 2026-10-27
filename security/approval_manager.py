"""
Human-in-the-Loop Approval Manager
==================================
Manages approval queues for agent actions that touch sensitive resources
or originate from untrusted sources.

Enforces critical safety constraints:
1. Hard-block decisions (destructive actions, injection attacks) CANNOT be approved.
2. Once processed (approved or rejected), a request cannot be processed again.
3. Approval records the governance decision only; it does NOT invoke live tools.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import enum
import threading
from typing import Dict, List, Optional, Tuple

from .policy_engine import PolicyDecision, PolicyResult


class ApprovalStatus(str, enum.Enum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass
class ApprovalRequest:
    """Represents an agent action requiring human governance review."""
    request_id: str
    timestamp: str
    action: str
    resource: str
    resource_source: str
    reason: str
    detected_risks: List[str] = field(default_factory=list)
    status: ApprovalStatus = ApprovalStatus.PENDING
    is_hard_block: bool = False
    reviewer: Optional[str] = None
    decision_timestamp: Optional[str] = None
    comments: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "resource": self.resource,
            "resource_source": self.resource_source,
            "reason": self.reason,
            "detected_risks": self.detected_risks,
            "status": self.status.value,
            "is_hard_block": self.is_hard_block,
            "reviewer": self.reviewer,
            "decision_timestamp": self.decision_timestamp,
            "comments": self.comments,
        }


class ApprovalManager:
    """Stateful approval queue manager with concurrency safeguards."""

    def __init__(self):
        self._requests: Dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

    def submit(self, policy_result: PolicyResult) -> ApprovalRequest:
        """
        Submits an evaluated policy result to the approval manager.

        Args:
            policy_result: Policy evaluation output.

        Returns:
            The registered ApprovalRequest.
        """
        with self._lock:
            # Determine if this was a hard block
            is_hard_block = (
                policy_result.is_hard_block
                or policy_result.decision == PolicyDecision.BLOCKED
            )

            req = ApprovalRequest(
                request_id=policy_result.request_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                action=policy_result.action,
                resource=policy_result.resource,
                resource_source=policy_result.resource_source,
                reason=policy_result.reason,
                detected_risks=list(policy_result.detected_risks),
                status=ApprovalStatus.PENDING,
                is_hard_block=is_hard_block,
            )
            self._requests[req.request_id] = req
            return req

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        """Retrieve a specific request by ID."""
        with self._lock:
            return self._requests.get(request_id)

    def get_pending_requests(self) -> List[ApprovalRequest]:
        """Returns all requests currently waiting for human review."""
        with self._lock:
            return [
                req for req in self._requests.values()
                if req.status == ApprovalStatus.PENDING
            ]

    def get_all_requests(self) -> List[ApprovalRequest]:
        """Returns all requests in the registry."""
        with self._lock:
            return list(self._requests.values())

    def approve(
        self,
        request_id: str,
        reviewer: str = "security_officer",
        comments: str = "",
    ) -> Tuple[bool, str]:
        """
        Approves a pending request.

        Safety invariant:
        - Must NEVER approve a hard-block decision.
        - Must NEVER allow double-processing.
        - Only records decision; does NOT execute tools.

        Returns:
            (success: bool, message: str)
        """
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                return False, f"Request '{request_id}' not found."

            # Invariant 1: Hard block cannot be overridden
            if req.is_hard_block:
                return (
                    False,
                    "Security Violation: Hard-blocked requests (destructive actions or injection attacks) "
                    "cannot be approved by policy.",
                )

            # Invariant 2: Idempotent processing / prevent replay
            if req.status != ApprovalStatus.PENDING:
                return (
                    False,
                    f"Request '{request_id}' has already been processed with status '{req.status.value}'. "
                    "Repeated processing is prohibited.",
                )

            # Record human approval
            req.status = ApprovalStatus.APPROVED
            req.reviewer = reviewer or "security_officer"
            req.decision_timestamp = datetime.now(timezone.utc).isoformat()
            req.comments = comments or "Approved via human-in-the-loop governance."

            return True, f"Request '{request_id}' has been successfully approved."

    def reject(
        self,
        request_id: str,
        reviewer: str = "security_officer",
        comments: str = "",
    ) -> Tuple[bool, str]:
        """
        Rejects a pending request.

        Safety invariant:
        - Must NEVER allow double-processing.

        Returns:
            (success: bool, message: str)
        """
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                return False, f"Request '{request_id}' not found."

            if req.status != ApprovalStatus.PENDING:
                return (
                    False,
                    f"Request '{request_id}' has already been processed with status '{req.status.value}'. "
                    "Repeated processing is prohibited.",
                )

            # Record human rejection
            req.status = ApprovalStatus.REJECTED
            req.reviewer = reviewer or "security_officer"
            req.decision_timestamp = datetime.now(timezone.utc).isoformat()
            req.comments = comments or "Rejected via human-in-the-loop governance."

            return True, f"Request '{request_id}' has been rejected."

    def clear(self):
        """Clears all in-memory requests (for testing/reset)."""
        with self._lock:
            self._requests.clear()
