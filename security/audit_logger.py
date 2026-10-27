"""
Cryptographic Audit Logger
==========================
Maintains an immutable, append-only audit trail in SQLite using a SHA-256
hash chain (blockchain-style tamper detection).

Security & Privacy Guarantees:
- Every record is cryptographically linked to the previous record's hash.
- Verification detects any retroactive record insertion, modification, or deletion.
- Zero sensitive data exposure: Raw prompts and sensitive payloads are NEVER stored.
  Only cryptographic hashes, lengths, actions, decisions, and sanitized metadata are persisted.
- Configurable storage path via the `GUARDRAIL_AUDIT_DB` environment variable with
  in-memory (`:memory:`) support.
"""

import contextlib
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple, Generator

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

# Defensive sanitizer regexes to ensure sensitive tokens never slip into audit records
_DEFENSIVE_PII_PATTERNS = [
    re.compile(r"\b[A-Za-z]{5}[0-9]{4}[A-Za-z]{1}\b"),  # Indian PAN
    re.compile(r"\b(?:\d{4}[ -]?){3}\d{4}\b"),           # Payment Card
    re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"),  # Email
]


def _sanitize_audit_value(val: Any) -> Any:
    """Recursively sanitize details to guarantee zero sensitive data exposure."""
    if isinstance(val, str):
        sanitized = val
        for pat in _DEFENSIVE_PII_PATTERNS:
            sanitized = pat.sub("[REDACTED_AUDIT_VALUE]", sanitized)
        return sanitized
    elif isinstance(val, dict):
        sanitized_dict = {}
        for k, v in val.items():
            # Forbid raw prompt or raw payload keys
            if k.lower() in {"raw_prompt", "prompt", "raw_payload", "payload", "secret", "password"}:
                sanitized_dict[f"{k}_sha256"] = compute_payload_hash(str(v))
                sanitized_dict[f"{k}_length"] = len(str(v))
            else:
                sanitized_dict[k] = _sanitize_audit_value(v)
        return sanitized_dict
    elif isinstance(val, list):
        return [_sanitize_audit_value(item) for item in val]
    return val


@dataclass
class AuditRecord:
    """Represents a single immutable audit entry in the hash chain."""
    id: int
    timestamp: str
    event_type: str
    request_id: str
    action: str
    decision: str
    details: Dict[str, Any]
    previous_hash: str
    record_hash: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "request_id": self.request_id,
            "action": self.action,
            "decision": self.decision,
            "details": self.details,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
        }


def compute_payload_hash(payload: str) -> str:
    """Computes a SHA-256 digest of a payload for verification without storing raw data."""
    if payload is None:
        return ""
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_record_hash(
    record_id: int,
    timestamp: str,
    event_type: str,
    request_id: str,
    action: str,
    decision: str,
    details_json: str,
    previous_hash: str,
) -> str:
    """
    Computes canonical SHA-256 digest for an audit entry.
    Links current record attributes with the previous record's hash.
    """
    canonical_str = (
        f"{record_id}|{timestamp}|{event_type}|{request_id}|"
        f"{action}|{decision}|{details_json}|{previous_hash}"
    )
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


class AuditLogger:
    """
    Thread-safe SQLite audit logger implementing a SHA-256 cryptographic chain.
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize the audit logger.
        Priority:
        1. Passed `db_path`
        2. `GUARDRAIL_AUDIT_DB` environment variable
        3. Default local file `audit_trail.db`
        """
        env_path = os.environ.get("GUARDRAIL_AUDIT_DB")
        resolved_path = db_path or env_path or "audit_trail.db"
        self.db_path = resolved_path
        self._lock = threading.Lock()
        self._init_db()

    @contextlib.contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Yields SQLite connection and guarantees clean closure to avoid Windows lock leaks."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        """Initializes the database schema if not present."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS audit_chain (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        event_type TEXT NOT NULL,
                        request_id TEXT NOT NULL,
                        action TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        details_json TEXT NOT NULL,
                        previous_hash TEXT NOT NULL,
                        record_hash TEXT NOT NULL
                    )
                    """
                )
                conn.commit()

    def _get_last_record(self, conn: sqlite3.Connection) -> Optional[Tuple[int, str]]:
        """Returns (id, record_hash) of the latest entry or None."""
        cur = conn.cursor()
        cur.execute("SELECT id, record_hash FROM audit_chain ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        if row:
            return row["id"], row["record_hash"]
        return None

    def log_event(
        self,
        event_type: str,
        request_id: str,
        action: str,
        decision: str,
        details: Dict[str, Any],
    ) -> AuditRecord:
        """
        Appends an event to the cryptographic audit chain.

        SAFETY: The caller MUST ensure that `details` contains only sanitized metadata,
        hashes, and categories - never raw user prompts or unredacted confidential data.
        """
        # Ensure details is safely sanitized and serializable
        clean_details = _sanitize_audit_value(dict(details))
        details_json = json.dumps(clean_details, sort_keys=True)
        timestamp = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._get_connection() as conn:
                last_record = self._get_last_record(conn)
                if last_record is None:
                    previous_hash = GENESIS_HASH
                else:
                    previous_hash = last_record[1]

                # Insert placeholder to obtain auto-increment ID
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO audit_chain
                    (timestamp, event_type, request_id, action, decision, details_json, previous_hash, record_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        timestamp,
                        event_type,
                        request_id,
                        action,
                        decision,
                        details_json,
                        previous_hash,
                        "PENDING",
                    ),
                )
                record_id = cursor.lastrowid

                # Calculate SHA-256 record hash over record contents + previous_hash
                record_hash = compute_record_hash(
                    record_id=record_id,
                    timestamp=timestamp,
                    event_type=event_type,
                    request_id=request_id,
                    action=action,
                    decision=decision,
                    details_json=details_json,
                    previous_hash=previous_hash,
                )

                # Commit final hash
                cursor.execute(
                    "UPDATE audit_chain SET record_hash = ? WHERE id = ?",
                    (record_hash, record_id),
                )
                conn.commit()

                return AuditRecord(
                    id=record_id,
                    timestamp=timestamp,
                    event_type=event_type,
                    request_id=request_id,
                    action=action,
                    decision=decision,
                    details=clean_details,
                    previous_hash=previous_hash,
                    record_hash=record_hash,
                )

    def get_records(self, limit: int = 100) -> List[AuditRecord]:
        """Retrieves audit entries ordered newest to oldest."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM audit_chain ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                rows = cursor.fetchall()
                records = []
                for row in rows:
                    records.append(
                        AuditRecord(
                            id=row["id"],
                            timestamp=row["timestamp"],
                            event_type=row["event_type"],
                            request_id=row["request_id"],
                            action=row["action"],
                            decision=row["decision"],
                            details=json.loads(row["details_json"]),
                            previous_hash=row["previous_hash"],
                            record_hash=row["record_hash"],
                        )
                    )
                return records

    def get_record_count(self) -> int:
        """Returns total number of audit records."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM audit_chain")
                row = cursor.fetchone()
                return row["count"] if row else 0

    def verify_chain(self) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Cryptographically verifies the integrity of the entire audit chain.

        Validates:
        1. Genesis record links to GENESIS_HASH.
        2. Every subsequent record's `previous_hash` matches previous record's `record_hash`.
        3. Every record's `record_hash` matches recomputed SHA-256 digest of its contents.

        Returns:
            (is_valid: bool, violations: List[Dict])
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM audit_chain ORDER BY id ASC")
                rows = cursor.fetchall()

                if not rows:
                    return True, []

                violations: List[Dict[str, Any]] = []
                expected_prev_hash = GENESIS_HASH
                prev_id = None

                for idx, row in enumerate(rows):
                    rec_id = row["id"]
                    stored_prev_hash = row["previous_hash"]
                    stored_hash = row["record_hash"]

                    # 1. Sequence gap check (detects record deletion / omission)
                    if prev_id is not None and rec_id != prev_id + 1:
                        violations.append({
                            "record_id": rec_id,
                            "error": f"Sequence Gap Detected (expected record ID {prev_id + 1}, found {rec_id})",
                            "expected_id": prev_id + 1,
                            "actual_id": rec_id,
                        })

                    # 2. Verify link to previous block
                    if stored_prev_hash != expected_prev_hash:
                        violations.append({
                            "record_id": rec_id,
                            "error": "Link Broken (previous_hash mismatch)",
                            "stored_prev_hash": stored_prev_hash,
                            "expected_prev_hash": expected_prev_hash,
                        })

                    # 3. Recompute current record hash
                    recalculated_hash = compute_record_hash(
                        record_id=rec_id,
                        timestamp=row["timestamp"],
                        event_type=row["event_type"],
                        request_id=row["request_id"],
                        action=row["action"],
                        decision=row["decision"],
                        details_json=row["details_json"],
                        previous_hash=stored_prev_hash,
                    )

                    if recalculated_hash != stored_hash:
                        violations.append({
                            "record_id": rec_id,
                            "error": "Tampered Record (content hash mismatch)",
                            "stored_hash": stored_hash,
                            "recalculated_hash": recalculated_hash,
                        })

                    # Advance expected previous hash and ID for next block
                    expected_prev_hash = stored_hash
                    prev_id = rec_id

                is_valid = len(violations) == 0
                return is_valid, violations

    def tamper_record_for_testing(self, record_id: int, new_decision: str) -> bool:
        """
        Simulates unauthorized database tampering (for security testing and demonstrations).
        Modifies a record's decision directly without recalculating its hash.
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE audit_chain SET decision = ? WHERE id = ?",
                    (new_decision, record_id),
                )
                conn.commit()
                return cursor.rowcount > 0

    def delete_record_for_testing(self, record_id: int) -> bool:
        """
        Simulates unauthorized deletion of a record to test chain integrity detection.
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM audit_chain WHERE id = ?", (record_id,))
                conn.commit()
                return cursor.rowcount > 0

    def swap_records_for_testing(self, id1: int, id2: int) -> bool:
        """
        Simulates unauthorized reordering/swapping of records to test order tamper detection.
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM audit_chain WHERE id = ?", (id1,))
                r1 = cursor.fetchone()
                cursor.execute("SELECT * FROM audit_chain WHERE id = ?", (id2,))
                r2 = cursor.fetchone()
                if not r1 or not r2:
                    return False

                # Swap non-ID fields between id1 and id2
                cursor.execute(
                    """
                    UPDATE audit_chain SET
                        timestamp = ?, event_type = ?, request_id = ?, action = ?,
                        decision = ?, details_json = ?, previous_hash = ?, record_hash = ?
                    WHERE id = ?
                    """,
                    (
                        r2["timestamp"], r2["event_type"], r2["request_id"], r2["action"],
                        r2["decision"], r2["details_json"], r2["previous_hash"], r2["record_hash"],
                        id1,
                    ),
                )
                cursor.execute(
                    """
                    UPDATE audit_chain SET
                        timestamp = ?, event_type = ?, request_id = ?, action = ?,
                        decision = ?, details_json = ?, previous_hash = ?, record_hash = ?
                    WHERE id = ?
                    """,
                    (
                        r1["timestamp"], r1["event_type"], r1["request_id"], r1["action"],
                        r1["decision"], r1["details_json"], r1["previous_hash"], r1["record_hash"],
                        id2,
                    ),
                )
                conn.commit()
                return True

    def reset_database(self):
        """Drops and recreates table (useful for test resets)."""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("DROP TABLE IF EXISTS audit_chain")
                conn.commit()
        self._init_db()
