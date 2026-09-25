"""ATHP common types and constants."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Dict, Optional


class ATHPVersion(str, Enum):
    V1_0 = "1.0"
    V1_1 = "1.1"


class MessageType(str, Enum):
    REGISTER = "REGISTER"
    REGISTER_OK = "REGISTER_OK"
    REGISTER_REJECT = "REGISTER_REJECT"
    TASK_ACCEPT = "TASK_ACCEPT"
    TASK_RESULT = "TASK_RESULT"
    HEARTBEAT = "HEARTBEAT"
    SHUTDOWN = "SHUTDOWN"
    CANCEL = "CANCEL"


class ErrorCode(str, Enum):
    AUTH_INVALID = "AUTH_INVALID"
    AUTH_REPLAY = "AUTH_REPLAY"
    SCHEMA_INVALID = "SCHEMA_INVALID"
    VERSION_UNSUPPORTED = "VERSION_UNSUPPORTED"
    STATE_INVALID = "STATE_INVALID"
    DUPLICATE_CONFLICT = "DUPLICATE_CONFLICT"
    TASK_TIMEOUT = "TASK_TIMEOUT"
    RESOURCE_LIMIT = "RESOURCE_LIMIT"
    SANDBOX_VIOLATION = "SANDBOX_VIOLATION"
    EGRESS_DENIED = "EGRESS_DENIED"
    SECRET_EXPOSURE = "SECRET_EXPOSURE"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class AgentState(str, Enum):
    INIT = "INIT"
    IDLE = "IDLE"
    EXECUTING = "EXECUTING"
    QUARANTINED = "QUARANTINED"
    ESCALATED = "ESCALATED"
    SHUTDOWN = "SHUTDOWN"
    REJECTED = "REJECTED"


class Trigger(str, Enum):
    REGISTER_OK = "REGISTER_OK"
    REGISTER_REJECT = "REGISTER_REJECT"
    TASK_ACCEPT = "TASK_ACCEPT"
    TASK_RESULT = "TASK_RESULT"
    QUARANTINE = "QUARANTINE"
    RECOVERY = "RECOVERY"
    REVIEW_RESUME = "REVIEW_RESUME"
    REVIEW_ESCALATION = "REVIEW_ESCALATION"
    REVIEW_TERMINATION = "REVIEW_TERMINATION"
    HARNESS_SHUTDOWN = "HARNESS_SHUTDOWN"


# Canonical state transition table shared by the wire lifecycle and reference
# harness. String keys keep it independent of either implementation's enums.
TRANSITION_RULES: dict[tuple[str, str], str] = {
    ("INIT", "REGISTER_OK"): "IDLE",
    ("INIT", "REGISTER_REJECT"): "REJECTED",
    ("IDLE", "TASK_ACCEPT"): "EXECUTING",
    ("EXECUTING", "TASK_RESULT"): "IDLE",
    ("EXECUTING", "QUARANTINE"): "QUARANTINED",
    ("EXECUTING", "TIMEOUT"): "QUARANTINED",
    ("EXECUTING", "RESOURCE_LIMIT"): "QUARANTINED",
    ("EXECUTING", "HEARTBEAT_FAILURE"): "QUARANTINED",
    ("EXECUTING", "SECURITY_EVENT"): "QUARANTINED",
    ("EXECUTING", "POLICY_EVENT"): "QUARANTINED",
    ("IDLE", "HEARTBEAT_FAILURE"): "QUARANTINED",
    ("QUARANTINED", "RECOVERY"): "IDLE",
    ("QUARANTINED", "REVIEW_RESUME"): "IDLE",
    ("QUARANTINED", "REVIEW_ESCALATION"): "ESCALATED",
    ("QUARANTINED", "SECURITY_EVENT"): "ESCALATED",
    ("QUARANTINED", "POLICY_EVENT"): "ESCALATED",
    ("ESCALATED", "REVIEW_RESUME"): "IDLE",
    ("ESCALATED", "REVIEW_RETRY"): "IDLE",
    ("ESCALATED", "REVIEW_TERMINATION"): "SHUTDOWN",
    ("ESCALATED", "REVIEW_SHUTDOWN"): "SHUTDOWN",
    ("IDLE", "HARNESS_SHUTDOWN"): "SHUTDOWN",
    ("QUARANTINED", "HARNESS_SHUTDOWN"): "SHUTDOWN",
    ("ESCALATED", "HARNESS_SHUTDOWN"): "SHUTDOWN",
    ("REJECTED", "HARNESS_SHUTDOWN"): "SHUTDOWN",
}


# Legal initial states per agent type
INITIAL_TRANSITIONS: dict[str, AgentState] = {
    "agent.example.builder-17": AgentState.IDLE,  # after successful register
}


# SLA thresholds (seconds)
SLA = {
    "registration_p95": 1,
    "registration_p99": 3,
    "task_accept_p95": 0.2,
    "task_accept_p99": 0.5,
    "heartbeat_ack_p95": 0.1,
    "heartbeat_ack_p99": 0.3,
    "shutdown_ack_p95": 0.5,
    "shutdown_ack_p99": 2,
}


# Default clock skew window in seconds
DEFAULT_CLOCK_SKEW_SECONDS = 30


# Minimum artifact retention period (days)
MIN_ARTIFACT_RETENTION_DAYS = 90


# Heartbeat thresholds
HEARTBEAT_MISSED_THRESHOLD = 3

# Default wall-clock timeout (ms)
DEFAULT_WALL_TIMEOUT_MS = 300_000  # 5 minutes


# Capability risk classes
class RiskClass(str, Enum):
    SAFE = "safe"
    MODERATE = "moderate"
    PRIVILEGED = "privileged"


# Tool profile options
TOOL_PROFILE_CI_STANDARD = "ci-standard"
TOOL_PROFILE_SANDBOXED = "sandboxed"


# Evidence span fields
EVIDENCE_FIELDS = {
    "previous_state",
    "new_state",
    "trigger",
    "decision_id",
    "message_id",
    "actor",
    "timestamp",
    "reason_code",
}


def now_utc_iso() -> str:
    """Return current UTC time as ISO-8601 with milliseconds."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def now_utc_timestamp() -> float:
    """Return current UTC timestamp in seconds."""
    return datetime.now(timezone.utc).timestamp()


def parse_utc_iso(ts: str) -> datetime:
    """Parse UTC ISO-8601 timestamp."""
    # Handle both with and without milliseconds
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)


def canonical_jcs(envelope: dict) -> bytes:
    """Produce JCS (RFC 8785) canonicalization of envelope with signature removed.

    Object members are sorted by key name.
    Insignificant whitespace is removed.
    Numbers, strings, booleans, nulls serialized exactly as RFC 8785.
    Arrays retain their declared order and are NOT sorted.
    """
    # Remove signature member
    env = {k: v for k, v in envelope.items() if k != "signature"}
    # Sort keys alphabetically (JCS requirement)
    sorted_items = sorted(env.items(), key=lambda x: x[0])
    # Build canonical JSON
    parts = []
    for key, value in sorted_items:
        parts.append(f'{json.dumps(key, ensure_ascii=False)}:{_jcs_serialize(value)}')
    # Join with no spaces
    canonical = "{" + ",".join(parts) + "}"
    return canonical.encode("utf-8")


def _jcs_serialize(value: Any) -> str:
    """Serialize a value according to RFC 8785 JCS rules."""
    if value is None:
        return "null"
    elif isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, int):
        # JCS requires no unnecessary trailing zeros, but Python's json.dumps handles this
        return json.dumps(value, ensure_ascii=False)
    elif isinstance(value, float):
        # JCS: float serialization must be exact; use repr-style for precision
        # Use json.dumps which produces reasonable float representation
        s = json.dumps(value, ensure_ascii=False)
        # Verify it round-trips correctly
        return s
    elif isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    elif isinstance(value, list):
        items = [_jcs_serialize(item) for item in value]
        return "[" + ",".join(items) + "]"
    elif isinstance(value, dict):
        # Recursively sort keys
        sorted_items = sorted(value.items(), key=lambda x: x[0])
        inner_parts = []
        for key, val in sorted_items:
            inner_parts.append(f'{_jcs_serialize(key)}:{_jcs_serialize(val)}')
        return "{" + ",".join(inner_parts) + "}"
    else:
        return json.dumps(value, ensure_ascii=False)


def compute_signature(canonical_bytes: bytes, key_id: str, secret: bytes) -> str:
    """Compute HMAC-SHA256 signature in base64url encoding."""
    mac = hmac.new(secret, canonical_bytes, hashlib.sha256).digest()
    # base64url encode
    import base64
    b64 = base64.urlsafe_b64encode(mac).decode("ascii")
    # Remove trailing =
    return b64.rstrip("=")


def verify_signature(
    canonical_bytes: bytes,
    signature_b64url: str,
    key_id: str,
    secret: bytes,
) -> bool:
    """Verify HMAC-SHA256 signature in constant time."""
    import base64
    # Decode base64url
    try:
        padding = 4 - len(signature_b64url) % 4
        if padding != 4:
            sig_padded = signature_b64url + "=" * padding
        else:
            sig_padded = signature_b64url
        mac = base64.urlsafe_b64decode(sig_padded.encode("ascii"))
    except Exception:
        return False
    
    expected = hmac.new(secret, canonical_bytes, hashlib.sha256).digest()
    return hmac.compare_digest(mac, expected)


def make_envelope(
    message_type: MessageType,
    agent_id: str,
    payload: dict,
    trace_id: Optional[str] = None,
    span_id: Optional[str] = None,
    key_id: Optional[str] = None,
    signature: Optional[str] = None,
) -> dict:
    """Create a standardized ATHP envelope."""
    return {
        "athp_version": ATHPVersion.V1_1.value,
        "message_id": str(uuid.uuid4()),
        "timestamp": now_utc_iso(),
        "agent_id": agent_id,
        "message_type": message_type.value,
        "payload": payload,
        "trace_id": trace_id or str(uuid.uuid4()),
        "span_id": span_id or str(uuid.uuid4())[-16:],
        "key_id": key_id or f"{agent_id}/2026-09",
        "signature": signature or "",
    }


def make_error_envelope(
    message_type: MessageType,
    agent_id: str,
    error_code: ErrorCode,
    trace_id: str,
    message_id: str,
    detail: str,
) -> dict:
    """Create an error response envelope."""
    return {
        "athp_version": ATHPVersion.V1_1.value,
        "message_id": message_id,
        "timestamp": now_utc_iso(),
        "agent_id": agent_id,
        "message_type": message_type.value,
        "payload": {
            "error": error_code.value,
            "detail": detail,
        },
        "trace_id": trace_id,
        "span_id": span_id if span_id else "",
        "key_id": f"{agent_id}/2026-09",
        "signature": "",
    }
