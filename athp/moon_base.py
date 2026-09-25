#!/usr/bin/env python3
"""ATHP Moon Base Edition - Reference harness + agent implementation.

RFC-0042 coverage: JCS signing, clock skew, replay/idempotency, version
negotiation, capability governance, lifecycle state machine with evidence
spans, quarantine/escalation/shutdown, reviewer decisions, sandbox policy
(deny-by-default), resource/timeout enforcement, restart-surviving dedup,
and reproducibility metadata.  Consumed by the conformance suite.
"""

import base64
import hashlib
import hmac
import inspect
import json
import logging
import os
import re
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("athp-moon-base")

ATHP_VERSION = "1.1"
CLOCK_SKEW_SECONDS = 30
HEARTBEAT_MISSED_THRESHOLD = 3
DEFAULT_WALL_TIMEOUT_MS = 300_000
GRACE_PERIOD_MS = 5_000


# ---------------------------------------------------------------------------
# 1. RFC 8785 JCS Canonicalization
# ---------------------------------------------------------------------------

def jcs_canonicalize(obj: Any) -> bytes:
    """Produce RFC 8785 JCS canonical output.
    - Object members sorted by canonicalized key bytes (arrays keep order).
    - No insignificant whitespace.
    """
    if obj is None:
        return b"null"
    if isinstance(obj, bool):
        return b"true" if obj else b"false"
    if isinstance(obj, (int, float)):
        return json.dumps(obj, separators=(",", ":")).encode("utf-8")
    if isinstance(obj, str):
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if isinstance(obj, list):
        parts = [jcs_canonicalize(item) for item in obj]
        return b"[" + b",".join(parts) + b"]"
    if isinstance(obj, dict):
        pairs = [(jcs_canonicalize(str(k)), jcs_canonicalize(v)) for k, v in obj.items()]
        pairs.sort(key=lambda p: p[0])
        inner = b",".join(k + b":" + v for k, v in pairs)
        return b"{" + inner + b"}"
    raise TypeError(f"Cannot canonicalize {type(obj).__name__}")


def jcs_sha256(obj: Any) -> str:
    """Content digest over JCS output (used for report artifact digests)."""
    data = obj if isinstance(obj, bytes) else jcs_canonicalize(obj)
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# 2. Types
# ---------------------------------------------------------------------------

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
    HEARTBEAT_ACK = "HEARTBEAT_ACK"
    SHUTDOWN = "SHUTDOWN"
    ERROR = "ERROR"


class AgentState(Enum):
    INIT = "INIT"
    IDLE = "IDLE"
    EXECUTING = "EXECUTING"
    QUARANTINED = "QUARANTINED"
    ESCALATED = "ESCALATED"
    REJECTED = "REJECTED"
    SHUTDOWN = "SHUTDOWN"


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


class ResultStatus(str, Enum):
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    QUARANTINED = "QUARANTINED"


class RiskClass(str, Enum):
    SAFE = "safe"
    MODERATE = "moderate"
    PRIVILEGED = "privileged"


class ReviewerDecision(str, Enum):
    RESUME = "RESUME"
    RETRY = "RETRY"
    SHUTDOWN = "SHUTDOWN"
    DENY = "DENY"


# Capability taxonomy (§13): name -> {version, risk_class, ops, profiles}
CAPABILITY_REGISTRY: Dict[str, dict] = {
    "readonly_repo": {"version": 1, "risk_class": RiskClass.SAFE,
                      "ops": ["repo.read"], "profiles": {"ci-standard", "sandboxed"}},
    "patch": {"version": 1, "risk_class": RiskClass.MODERATE,
              "ops": ["repo.read", "repo.write", "apply_patch"], "profiles": {"ci-standard"}},
    "tests": {"version": 1, "risk_class": RiskClass.SAFE,
              "ops": ["repo.read", "execute_tests"], "profiles": {"ci-standard", "sandboxed"}},
    "host.fs.write": {"version": 1, "risk_class": RiskClass.PRIVILEGED,
                      "ops": ["host.write"], "profiles": set()},
}

# Tool directory: tool name -> capability name (§14 tool_grants may name tools)
TOOL_DIRECTORY: Dict[str, str] = {
    "repo.read": "readonly_repo",
    "repo.write": "patch",
    "tests.execute": "tests",
    "patch.apply": "patch",
    "host.fs.write": "host.fs.write",
}

AUTHORIZED_ROLES: Dict[str, Set[str]] = {
    RiskClass.SAFE: {"ci-operator", "security-lead"},
    RiskClass.MODERATE: {"ci-operator", "security-lead"},
    RiskClass.PRIVILEGED: {"security-lead"},
}

TRIGGERS = {
    "REGISTER_OK", "REGISTER_REJECT", "TASK_ACCEPT", "TASK_RESULT",
    "TIMEOUT", "RESOURCE_LIMIT", "HEARTBEAT_FAILURE",
    "SECURITY_EVENT", "POLICY_EVENT", "RECOVERY",
    "REVIEW_RESUME", "REVIEW_RETRY", "REVIEW_SHUTDOWN", "HARNESS_SHUTDOWN",
}

# (previous_state, trigger) -> new_state  (§11 required transitions)
TRANSITION_RULES: Dict[Tuple[AgentState, str], AgentState] = {
    (AgentState.INIT, "REGISTER_OK"): AgentState.IDLE,
    (AgentState.INIT, "REGISTER_REJECT"): AgentState.REJECTED,
    (AgentState.IDLE, "TASK_ACCEPT"): AgentState.EXECUTING,
    (AgentState.EXECUTING, "TASK_RESULT"): AgentState.IDLE,
    (AgentState.EXECUTING, "TIMEOUT"): AgentState.QUARANTINED,
    (AgentState.EXECUTING, "RESOURCE_LIMIT"): AgentState.QUARANTINED,
    (AgentState.EXECUTING, "HEARTBEAT_FAILURE"): AgentState.QUARANTINED,
    (AgentState.EXECUTING, "SECURITY_EVENT"): AgentState.QUARANTINED,
    (AgentState.EXECUTING, "POLICY_EVENT"): AgentState.QUARANTINED,
    (AgentState.IDLE, "HEARTBEAT_FAILURE"): AgentState.QUARANTINED,
    (AgentState.QUARANTINED, "RECOVERY"): AgentState.IDLE,
    (AgentState.QUARANTINED, "REVIEW_RESUME"): AgentState.IDLE,
    (AgentState.QUARANTINED, "SECURITY_EVENT"): AgentState.ESCALATED,
    (AgentState.QUARANTINED, "POLICY_EVENT"): AgentState.ESCALATED,
    (AgentState.ESCALATED, "REVIEW_RESUME"): AgentState.IDLE,
    (AgentState.ESCALATED, "REVIEW_RETRY"): AgentState.IDLE,
    (AgentState.ESCALATED, "REVIEW_SHUTDOWN"): AgentState.SHUTDOWN,
    (AgentState.IDLE, "HARNESS_SHUTDOWN"): AgentState.SHUTDOWN,
    (AgentState.QUARANTINED, "HARNESS_SHUTDOWN"): AgentState.SHUTDOWN,
    (AgentState.ESCALATED, "HARNESS_SHUTDOWN"): AgentState.SHUTDOWN,
    (AgentState.REJECTED, "HARNESS_SHUTDOWN"): AgentState.SHUTDOWN,
}


# ---------------------------------------------------------------------------
# 3. Sandbox policy (§6 - deny-by-default)
# ---------------------------------------------------------------------------

@dataclass
class SandboxPolicy:
    """Deny-by-default policy attached to a tool profile."""
    profile: str = "ci-standard"
    allow_host_fs: bool = False
    allow_host_network: bool = False
    allow_privileged_syscalls: bool = False
    allow_undeclared_devices: bool = False
    allow_egress: Set[str] = field(default_factory=set)  #  "host" or "host:port"
    repo_ro_mounts: Tuple[str, ...] = ("/repo",)
    repo_rw_mounts: Tuple[str, ...] = ()
    secret_patterns: Tuple[str, ...] = (r"sk-[A-Za-z0-9]{20,}", r"AKIA[0-9A-Z]{16}")

    def egress_allowed(self, host: str) -> bool:
        if not host:
            return True
        return host in self.allow_egress

    def scan_for_secrets(self, text: str) -> List[str]:
        found = []
        for pat in self.secret_patterns:
            if re.search(pat, text or ""):
                found.append(pat)
        return found


PROFILE_POLICIES: Dict[str, SandboxPolicy] = {
    "ci-standard": SandboxPolicy(profile="ci-standard",
                                 allow_egress={
                                     "pypi.org", "files.pythonhosted.org", "github.com:443",
                                     "git.example.internal:9418"}),
    "sandboxed": SandboxPolicy(profile="sandboxed",
                               allow_egress=set()),
}


# ---------------------------------------------------------------------------
# 4. Evidence and agent context
# ---------------------------------------------------------------------------

@dataclass
class EvidenceSpan:
    """Immutable evidence span for a state transition (§11.4)."""
    previous_state: AgentState
    new_state: AgentState
    trigger: str
    decision_id: str
    agent_id: str
    message_id: str = ""
    actor: str = "harness"
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%S.000Z"))
    reason_code: str = "NONE"

    def to_dict(self) -> dict:
        return {
            "previous_state": self.previous_state.value,
            "new_state": self.new_state.value,
            "trigger": self.trigger,
            "decision_id": self.decision_id,
            "agent_id": self.agent_id,
            "message_id": self.message_id,
            "actor": self.actor,
            "timestamp": self.timestamp,
            "reason_code": self.reason_code,
        }


@dataclass
class AgentContext:
    """Agent state tracked by the harness (§3/§12)."""
    agent_id: str
    state: AgentState = AgentState.INIT
    session_id: Optional[str] = None
    registered_version: Optional[str] = None
    effective_capabilities: List[str] = field(default_factory=list)
    tool_profile: str = "ci-standard"
    heartbeat_count: int = 0
    missed_heartbeats: int = 0
    quarantine_reason: str = ""

    def reset_heartbeat_counter(self) -> None:
        self.missed_heartbeats = 0


@dataclass
class ReviewerDecisionRecord:
    """Append-only signed reviewer decision (§16)."""
    decision_id: str
    agent_id: str
    reviewer_identity: str
    role: str
    decision: str
    scope: dict
    findings: str
    evidence_refs: List[str]
    timestamp: str
    expiration: str
    signature: str = ""


# ---------------------------------------------------------------------------
# 5. Harness
# ---------------------------------------------------------------------------

class Harness:
    """ATHP reference harness enforcing lifecycle, signing, and policy."""

    def __init__(self, hmac_secret: Optional[bytes] = None,
                 persist_path: Optional[str] = None,
                 clock_skew_seconds: int = CLOCK_SKEW_SECONDS,
                 quarantine_on_timeout: bool = False,
                 executor: Optional[Callable[["Harness", dict], dict]] = None,
                 policy_overrides: Optional[Dict[str, SandboxPolicy]] = None,
                 reviewer_roles: Optional[Dict[str, str]] = None):
        self.agents: Dict[str, AgentContext] = {}
        self.seen_messages: Dict[str, dict] = {}          # dedup key -> stored response
        self.idempotency: Dict[str, dict] = {}            # task dedup key -> stored result
        self._register_outcomes: Dict[str, dict] = {}     # agent_id -> REGISTER_OK envelope
        self.hmac_keys: Dict[str, bytes] = {}
        self.trusted_keys: Set[str] = set()               # session key_ids provisioned at REGISTER
        self._master_secret: Optional[bytes] = hmac_secret
        self.evidence_log: List[EvidenceSpan] = []
        self.decisions: List[ReviewerDecisionRecord] = []
        self.reviewer_roles = dict(reviewer_roles or {})
        self.persist_path = persist_path
        self.clock_skew_seconds = clock_skew_seconds
        self.quarantine_on_timeout = quarantine_on_timeout
        self.executor = executor or self._default_execute
        self.policies: Dict[str, SandboxPolicy] = dict(PROFILE_POLICIES)
        if policy_overrides:
            self.policies.update(policy_overrides)
        self.uid_counter = 0
        self._lock = threading.RLock()

        if persist_path and not hmac_secret:
            raise ValueError("persistence requires a server-side HMAC secret")
        if hmac_secret is not None:
            self.hmac_keys["agent.default/2026-09"] = hmac_secret
        if persist_path:
            self._load_persistence()

    # ---- Signing ----------------------------------------------------------

    def _key_for(self, key_id: str) -> Optional[bytes]:
        """Only provisioned key_ids resolve to keys (§4.2: key_id registry)."""
        if key_id in self.hmac_keys:
            return self.hmac_keys[key_id]
        if key_id in self.trusted_keys and self._master_secret is not None:
            return hashlib.sha256(self._master_secret + key_id.encode("utf-8")).digest()
        return None

    def _canonical_envelope(self, envelope: dict) -> bytes:
        env = {k: v for k, v in envelope.items() if k != "signature"}
        return jcs_canonicalize(env)

    def _compute_hmac(self, canonical: bytes, key_id: str) -> bytes:
        key = self._key_for(key_id)
        if key is None:
            raise ValueError(f"Unknown key_id: {key_id}")
        return hmac.new(key, canonical, hashlib.sha256).digest()

    def _base64url(self, data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

    def sign_envelope(self, envelope: dict) -> dict:
        signed = dict(envelope)
        key_id = envelope.get("key_id", "")
        if self._key_for(key_id) is not None:
            canonical = self._canonical_envelope(signed)
            signed["signature"] = self._base64url(self._compute_hmac(canonical, key_id))
        return signed

    def verify_signature(self, envelope: dict) -> bool:
        sig_b64url = envelope.get("signature", "")
        key_id = envelope.get("key_id", "")
        try:
            sig_bytes = base64.urlsafe_b64decode(sig_b64url + "==")
        except Exception:
            return False
        try:
            canonical = self._canonical_envelope(envelope)
            expected = self._compute_hmac(canonical, key_id)
        except ValueError:
            return False
        return hmac.compare_digest(expected, sig_bytes)

    def sign_record(self, record: dict) -> str:
        return self._base64url(self._compute_hmac(jcs_canonicalize(record), "agent.default/2026-09"))

    def verify_record(self, record: ReviewerDecisionRecord) -> bool:
        body = dict(record.__dict__)
        sig = body.pop("signature", "")
        try:
            return hmac.compare_digest(self._compute_hmac(jcs_canonicalize(body), "agent.default/2026-09"),
                                       base64.urlsafe_b64decode(sig + "=="))
        except Exception:
            return False

    # ---- Persistence (restart-surviving dedup, §12) ------------------------

    def _dedup_file(self, name: str) -> str:
        return os.path.join(self.persist_path, name)

    def _load_persistence(self) -> None:
        for fname, store in (("seen_messages.json", self.seen_messages),
                             ("idempotency.json", self.idempotency)):
            path = self._dedup_file(fname)
            if os.path.exists(path):
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        wrapper = json.load(f)
                    data = wrapper.get("data")
                    signature = wrapper.get("hmac", "")
                    expected = self._persistence_mac(data)
                    if not isinstance(data, dict) or not hmac.compare_digest(signature, expected):
                        raise ValueError("persistence HMAC mismatch")
                    store.update(data)
                    logger.info("Loaded %d dedup records from %s", len(store), path)
                except Exception as exc:  # pragma: no cover
                    raise RuntimeError(f"refusing corrupt or unsigned persistence file {path}") from exc

    def _persistence_mac(self, data: dict) -> str:
        if not self._master_secret:
            raise RuntimeError("persistence signing key is unavailable")
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return base64.urlsafe_b64encode(
            hmac.new(self._master_secret, encoded, hashlib.sha256).digest()
        ).decode("ascii").rstrip("=")

    def _write_signed_persistence(self, path: str, data: dict) -> None:
        wrapper = {"data": data, "hmac": self._persistence_mac(data)}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(wrapper, f, sort_keys=True, separators=(",", ":"))

    def _save_persistence(self) -> None:
        if not self.persist_path:
            return
        os.makedirs(self.persist_path, exist_ok=True)
        self._write_signed_persistence(self._dedup_file("seen_messages.json"), self.seen_messages)
        self._write_signed_persistence(self._dedup_file("idempotency.json"), self.idempotency)
        with open(self._dedup_file("evidence.jsonl"), "w", encoding="utf-8") as f:
            for span in self.evidence_log:
                f.write(json.dumps(span.to_dict()) + "\n")
        with open(self._dedup_file("decisions.jsonl"), "w", encoding="utf-8") as f:
            for rec in self.decisions:
                f.write(json.dumps(rec.__dict__) + "\n")

    # ---- Reproducibility metadata (§8) ------------------------------------

    def metadata(self) -> dict:
        try:
            src = inspect.getsourcefile(Harness) or __file__
            with open(src, "rb") as f:
                build_digest = hashlib.sha256(f.read()).hexdigest()
        except Exception:
            build_digest = "unavailable"
        return {
            "athp_version": ATHP_VERSION,
            "harness_build_digest": build_digest,
            "agent_implementation": "athp.moon_base.Agent; HTTP gates: athp.server",
            "python": {"version": os.sys.version.split()[0], "implementation": os.sys.implementation.name},
            "os": {"name": os.name, "platform": os.sys.platform},
            "runner": {"isolation": "simulated", "mechanism": "none", "version": "1.0"},
            "clock_skew_seconds": self.clock_skew_seconds,
            "heartbeat_missed_threshold": HEARTBEAT_MISSED_THRESHOLD,
            "retention_days": 90,
            "seed": "none",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        }

    # ---- Agent lifecycle ---------------------------------------------------

    def get_agent(self, agent_id: str) -> AgentContext:
        if agent_id not in self.agents:
            self.agents[agent_id] = AgentContext(agent_id=agent_id)
        return self.agents[agent_id]

    def _new_decision_id(self) -> str:
        self.uid_counter += 1
        return f"dec-{uuid.uuid4()}"

    # ---- State machine (transition informed by trigger, §11) -----------------

    def transition(self, agent_id: str, trigger: str, *,
                   message_id: str = "", actor: str = "harness",
                   reason_code: str = "NONE") -> Optional[EvidenceSpan]:
        """Attempt `trigger` on the agent's current state.

        Legal outcome is taken from TRANSITION_RULES.  Unknown triggers,
        illegal transitions, and missing/unknown states -> None (STATE_INVALID).
        """
        agent = self.get_agent(agent_id)
        prev = agent.state
        if trigger not in TRIGGERS or agent.state not in AgentState:
            return None
        key = (prev, trigger)
        new_state = TRANSITION_RULES.get(key)
        if new_state is None:
            return None
        if trigger == "RECOVERY":
            if not self.perform_health_checks(agent_id):
                return None
            if not self._has_valid_recovery_decision(agent_id, actor, message_id):
                return None

        span = EvidenceSpan(
            previous_state=prev,
            new_state=new_state,
            trigger=trigger,
            decision_id=self._new_decision_id(),
            agent_id=agent_id,
            message_id=message_id,
            actor=actor,
            reason_code=reason_code,
        )
        agent.state = new_state
        self.evidence_log.append(span)
        self._save_persistence()
        return span

    def _has_valid_recovery_decision(
        self, agent_id: str, reviewer_identity: str, decision_id: str
    ) -> bool:
        """Require a signed, registered reviewer RESUME decision for RECOVERY."""
        if not decision_id or self.reviewer_roles.get(reviewer_identity) is None:
            return False
        agent = self.get_agent(agent_id)
        risk = RiskClass.PRIVILEGED if agent.quarantine_reason == "RESOURCE_LIMIT" else \
            (RiskClass.MODERATE if agent.quarantine_reason in (
                "SECRET_EXPOSURE", "SANDBOX_VIOLATION", "EGRESS_DENIED"
            ) else RiskClass.SAFE)
        role = self.reviewer_roles[reviewer_identity]
        if role not in AUTHORIZED_ROLES.get(risk, set()):
            return False
        return any(
            record.decision_id == decision_id
            and record.agent_id == agent_id
            and record.reviewer_identity == reviewer_identity
            and record.role == role
            and record.decision == ReviewerDecision.RESUME.value
            and self.verify_record(record)
            for record in self.decisions
        )

    # ---- Message envelope helpers ------------------------------------------

    def _reply(self, envelope: dict, message_type: MessageType, payload: dict,
               sign: bool = True) -> dict:
        resp = {
            "athp_version": envelope.get("athp_version", ATHP_VERSION),
            "message_id": str(uuid.uuid4()),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "agent_id": envelope.get("agent_id", ""),
            "message_type": message_type.value,
            "payload": payload,
            "trace_id": envelope.get("trace_id", ""),
            "span_id": envelope.get("span_id", ""),
            "key_id": envelope.get("key_id", "agent.default/2026-09"),
            "signature": "",
        }
        return self.sign_envelope(resp) if sign else resp

    def _error(self, envelope: dict, code: ErrorCode, detail: str,
               retryable: bool = False, message_type: MessageType = MessageType.ERROR) -> dict:
        payload = {
            "code": code.value,
            "retryable": retryable,
            "in_reply_to": envelope.get("message_id", ""),
            "trace_id": envelope.get("trace_id", ""),
            "detail": detail,
        }
        resp = self._reply(envelope, message_type, payload)
        # Errors never echo secrets; detail is the only human text and is ours.
        return resp

    def _message_fingerprint(self, envelope: dict) -> str:
        """Content fingerprint of a signed request (signature excluded).

        A true replay is byte-identical; a conflicting duplicate differs.
        """
        return jcs_sha256(self._canonical_envelope(envelope))

    def _cache_message(self, envelope: dict, response: dict) -> None:
        agent_id = envelope.get("agent_id", "")
        if agent_id and envelope.get("message_id"):
            sess = envelope.get("session_id") or "sess"  # session under which request was sent
            key = f"{agent_id}\u241f{sess}\u241f{envelope['message_id']}"
            self.seen_messages[key] = {"request": self._message_fingerprint(envelope),
                                       "response": response}
            self._save_persistence()

    def _dedup_key(self, agent_id: str, idempotency_key: str) -> str:
        return f"{agent_id}\u241f{idempotency_key}"

    # ---- Clock skew (§4.1) ---------------------------------------------------

    def _within_skew(self, timestamp_str: Any) -> bool:
        if not isinstance(timestamp_str, str):
            return False
        try:
            t = time.strptime(timestamp_str.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S.%f+0000")
            msg_time = time.mktime(t)
        except ValueError:
            try:
                t = time.strptime(timestamp_str.replace("Z", "+0000"), "%Y-%m-%dT%H:%M:%S+0000")
                msg_time = time.mktime(t)
            except ValueError:
                return False
        return abs(time.time() - msg_time) <= self.clock_skew_seconds

    # ---- Main dispatch (§4) ----------------------------------------------------

    def handle_message(self, envelope: dict) -> dict:
        """Process an ATHP envelope and return a response envelope."""
        with self._lock:
            return self._handle_message_locked(envelope)

    def _handle_message_locked(self, envelope: dict) -> dict:
        if not isinstance(envelope, dict):
            return {"message_type": MessageType.ERROR.value,
                    "payload": {"code": ErrorCode.SCHEMA_INVALID.value, "retryable": False,
                                "detail": "Envelope is not a JSON object"}}

        try:
            msg_type = MessageType(str(envelope.get("message_type", "")))
        except ValueError:
            return self._error(envelope, ErrorCode.SCHEMA_INVALID,
                               f"Unknown message type: {envelope.get('message_type')!r}")

        # 1) Required envelope members (§4.1)
        for req in ("athp_version", "message_id", "timestamp", "agent_id",
                    "payload", "trace_id", "span_id", "key_id", "signature"):
            if req not in envelope:
                return self._error(envelope, ErrorCode.SCHEMA_INVALID,
                                   f"Missing required envelope field: {req}")

        agent_id = envelope["agent_id"]
        message_id = envelope["message_id"]

        # 2) Replay protection first: an already-recorded message returns its
        #    stored outcome without re-validation (§4.4) and skips skew/signature.
        agent_context = self.agents.get(agent_id)
        if agent_context is not None and agent_context.session_id:
            expected_key_id = f"{agent_id}/2026-09"
            if (envelope.get("session_id") != agent_context.session_id
                    or envelope.get("key_id") != expected_key_id):
                return self._error(envelope, ErrorCode.AUTH_INVALID,
                                   "Registered agent session/key binding mismatch")
        if agent_id and message_id:
            sess = envelope.get("session_id") or "sess"
            key = f"{agent_id}\u241f{sess}\u241f{message_id}"
            entry = self.seen_messages.get(key)
            if entry is not None:
                if msg_type == MessageType.TASK_ACCEPT and agent_context is not None \
                        and agent_context.state != AgentState.IDLE:
                    return self._error(envelope, ErrorCode.STATE_INVALID,
                                       "Agent state does not permit cached task replay")
                if entry["request"] != self._message_fingerprint(envelope):
                    # Same dedup key, different content: conflicting duplicate (§12).
                    logger.info("Conflicting duplicate for %s", message_id)
                    return self._error(envelope, ErrorCode.DUPLICATE_CONFLICT,
                                       "Duplicate message_id with conflicting content",
                                       retryable=False)
                logger.info("Replay: returning cached outcome for %s", message_id)
                return entry["response"]

        # 3) Clock skew (§4.1): reject outside window.
        if not self._within_skew(envelope.get("timestamp", "")):
            return self._error(envelope, ErrorCode.AUTH_REPLAY, "Timestamp outside clock-skew window",
                               retryable=True)

        # 4) Signature (§4.2): HMAC-SHA256 over JCS, constant time.
        if not self.verify_signature(envelope):
            return self._error(envelope, ErrorCode.AUTH_INVALID, "Invalid or missing signature")

        # 5) Session version must equal negotiated version (§12).
        agent = self.get_agent(agent_id)
        if agent.session_id and agent.registered_version:
            if envelope.get("athp_version") != agent.registered_version:
                return self._error(envelope, ErrorCode.VERSION_UNSUPPORTED,
                                   "Message version does not match negotiated session version")

        # 6) Route
        if msg_type == MessageType.REGISTER:
            return self._handle_register(envelope)
        if msg_type == MessageType.TASK_ACCEPT:
            return self._handle_task_accept(envelope)
        if msg_type == MessageType.HEARTBEAT:
            return self._handle_heartbeat(envelope)
        if msg_type == MessageType.SHUTDOWN:
            return self._handle_shutdown(envelope)
        return self._error(envelope, ErrorCode.SCHEMA_INVALID,
                           f"Unsupported message type: {msg_type.value}")

    # ---- REGISTER (§4.3, §12, §13) --------------------------------------------

    def _handle_register(self, envelope: dict) -> dict:
        agent_id = envelope["agent_id"]
        payload = envelope.get("payload", {})
        agent = self.get_agent(agent_id)

        # Replayed/duplicate registration under an active session (§12).
        if agent.session_id and agent.state in (AgentState.IDLE, AgentState.EXECUTING):
            stored = self._register_outcomes.get(agent_id)
            if stored is not None:
                logger.info("Active session for %s: returning stored REGISTER_OK", agent_id)
                return stored
        if agent.state in (AgentState.QUARANTINED, AgentState.ESCALATED):
            return self._error(envelope, ErrorCode.STATE_INVALID,
                               f"Agent is {agent.state.value}; recovery/decision required before re-registration")

        supported = payload.get("supported_versions", [])
        declared_caps = payload.get("capabilities", [])
        resource_limits = payload.get("resource_limits", {})
        tool_profile = payload.get("tool_profile", "ci-standard")

        # Version negotiation (§4.3): highest mutually supported.
        harness_versions = [ATHPVersion.V1_1, ATHPVersion.V1_0]
        selected = next((v.value for v in harness_versions if v.value in supported), None)
        if selected is None:
            reject = self._error(envelope, ErrorCode.VERSION_UNSUPPORTED,
                                 f"No compatible version (agent={supported}, harness=[1.0, 1.1])",
                                 message_type=MessageType.REGISTER_REJECT)
            self.transition(agent_id, "REGISTER_REJECT", message_id=envelope["message_id"],
                            actor="harness", reason_code="VERSION_UNSUPPORTED")
            return reject

        # Capability governance (§13): declared are requests, not authority.
        if tool_profile not in self.policies:
            reject = self._error(envelope, ErrorCode.SCHEMA_INVALID,
                                 f"Unknown tool profile: {tool_profile}",
                                 message_type=MessageType.REGISTER_REJECT)
            self.transition(agent_id, "REGISTER_REJECT", message_id=envelope["message_id"],
                            actor="harness", reason_code="SCHEMA_INVALID")
            return reject
        effective = []
        for cap in declared_caps:
            spec = CAPABILITY_REGISTRY.get(cap)
            if spec is None:
                reject = self._error(envelope, ErrorCode.SCHEMA_INVALID,
                                     f"Unknown capability: {cap}",
                                     message_type=MessageType.REGISTER_REJECT)
                self.transition(agent_id, "REGISTER_REJECT", message_id=envelope["message_id"],
                                actor="harness", reason_code="SCHEMA_INVALID")
                return reject
            if tool_profile not in spec["profiles"]:
                reject = self._error(envelope, ErrorCode.SCHEMA_INVALID,
                                     f"Capability {cap} incompatible with profile {tool_profile}",
                                     message_type=MessageType.REGISTER_REJECT)
                self.transition(agent_id, "REGISTER_REJECT", message_id=envelope["message_id"],
                                actor="harness", reason_code="SCHEMA_INVALID")
                return reject
            effective.append(cap)

        session_id = f"session-{agent_id}-{uuid.uuid4()}"
        register_ok = self._reply(envelope, MessageType.REGISTER_OK, {
            "selected_version": selected,
            "heartbeat_interval_ms": 5000,
            "timeout_policy": {
                "default_wall_timeout_ms": DEFAULT_WALL_TIMEOUT_MS,
                "max_cpu_millis": resource_limits.get("cpu_millis", 2000),
                "max_memory_mb": resource_limits.get("memory_mb", 4096),
            },
            "tool_profile": tool_profile,
            "effective_capabilities": effective,
            "server_nonce": str(uuid.uuid4()),
        })
        register_ok["session_id"] = session_id
        register_ok = self.sign_envelope(register_ok)  # sign AFTER session_id (wire-inclusive)

        span = self.transition(agent_id, "REGISTER_OK", message_id=envelope["message_id"])
        if span:
            agent.session_id = session_id
            agent.registered_version = selected
            agent.effective_capabilities = effective
            agent.tool_profile = tool_profile
            self.trusted_keys.add(f"{agent_id}/2026-09")  # provision the session key

        self._register_outcomes[agent_id] = register_ok
        self._cache_message(envelope, register_ok)
        return register_ok

    # ---- Policy enforcement (§6) --------------------------------------------------

    def _resolve_grants(self, tool_grants: List[str]) -> Set[str]:
        """Map granted tool/capability names to the capabilities they imply."""
        resolved = set()
        for grant in tool_grants:
            if grant in CAPABILITY_REGISTRY:
                resolved.add(grant)
            elif grant in TOOL_DIRECTORY:
                resolved.add(TOOL_DIRECTORY[grant])
        return resolved

    def _enforce_policy(self, spec: dict, tool_grants: List[str],
                        effective_caps: List[str], profile: str) -> Tuple[Optional[str], str]:
        """Return (None, '') if permitted, else (error_code, detail).

        Deny-by-default: a tool invocation is only allowed when its capability,
        egress, and filesystem use are explicitly permitted.
        """
        policy = self.policies.get(profile, SandboxPolicy(profile=profile))
        granted = self._resolve_grants(tool_grants)
        caps = set(effective_caps)
        for tool in spec.get("tool_uses", []):
            cap = tool.get("capability")
            if cap not in granted or cap not in caps:
                return ErrorCode.SANDBOX_VIOLATION.value, f"Tool uses ungranted capability {cap!r}"
            cap_spec = CAPABILITY_REGISTRY[cap]
            egress = tool.get("egress") or []
            for host in egress:
                if not policy.egress_allowed(host):
                    return ErrorCode.EGRESS_DENIED.value, f"Network egress denied to {host}"
            for op in tool.get("fs", []):
                if op not in cap_spec["ops"]:
                    return ErrorCode.SANDBOX_VIOLATION.value, f"Capability {cap} forbids op {op}"
                if op == "repo.read" and "/repo" in policy.repo_ro_mounts:
                    continue
                if op == "repo.write" and "/repo" in policy.repo_rw_mounts:
                    continue
                if op == "host.write" and policy.allow_host_fs:
                    continue
                return ErrorCode.SANDBOX_VIOLATION.value, f"File access denied: {op}"
            if tool.get("privileged"):
                return ErrorCode.SANDBOX_VIOLATION.value, "Privileged syscall denied"
            if tool.get("device"):
                return ErrorCode.SANDBOX_VIOLATION.value, "Undeclared device access denied"
            if tool.get("exposes_secret"):
                return ErrorCode.SECRET_EXPOSURE.value, "Secret exposure in tool result"
            for pat in policy.scan_for_secrets(tool.get("result_text", "")):
                return ErrorCode.SECRET_EXPOSURE.value, f"Secret pattern {pat} in result"
        return None, ""

    # ---- TASK_ACCEPT (§14, §15) ---------------------------------------------------

    def _handle_task_accept(self, envelope: dict) -> dict:
        agent_id = envelope["agent_id"]
        payload = envelope.get("payload", {})
        agent = self.get_agent(agent_id)

        task_id = payload.get("task_id", "")
        idempotency_key = payload.get("idempotency_key", "")

        # §14 required members
        if not task_id or not idempotency_key:
            return self._error(envelope, ErrorCode.SCHEMA_INVALID,
                               "task_id and idempotency_key are required")

        # §4.4 duplicate task: same (agent, idempotency_key) returns stored result or
        # is rejected as a conflict; it MUST NOT execute twice.  Comparison is on
        # task *content*: a retry may legitimately carry a new message_id/timestamp.
        dedup_key = self._dedup_key(agent_id, idempotency_key)
        payload_fp = jcs_sha256(payload)
        stored = self.idempotency.get(dedup_key)
        if stored is not None:
            if agent.state != AgentState.IDLE or not agent.session_id:
                return self._error(envelope, ErrorCode.STATE_INVALID,
                                   "Agent state does not permit idempotent task replay")
            if stored["request"] != payload_fp:
                return self._error(envelope, ErrorCode.DUPLICATE_CONFLICT,
                                   "Same idempotency_key with conflicting task payload",
                                   retryable=False)
            logger.info("Task idempotency hit for %s/%s", agent_id, idempotency_key)
            return self._reply(envelope, MessageType.TASK_RESULT, stored["result"])

        # §11 invariant 2/3: only IDLE with a valid session executes.
        if agent.state != AgentState.IDLE or not agent.session_id:
            return self._error(envelope, ErrorCode.STATE_INVALID,
                               f"Agent state is {agent.state.value}; only IDLE with a session may execute")

        requested_profile = payload.get("sandbox_profile")
        if requested_profile is not None and requested_profile != agent.tool_profile:
            return self._error(
                envelope, ErrorCode.SANDBOX_VIOLATION,
                "Task sandbox_profile must match the registered tool_profile",
            )

        # §13 tool grants must be within the effective capability set.
        granted_caps = self._resolve_grants(payload.get("tool_grants", []))
        for cap in granted_caps:
            if cap not in agent.effective_capabilities:
                return self._error(envelope, ErrorCode.SANDBOX_VIOLATION,
                                   f"tool_grants references capability {cap!r} not granted this session",
                                   retryable=False)

        span = self.transition(agent_id, "TASK_ACCEPT", message_id=envelope["message_id"])
        if span is None:
            return self._error(envelope, ErrorCode.STATE_INVALID, "Illegal IDLE->EXECUTING transition")

        budget = payload.get("resource_budget", {})
        wall_timeout_ms = int(budget.get("wall_timeout_ms", DEFAULT_WALL_TIMEOUT_MS))
        cpu_budget = int(budget.get("cpu_millis", 2000))
        mem_budget = int(budget.get("memory_mb", 4096))

        started = time.monotonic()
        spec = dict(payload)
        try:
            # Apply the registered profile before invoking any executor, including
            # custom executors that do not call the reference policy helper.
            policy_code, policy_detail = self._enforce_policy(
                spec, payload.get("tool_grants", []),
                agent.effective_capabilities, agent.tool_profile,
            )
            if policy_code:
                outcome = {"status": ResultStatus.QUARANTINED.value,
                           "error_code": policy_code, "detail": policy_detail,
                           "exit_code": 1}
            else:
                outcome = self.executor(self, spec)
        except Exception as exc:  # oracle / executor crash
            outcome = {"status": ResultStatus.FAILED.value,
                       "error_code": ErrorCode.INTERNAL_ERROR.value,
                       "detail": f"executor error: {type(exc).__name__}"}
        elapsed_ms = int((time.monotonic() - started) * 1000)

        # Security/resource policy is enforced by the executor path; here we
        # classify timeouts and budgets.
        status = str(outcome.get("status", ResultStatus.FAILED.value))
        error_code = outcome.get("error_code")

        # Wall-clock timeout (§15)
        timed_out = elapsed_ms > wall_timeout_ms
        if timed_out:
            status = ResultStatus.TIMED_OUT.value
            error_code = ErrorCode.TASK_TIMEOUT.value

        resource_usage = outcome.get("resource_usage", {})
        over_resource = (resource_usage.get("cpu_ms", 0) > cpu_budget
                         or resource_usage.get("peak_memory_mb", 0) > mem_budget)
        if over_resource:
            status = ResultStatus.QUARANTINED.value
            error_code = ErrorCode.RESOURCE_LIMIT.value

        if error_code in (ErrorCode.SANDBOX_VIOLATION.value, ErrorCode.EGRESS_DENIED.value,
                          ErrorCode.SECRET_EXPOSURE.value):
            # §15: security-related violation quarantines immediately.
            status = ResultStatus.QUARANTINED.value
            trigger = "SECURITY_EVENT"
            self.transition(agent_id, trigger, message_id=envelope["message_id"],
                            actor="harness", reason_code=error_code)
            agent.quarantine_reason = error_code
        elif error_code == ErrorCode.RESOURCE_LIMIT.value:
            self.transition(agent_id, "RESOURCE_LIMIT", message_id=envelope["message_id"],
                            actor="harness", reason_code="RESOURCE_LIMIT")
            agent.quarantine_reason = "RESOURCE_LIMIT"
        elif timed_out:
            if self.quarantine_on_timeout:
                self.transition(agent_id, "TIMEOUT", message_id=envelope["message_id"],
                                actor="harness", reason_code="TASK_TIMEOUT")
                agent.quarantine_reason = "TASK_TIMEOUT"
            else:
                # Ordinary timeout follows the configured failure policy: back to IDLE.
                self.transition(agent_id, "TASK_RESULT", message_id=envelope["message_id"],
                                actor="harness", reason_code="TASK_TIMEOUT")
        else:
            self.transition(agent_id, "TASK_RESULT", message_id=envelope["message_id"],
                            actor="harness", reason_code="NONE")

        result = {
            "task_id": task_id,
            "status": status,
            "result_artifacts": outcome.get("result_artifacts", []),
            "exit_code": outcome.get("exit_code", 1),
            "error_code": error_code,
            "resource_usage": {
                "wall_ms": resource_usage.get("wall_ms", elapsed_ms),
                "cpu_ms": resource_usage.get("cpu_ms", 0),
                "peak_memory_mb": resource_usage.get("peak_memory_mb", 0),
            },
            "span_ids": [envelope.get("span_id", "00f067aa0ba902b7")],
            "detail": outcome.get("detail", ""),
        }

        # §4.4 persist terminal result for the artifact-retention period.
        self.idempotency[dedup_key] = {"request": payload_fp, "result": result}
        response = self._reply(envelope, MessageType.TASK_RESULT, result)
        self._cache_message(envelope, response)
        return response

    def _default_execute(self, harness: "Harness", spec: dict) -> dict:
        """Simulated task execution with policy enforcement."""
        profile = harness.get_agent(spec.get("agent_id", "")).tool_profile
        grants = spec.get("tool_grants", [])
        caps = harness.get_agent(spec.get("agent_id", "")).effective_capabilities
        code, detail = harness._enforce_policy(spec, grants, caps, profile)
        if code:
            return {"status": ResultStatus.QUARANTINED.value, "error_code": code,
                    "detail": detail, "exit_code": 1}
        time.sleep(0.01)
        result_sha = hashlib.sha256(f"task-{spec['task_id']}-result".encode()).hexdigest()
        return {
            "status": ResultStatus.SUCCEEDED.value,
            "exit_code": 0,
            "error_code": None,
            "result_artifacts": [{"uri": f"artifact://result/{spec['task_id']}",
                                  "sha256": result_sha}],
            "resource_usage": {"wall_ms": 4812, "cpu_ms": 1960,
                               "peak_memory_mb": 1830},
            "detail": "",
        }

    # ---- HEARTBEAT (§4.5) --------------------------------------------------------

    def _handle_heartbeat(self, envelope: dict) -> dict:
        agent_id = envelope["agent_id"]
        agent = self.get_agent(agent_id)
        if agent.state in (AgentState.SHUTDOWN, AgentState.REJECTED):
            return self._error(envelope, ErrorCode.STATE_INVALID,
                               f"Agent is {agent.state.value}; no heartbeat accepted")
        if agent.state == AgentState.QUARANTINED:
            return self._error(envelope, ErrorCode.STATE_INVALID,
                               "Agent is quarantined; recovery decision required")
        agent.heartbeat_count += 1
        agent.reset_heartbeat_counter()
        return self._reply(envelope, MessageType.HEARTBEAT_ACK,
                           {"ack": True, "heartbeat_count": agent.heartbeat_count,
                            "state": agent.state.value})

    def record_missed_heartbeat(self, agent_id: str) -> Optional[EvidenceSpan]:
        """Count one missed heartbeat; quarantine at the threshold (§4.5)."""
        agent = self.get_agent(agent_id)
        agent.missed_heartbeats += 1
        if agent.missed_heartbeats >= HEARTBEAT_MISSED_THRESHOLD:
            agent.missed_heartbeats = 0
            agent.quarantine_reason = "HEARTBEAT_FAILURE"
            return self.transition(agent_id, "HEARTBEAT_FAILURE", actor="harness",
                                   reason_code="HEARTBEAT_FAILURE")
        return None

    # ---- SHUTDOWN (§4.5) --------------------------------------------------------------

    def _handle_shutdown(self, envelope: dict) -> dict:
        agent_id = envelope["agent_id"]
        payload = envelope.get("payload", {})
        agent = self.get_agent(agent_id)
        span = self.transition(agent_id, "HARNESS_SHUTDOWN", message_id=envelope["message_id"],
                               actor="harness", reason_code="SHUTDOWN")
        if span is None:
            return self._error(envelope, ErrorCode.STATE_INVALID,
                               f"Cannot shut down from {agent.state.value}")
        return self._reply(envelope, MessageType.SHUTDOWN,
                           {"reason": payload.get("reason", "Harness shutdown decision"),
                            "grace_period_ms": payload.get("grace_period_ms", GRACE_PERIOD_MS),
                            "final_state": agent.state.value,
                            "terminated": True})

    def harness_shutdown(self, agent_id: str) -> Optional[EvidenceSpan]:
        return self.transition(agent_id, "HARNESS_SHUTDOWN", actor="harness",
                               reason_code="SHUTDOWN")

    # ---- Escalation (§11, §16) ------------------------------------------------------------

    def escalate(self, agent_id: str, reason: str = "review required") -> Optional[EvidenceSpan]:
        """QUARANTINED -> ESCALATED on a review-required policy/security event."""
        code = "SECURITY_EVENT" if "security" in reason else "POLICY_EVENT"
        return self.transition(agent_id, code, actor="harness", reason_code=reason[:32])

    def perform_health_checks(self, agent_id: str) -> bool:
        """Health checks gating RESUME (§16)."""
        agent = self.get_agent(agent_id)
        return agent.missed_heartbeats == 0

    def reviewer_decision(self, agent_id: str, *, reviewer_identity: str, role: str,
                          decision: ReviewerDecision, findings: str = "",
                          scope: Optional[dict] = None, evidence_refs: Optional[List[str]] = None,
                          expiration: Optional[str] = None) -> dict:
        """Authenticated reviewer decision (§16). Signed + append-only."""
        agent = self.get_agent(agent_id)

        # The caller's role string is only a claim. Trust the server-side
        # reviewer directory and refuse unknown identities or role mismatches.
        if self.reviewer_roles.get(reviewer_identity) != role:
            return {"ok": False, "error": ErrorCode.AUTH_INVALID.value,
                    "detail": "Reviewer identity is not registered for the claimed role"}

        # Role authorization for the risk class of the triggered event.
        risk = RiskClass.PRIVILEGED if agent.quarantine_reason == "RESOURCE_LIMIT" else \
            (RiskClass.MODERATE if agent.quarantine_reason in ("SECRET_EXPOSURE", "SANDBOX_VIOLATION",
                                                               "EGRESS_DENIED") else RiskClass.SAFE)
        allowed = AUTHORIZED_ROLES.get(risk, set())
        if role not in allowed:
            return {"ok": False, "error": ErrorCode.AUTH_INVALID.value,
                    "detail": f"Role {role!r} not authorized for risk class {risk.value}"}

        rec = ReviewerDecisionRecord(
            decision_id=f"review-{uuid.uuid4()}",
            agent_id=agent_id,
            reviewer_identity=reviewer_identity,
            role=role,
            decision=decision.value,
            scope=scope or {},
            findings=findings,
            evidence_refs=evidence_refs or [],
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            expiration=expiration or time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        )
        rec_unstamped = {k: v for k, v in rec.__dict__.items() if k != "signature"}
        rec.signature = self.sign_record(rec_unstamped)
        self.decisions.append(rec)  # append-only; never deleted or rewritten.
        self._save_persistence()

        span = None
        if decision == ReviewerDecision.RESUME:
            if agent.state in (AgentState.QUARANTINED, AgentState.ESCALATED) and self.perform_health_checks(agent_id):
                trigger = "RECOVERY" if agent.state == AgentState.QUARANTINED else "REVIEW_RESUME"
                span = self.transition(agent_id, trigger, actor=reviewer_identity,
                                       message_id=rec.decision_id,
                                       reason_code="REVIEW_RESUME")
                agent.reset_heartbeat_counter()
        elif decision == ReviewerDecision.RETRY:
            if (agent.state in (AgentState.QUARANTINED, AgentState.ESCALATED)
                    and self.perform_health_checks(agent_id)):
                span = self.transition(agent_id, "REVIEW_RETRY", actor=f"reviewer:{reviewer_identity}",
                                       reason_code="REVIEW_RETRY")
                agent.reset_heartbeat_counter()
        elif decision == ReviewerDecision.SHUTDOWN:
            if agent.state == AgentState.ESCALATED:
                span = self.transition(agent_id, "REVIEW_SHUTDOWN", actor=f"reviewer:{reviewer_identity}",
                                       reason_code="REVIEW_SHUTDOWN")
        elif decision == ReviewerDecision.DENY:
            pass  # recorded; state preserved.

        return {"ok": span is not None or decision == ReviewerDecision.DENY,
                "decision_id": rec.decision_id, "state": agent.state.value,
                "verified": self.verify_record(rec), "span": span.to_dict() if span else None}


# ---------------------------------------------------------------------------
# 6. Agent (client side)
# ---------------------------------------------------------------------------

class Agent:
    """Minimal ATHP agent: register, execute tasks, heartbeat, shutdown."""

    def __init__(self, agent_id: str, harness: Harness):
        self.agent_id = agent_id
        self.harness = harness
        self.key_id = "agent.default/2026-09"  # root key until the session key is provisioned
        self.session_id: Optional[str] = None

    def build_envelope(self, message_type: MessageType, payload: dict, *,
                       timestamp: Optional[str] = None, message_id: Optional[str] = None,
                       version: str = ATHP_VERSION, extra: Optional[dict] = None) -> dict:
        env = {
            "athp_version": version,
            "message_id": message_id or str(uuid.uuid4()),
            "timestamp": timestamp or time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "agent_id": self.agent_id,
            "message_type": message_type.value,
            "payload": payload,
            "trace_id": str(uuid.uuid4()),
            "span_id": str(uuid.uuid4())[-16:],
            "key_id": self.key_id,
            "signature": "",
        }
        if self.session_id:
            env["session_id"] = self.session_id
        if extra:
            env.update(extra)
        return self.harness.sign_envelope(env)

    def send_envelope(self, envelope: dict) -> dict:
        response = self.harness.handle_message(envelope)
        if isinstance(response, dict) and response.get("message_type") == MessageType.REGISTER_OK.value \
                and not self.session_id:
            self.session_id = response["session_id"]
            self.key_id = f"{self.agent_id}/2026-09"  # adopt the provisioned session key
        return response

    def send(self, message_type: MessageType, payload: dict, **kw) -> dict:
        return self.send_envelope(self.build_envelope(message_type, payload, **kw))

    def register(self, supported_versions: Optional[List[str]] = None,
                 capabilities: Optional[List[str]] = None,
                 resource_limits: Optional[dict] = None,
                 tool_profile: str = "ci-standard") -> dict:
        return self.send(MessageType.REGISTER, {
            "supported_versions": supported_versions or ["1.0", "1.1"],
            "agent_version": "3.8.2",
            "capabilities": capabilities or ["patch", "tests", "readonly_repo"],
            "resource_limits": resource_limits or {"cpu_millis": 2000, "memory_mb": 4096},
            "tool_profile": tool_profile,
        })

    def accept_task(self, payload: dict) -> dict:
        return self.send(MessageType.TASK_ACCEPT, payload)

    def send_heartbeat(self) -> dict:
        return self.send(MessageType.HEARTBEAT, {})

    def request_shutdown(self, reason: str = "Agent-initiated shutdown") -> dict:
        return self.send(MessageType.SHUTDOWN, {"reason": reason, "grace_period_ms": GRACE_PERIOD_MS})


# ---------------------------------------------------------------------------
# 7. Demos
# ---------------------------------------------------------------------------

def _register_ok(agent: Agent, resp: dict) -> bool:
    if resp.get("message_type") != MessageType.REGISTER_OK.value:
        print(f"   -> REGISTER failed: {resp.get('payload', {})}")
        return False
    p = resp["payload"]
    print(f"   -> REGISTER_OK: version={p['selected_version']} caps={p['effective_capabilities']}")
    print(f"   -> session_id={agent.session_id} signed={bool(resp.get('signature'))}")
    return True


def demo():
    hmac_secret = os.urandom(32)
    h = Harness(hmac_secret=hmac_secret)
    agent = Agent(agent_id="agent.example.builder-17", harness=h)

    print("=== ATHP Moon Base Demo ===")
    print(f"Initial state: {h.get_agent(agent.agent_id).state.value}")

    reg = agent.register()
    if not _register_ok(agent, reg):
        return

    task = {"task_id": "task-001", "idempotency_key": "repo-abc/commit-123/task-7",
            "task_type": "coding.change",
            "input_artifacts": [{"uri": "artifact://fixture/abc", "sha256": "x", "mode": "readonly"}],
            "oracle": {"oracle_id": "pytest.v2", "version": "2.1.0"},
            "resource_budget": {"wall_timeout_ms": 300_000, "cpu_millis": 2000, "memory_mb": 4096},
            "sandbox_profile": "ci-standard",
            "tool_grants": ["repo.read", "tests.execute"],
            "tool_uses": [{"name": "read_file", "capability": "readonly_repo", "fs": ["repo.read"]},
                          {"name": "run_pytest", "capability": "tests", "fs": ["repo.read"]}],
            "agent_id": agent.agent_id}
    r1 = agent.accept_task(task)
    print(f"\nTASK_ACCEPT -> {r1['payload']['status']} exit={r1['payload']['exit_code']}")
    r2 = agent.accept_task(task)
    print(f"Idempotent replay -> same? {r2['payload'] == r1['payload']} (no re-execution)")

    hb = agent.send_heartbeat()
    print(f"\nHEARTBEAT -> ack={hb['payload']['ack']} state={hb['payload']['state']}")

    sh = agent.request_shutdown()
    print(f"SHUTDOWN -> final_state={sh['payload']['final_state']}")

    print("\n=== Evidence Span Log ===")
    for s in h.evidence_log:
        print(f"  {s.previous_state.value} -> {s.new_state.value} [{s.trigger}] "
              f"{s.agent_id} reason={s.reason_code}")
    print("\nDemo complete.")


def quarantine_demo():
    logging.basicConfig(level=logging.WARNING)
    h = Harness(hmac_secret=os.urandom(32))
    agent = Agent(agent_id="quarantine.test-01", harness=h)
    print("=== Quarantine & Recovery Demo ===")
    agent.register()

    print("Missed heartbeats...")
    for i in range(1, HEARTBEAT_MISSED_THRESHOLD + 1):
        span = h.record_missed_heartbeat(agent.agent_id)
        st = h.get_agent(agent.agent_id).state.value
        print(f"  miss #{i}: state={st}")
        if span:
            print(f"   -> quarantined (span {span.decision_id})")

    print("\nTask while quarantined...")
    r = agent.accept_task({"task_id": "task-002", "idempotency_key": "q/1", "tool_grants": [],
                           "tool_uses": [], "resource_budget": {}, "agent_id": agent.agent_id})
    print(f"  -> {r['payload']['code']}: {r['payload']['detail']}")

    print("\nReviewer RESUME...")
    out = h.reviewer_decision(agent.agent_id, reviewer_identity="alice@ci",
                              role="ci-operator", decision=ReviewerDecision.RESUME,
                              findings="heartbeat monitoring restored")
    print(f"  -> ok={out['ok']} state={out['state']} signed={out['verified']}")

    print("\nTask after recovery...")
    r = agent.accept_task({"task_id": "task-003", "idempotency_key": "post/1", "tool_grants": [],
                           "tool_uses": [], "resource_budget": {}, "agent_id": agent.agent_id})
    print(f"  -> {r['payload']['status']}")
    print("\nQuarantine demo complete.")


if __name__ == "__main__":
    demo()
    print()
    quarantine_demo()
