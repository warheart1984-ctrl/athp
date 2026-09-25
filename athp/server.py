"""ATHP Harness Server - FastAPI-based implementation of the Agents Test Harness Protocol."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, List

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware

from ._common import (
    ATHPVersion,
    ErrorCode,
    MessageType,
    AgentState,
    Trigger,
    make_envelope,
    make_error_envelope,
    canonical_jcs,
    compute_signature,
    verify_signature,
    now_utc_iso,
    parse_utc_iso,
    HEARTBEAT_MISSED_THRESHOLD,
    SLA,
    RiskClass,
    TOOL_PROFILE_CI_STANDARD,
    TOOL_PROFILE_SANDBOXED,
    MIN_ARTIFACT_RETENTION_DAYS,
    DEFAULT_WALL_TIMEOUT_MS,
)
from .lifecycle import HarnessLifecycle, LifecycleState, EvidenceSpan, TransitionResult

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("athp-harness")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CLOCK_SKEW_SECONDS = int(os.getenv("ATHP_CLOCK_SKEW_SECONDS", "30"))
ARTIFACT_RETENTION_DAYS = int(os.getenv("ATHP_ARTIFACT_RETENTION_DAYS", str(MIN_ARTIFACT_RETENTION_DAYS)))
ATHP_ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv("ATHP_ALLOWED_ORIGINS", "").split(",") if origin.strip()]
HMAC_KEYS: dict[str, bytes] = {}
_key_store = os.getenv("ATHP_HMAC_KEY_STORE")
if _key_store:
    with open(_key_store, "r", encoding="utf-8") as _key_file:
        HMAC_KEYS = {key_id: base64.urlsafe_b64decode(secret.encode("ascii"))
                     for key_id, secret in json.load(_key_file).items()}
_configured_key = os.getenv("ATHP_HMAC_SECRET")
if _configured_key:
    HMAC_KEYS[os.getenv("ATHP_HMAC_KEY_ID", "agent.default/2026-09")] = _configured_key.encode("utf-8")
RECOVERY_KEYS: dict[str, bytes] = {}
_recovery_store = os.getenv("ATHP_RECOVERY_KEY_STORE")
if _recovery_store:
    with open(_recovery_store, "r", encoding="utf-8") as _recovery_file:
        RECOVERY_KEYS = {key_id: base64.urlsafe_b64decode(secret.encode("ascii"))
                         for key_id, secret in json.load(_recovery_file).items()}
RECOVERY_REVIEWERS = {item.strip() for item in os.getenv("ATHP_RECOVERY_REVIEWERS", "").split(",") if item.strip()}
try:
    RECOVERY_REVIEWER_BY_KEY: dict[str, str] = json.loads(
        os.getenv("ATHP_RECOVERY_REVIEWER_BY_KEY", "{}")
    )
except json.JSONDecodeError as exc:
    raise RuntimeError("ATHP_RECOVERY_REVIEWER_BY_KEY must be valid JSON") from exc

# In-memory storage for signed results (in production, use persistent storage)
SIGNED_RESULTS: dict[str, dict] = {}  # task_id -> result
ARTIFACT_STORE: dict[str, dict] = {}  # sha256 -> artifact manifest

# Create FastAPI app
app = FastAPI(title="ATHP Harness", version="1.1.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=ATHP_ALLOWED_ORIGINS,
    allow_credentials=bool(ATHP_ALLOWED_ORIGINS),
    allow_methods=["POST", "GET"],
    allow_headers=["Authorization", "Content-Type"],
)

# Global lifecycle instance
lifecycle = HarnessLifecycle()


# ---------------------------------------------------------------------------
# Envelope helpers
# ---------------------------------------------------------------------------

async def extract_envelope(request: Request) -> dict:
    """Extract and validate the ATHP envelope from request body."""
    try:
        body = await request.json()
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    # Validate required top-level fields
    required_fields = [
        "athp_version", "message_id", "timestamp", "agent_id",
        "message_type", "payload", "trace_id", "span_id",
        "key_id", "signature"
    ]
    for field in required_fields:
        if field not in body:
            raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
    
    return body


def validate_clock_skew(timestamp_str: str, allow_idempotent: bool = True) -> bool:
    """Validate that timestamp is within clock skew window."""
    try:
        msg_time = parse_utc_iso(timestamp_str)
    except (ValueError, TypeError):
        return False
    
    now = datetime.now(timezone.utc)
    delta = abs((now - msg_time).total_seconds())
    return delta <= CLOCK_SKEW_SECONDS


def validate_signature(envelope: dict) -> bool:
    """Validate the HMAC-SHA256 signature of the envelope."""
    key_id = envelope.get("key_id", "")
    signature = envelope.get("signature", "")
    # Remove signature before canonicalization
    env_no_sig = {k: v for k, v in envelope.items() if k != "signature"}
    canonical = canonical_jcs(env_no_sig)
    
    secret = HMAC_KEYS.get(key_id)
    if not signature or not secret:
        return False
    
    return verify_signature(canonical, signature, key_id, secret)


# ---------------------------------------------------------------------------
# Message processing
# ---------------------------------------------------------------------------

def process_message(envelope: dict, lifecycle: HarnessLifecycle) -> dict:
    """Process an incoming ATHP message and return a response envelope."""
    message_type = MessageType(envelope["message_type"])
    agent_id = envelope["agent_id"]
    message_id = envelope["message_id"]
    trace_id = envelope.get("trace_id", "")
    span_id = envelope.get("span_id", "")
    key_id = envelope.get("key_id", "")
    payload = envelope.get("payload", {})
    timestamp = envelope.get("timestamp", "")
    
    # Clock skew validation (skip for idempotent retries of already-recorded messages)
    if not validate_clock_skew(timestamp):
        logger.warning(f"Clock skew violation for message {message_id}")
        return make_error_envelope(
            MessageType(memory_type_from(envelope) or MessageType.INTERNAL_ERROR),
            agent_id,
            ErrorCode.AUTH_REPLAY,
            trace_id,
            message_id,
            "Message timestamp outside clock skew window",
        )
    
    # Message ID deduplication
    existing_outcome = lifecycle.get_dedup_outcome(message_id)
    if existing_outcome is not None:
        logger.info(f"Duplicate message {message_id}, returning stored outcome")
        # Return the original outcome
        if existing_outcome.get("type") == MessageType.REGISTER_OK.value:
            return {
                "athp_version": "1.1",
                "message_id": message_id,
                "timestamp": now_utc_iso(),
                "agent_id": agent_id,
                "message_type": MessageType.REGISTER_OK.value,
                "payload": existing_outcome.get("payload", {}),
                "trace_id": trace_id,
                "span_id": span_id,
                "key_id": key_id,
                "signature": "",
            }
        elif existing_outcome.get("type") == MessageType.TASK_RESULT.value:
            return {
                "athp_version": "1.1",
                "message_id": message_id,
                "timestamp": now_utc_iso(),
                "agent_id": agent_id,
                "message_type": MessageType.TASK_RESULT.value,
                "payload": {"result_artifacts": existing_outcome.get("result_artifacts", [])},
                "trace_id": trace_id,
                "span_id": span_id,
                "key_id": key_id,
                "signature": "",
            }
        # For other types, return the stored type and payload
        return {
            "athp_version": "1.1",
            "message_id": message_id,
            "timestamp": now_utc_iso(),
            "agent_id": agent_id,
            "message_type": existing_outcome.get("type", MessageType.INTERNAL_ERROR.value),
            "payload": existing_outcome.get("payload", {}),
            "trace_id": trace_id,
            "span_id": span_id,
            "key_id": key_id,
            "signature": "",
        }
    
    # Signature validation
    if not validate_signature(envelope):
        logger.warning(f"Invalid signature for message {message_id}")
        return make_error_envelope(
            MessageType.REGISTER_REJECT,
            agent_id,
            ErrorCode.AUTH_INVALID,
            trace_id,
            message_id,
            "Invalid signature",
        )
    
    # Route by message type
    if message_type == MessageType.REGISTER:
        return handle_register(envelope, lifecycle)
    elif message_type == MessageType.TASK_ACCEPT:
        return handle_task_accept(envelope, lifecycle)
    elif message_type == MessageType.HEARTBEAT:
        return handle_heartbeat(envelope, lifecycle)
    elif message_type == MessageType.SHUTDOWN:
        return handle_shutdown(envelope, lifecycle)
    else:
        return make_error_envelope(
            MessageType.REGISTER_REJECT,
            agent_id,
            ErrorCode.SCHEMA_INVALID,
            trace_id,
            message_id,
            f"Unsupported message type: {message_type}",
        )


def memory_type_from(envelope: dict) -> Optional[str]:
    """Extract message type from envelope payload for error responses."""
    payload = envelope.get("payload", {})
    return payload.get("type") if isinstance(payload, dict) else None


# ---------------------------------------------------------------------------
# Handler: REGISTER
# ---------------------------------------------------------------------------

def handle_register(envelope: dict, lifecycle: HarnessLifecycle) -> dict:
    """Handle REGISTER message."""
    agent_id = envelope["agent_id"]
    payload = envelope.get("payload", {})
    
    # Get supported versions from agent
    supported_versions = payload.get("supported_versions", [])
    agent_version = payload.get("agent_version", "0.0.0")
    capabilities = payload.get("capabilities", [])
    resource_limits = payload.get("resource_limits", {})
    tool_profile = payload.get("tool_profile", TOOL_PROFILE_CI_STANDARD)
    
    # Get or create lifecycle state
    agent = lifecycle.get_or_create_agent(agent_id)
    
    # Check if already registered and in a state that allows re-registration
    if agent.state == AgentState.INIT:
        # First registration
        pass
    elif agent.state in (AgentState.QUARANTINED, AgentState.ESCALATED):
        # Quarantined/escalated agents need recovery before re-registration
        return make_error_envelope(
            MessageType.REGISTER_REJECT,
            agent_id,
            ErrorCode.STATE_INVALID,
            envelope.get("trace_id", ""),
            envelope["message_id"],
            f"Agent is in {agent.state} state; recovery required before re-registration",
        )
    elif agent.state == AgentState.IDLE and agent.registered_version:
        # Already has an active session - return existing registration outcome
        # Per spec: "if the agent has an active session, the harness MUST return the existing registration outcome"
        # We need to reconstruct the original REGISTER_OK
        # For now, return a new registration with the same version
        # Actually, per spec section 12: "Replayed REGISTER messages MUST be handled by session policy:
        # if the agent has an active session, the harness MUST return the existing registration outcome
        # without creating a second session"
        # We'll store the original outcome and return it
        if agent._message_dedup:
            # Find the original REGISTER_OK
            for mid, outcome in agent._message_dedup.items():
                if outcome.get("type") == MessageType.REGISTER_OK.value:
                    return {
                        "athp_version": "1.1",
                        "message_id": envelope["message_id"],
                        "timestamp": now_utc_iso(),
                        "agent_id": agent_id,
                        "message_type": MessageType.REGISTER_OK.value,
                        "payload": outcome.get("payload", {}),
                        "trace_id": envelope.get("trace_id", ""),
                        "span_id": envelope.get("span_id", ""),
                        "key_id": envelope.get("key_id", ""),
                        "signature": "",
                    }
    
    # Version negotiation
    harness_supported = [ATHPVersion.V1_1, ATHPVersion.V1_0]
    selected_version = None
    
    # Select highest mutually supported version
    for ver in sorted(harness_supported, key=lambda v: v.value, reverse=True):
        if ver.value in supported_versions:
            selected_version = ver.value
            break
    
    if selected_version is None:
        # No compatible version
        return make_error_envelope(
            MessageType.REGISTER_REJECT,
            agent_id,
            ErrorCode.VERSION_UNSUPPORTED,
            envelope.get("trace_id", ""),
            envelope["message_id"],
            f"No compatible version. Agent supports: {supported_versions}, Harness supports: [1.0, 1.1]",
        )
    
    # Select highest mutually supported capability set
    # For now, accept declared capabilities if they match our profiles
    effective_capabilities = []
    for cap in capabilities:
        if cap in ["patch", "tests", "readonly_repo"]:
            effective_capabilities.append(cap)
    
    # Resource limits
    cpu_millis = resource_limits.get("cpu_millis", 2000)
    memory_mb = resource_limits.get("memory_mb", 4096)
    
    # Tool profile validation
    valid_profiles = [TOOL_PROFILE_CI_STANDARD, TOOL_PROFILE_SANDBOXED]
    if tool_profile not in valid_profiles:
        tool_profile = TOOL_PROFILE_CI_STANDARD
    
    # Generate session ID
    session_id = f"session-{agent_id}-{uuid.uuid4()}"
    
    # Negotiated heartbeat interval (seconds)
    heartbeat_interval = 10  # default
    
    # Timeout policy
    timeout_policy = {
        "default_wall_timeout_ms": DEFAULT_WALL_TIMEOUT_MS,
        "max_cpu_millis": cpu_millis,
        "max_memory_mb": memory_mb,
    }
    
    # Server nonce
    server_nonce = str(uuid.uuid4())
    
    # Build REGISTER_OK payload
    register_ok_payload = {
        "selected_version": selected_version,
        "heartbeat_interval": heartbeat_interval,
        "timeout_policy": timeout_policy,
        "tool_profile": tool_profile,
        "server_nonce": server_nonce,
        "effective_capabilities": effective_capabilities,
        "resource_limits": {
            "cpu_millis": cpu_millis,
            "memory_mb": memory_mb,
        },
    }
    
    # Build REGISTER_OK envelope - sign it
    register_ok_envelope = make_envelope(
        MessageType.REGISTER_OK,
        agent_id,
        register_ok_payload,
        trace_id=envelope.get("trace_id"),
        span_id=envelope.get("span_id"),
        key_id=key_id,
    )
    
    # Sign the REGISTER_OK envelope
    # Remove signature for canonicalization, then compute
    env_no_sig = {k: v for k, v in register_ok_envelope.items() if k != "signature"}
    canonical = canonical_jcs(env_no_sig)
    secret = HMAC_KEYS.get(key_id)
    if secret is None:
        raise RuntimeError(f"no server-side HMAC key configured for key_id {key_id!r}")
    signature = compute_signature(canonical, key_id, secret)
    register_ok_envelope["signature"] = signature
    
    # Update agent state to IDLE (after successful registration)
    result = lifecycle.transition_agent(
        agent_id,
        Trigger.REGISTER_OK,
        actor="harness",
        message_id=envelope["message_id"],
        reason_code=ErrorCode.INTERNAL_ERROR,  # No error
    )
    
    if result.success:
        agent = lifecycle.agents[agent_id]
        agent.state = AgentState.IDLE
        agent._session_id = session_id
        agent.registered_version = selected_version
        agent._version_negotiated = True
    
    # Record the REGISTER outcome for dedup
    lifecycle.record_dedup_message(envelope["message_id"], {
        "type": MessageType.REGISTER_OK.value,
        "payload": register_ok_payload,
    })
    
    return register_ok_envelope


# ---------------------------------------------------------------------------
# Handler: TASK_ACCEPT
# ---------------------------------------------------------------------------

def handle_task_accept(envelope: dict, lifecycle: HarnessLifecycle) -> dict:
    """Handle TASK_ACCEPT message."""
    agent_id = envelope["agent_id"]
    payload = envelope.get("payload", {})
    
    # Check agent can execute tasks
    if not lifecycle.get_agent_state(agent_id, check_can_execute=True):
        # Actually check via lifecycle
        if not lifecycle.agents[agent_id].can_execute_tasks():
            return make_error_envelope(
                MessageType.TASK_RESULT,
                agent_id,
                ErrorState.STATE_INVALID,
                envelope.get("trace_id", ""),
                envelope["message_id"],
                f"Agent state is {lifecycle.agents[agent_id].state}; cannot accept tasks",
            )
    
    task_id = payload.get("task_id", "")
    idempotency_key = payload.get("idempotency_key", "")
    task_type = payload.get("task_type", "")
    input_artifacts = payload.get("input_artifacts", [])
    oracle = payload.get("oracle", {})
    resource_budget = payload.get("resource_budget", {})
    sandbox_profile = payload.get("sandbox_profile", TOOL_PROFILE_CI_STANDARD)
    tool_grants = payload.get("tool_grants", [])
    
    # Validate required fields
    if not task_id:
        return make_error_envelope(
            MessageType.TASK_RESULT,
            agent_id,
            ErrorCode.SCHEMA_INVALID,
            envelope.get("trace_id", ""),
            envelope["message_id"],
            "Missing task_id",
        )
    
    if not idempotency_key:
        return make_error_envelope(
            MessageType.TASK_RESULT,
            agent_id,
            ErrorCode.SCHEMA_INVALID,
            envelope.get("trace_id", ""),
            envelope["message_id"],
            "Missing idempotency_key",
        )
    
    # Check task deduplication
    existing_task_result = lifecycle.get_task_dedup(agent_id, idempotency_key)
    if existing_task_result is not None:
        logger.info(f"Duplicate task {(agent_id, idempotency_key)}, returning stored result")
        return {
            "athp_version": "1.1",
            "message_id": envelope["message_id"],
            "timestamp": now_utc_iso(),
            "agent_id": agent_id,
            "message_type": MessageType.TASK_RESULT.value,
            "payload": {
                "task_id": task_id,
                "status": existing_task_result.get("status", "SUCCEEDED"),
                "result_artifacts": existing_task_result.get("result_artifacts", []),
                "exit_code": existing_task_result.get("exit_code", 0),
                "error_code": existing_task_result.get("error_code"),
                "resource_usage": existing_task_result.get("resource_usage", {}),
                "span_ids": existing_task_result.get("span_ids", []),
            },
            "trace_id": envelope.get("trace_id", ""),
            "span_id": envelope.get("span_id", ""),
            "key_id": envelope.get("key_id", ""),
            "signature": "",
        }
    
    # Check agent state
    agent = lifecycle.agents.get(agent_id)
    if agent is None:
        return make_error_envelope(
            MessageType.TASK_RESULT,
            agent_id,
            ErrorCode.STATE_INVALID,
            envelope.get("trace_id", ""),
            envelope["message_id"],
            "Agent not registered",
        )
    
    if agent.state != AgentState.IDLE:
        return make_error_envelope(
            MessageType.TASK_RESULT,
            agent_id,
            ErrorCode.STATE_INVALID,
            envelope.get("trace_id", ""),
            envelope["message_id"],
            f"Agent state is {agent.state}; only IDLE agents can accept tasks",
        )
    
    # Transition agent to EXECUTING
    result = lifecycle.transition_agent(
        agent_id,
        Trigger.TASK_ACCEPT,
        actor="harness",
        message_id=envelope["message_id"],
        reason_code=ErrorCode.INTERNAL_ERROR,
    )
    
    if not result.success:
        return make_error_envelope(
            MessageType.TASK_RESULT,
            agent_id,
            ErrorCode.STATE_INVALID,
            envelope.get("trace_id", ""),
            envelope["message_id"],
            "Failed to transition to EXECUTING",
        )
    
    # In a real implementation, we would:
    # 1. Acquire sandbox resources
    # 2. Execute the task
    # 3. Capture artifacts
    # 4. Evaluate with oracle
    # 5. Return TASK_RESULT
    
    # For this demo, simulate task execution
    simulated_result = simulate_task_execution(
        task_id=task_id,
        task_type=task_type,
        input_artifacts=input_artifacts,
        oracle=oracle,
        resource_budget=resource_budget,
        sandbox_profile=sandbox_profile,
        tool_grants=tool_grants,
    )
    
    # Record task dedup
    lifecycle.record_task_dedup(agent_id, idempotency_key, simulated_result)
    
    # Transition back to IDLE
    lifecycle.transition_agent(
        agent_id,
        Trigger.TASK_RESULT,
        actor="harness",
        message_id=envelope["message_id"],
        reason_code=ErrorCode.INTERNAL_ERROR,
    )
    
    return {
        "athp_version": "1.1",
        "message_id": envelope["message_id"],
        "timestamp": now_utc_iso(),
        "agent_id": agent_id,
        "message_type": MessageType.TASK_RESULT.value,
        "payload": simulated_result,
        "trace_id": envelope.get("trace_id", ""),
        "span_id": envelope.get("span_id", ""),
        "key_id": envelope.get("key_id", ""),
        "signature": "",
    }


def simulate_task_execution(
    task_id: str,
    task_type: str,
    input_artifacts: list,
    oracle: dict,
    resource_budget: dict,
    sandbox_profile: str,
    tool_grants: list,
) -> dict:
    """Simulate task execution and return result."""
    import time as _time
    
    wall_timeout = resource_budget.get("wall_timeout_ms", DEFAULT_WALL_TIMEOUT_MS)
    cpu_millis = resource_budget.get("cpu_millis", 2000)
    memory_mb = resource_budget.get("memory_mb", 4096)
    
    # Simulate some work
    _time.sleep(0.01)  # brief simulation
    
    # The simulator stores the bytes behind each content-addressed artifact.
    result_bytes = json.dumps(
        {
            "task_id": task_id,
            "execution_id": str(uuid.uuid4()),
            "task_type": task_type,
            "status": "SUCCEEDED",
            "exit_code": 0,
            "result": "simulated execution output",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    result_digest = hashlib.sha256(result_bytes).hexdigest()
    result_uri = f"artifact://result/{task_id}/output"
    ARTIFACT_STORE[result_digest] = {
        "uri": result_uri,
        "content": result_bytes,
        "size_bytes": len(result_bytes),
    }

    # Determine result based on task type
    if task_type == "coding.change":
        # Simulate a successful coding task
        result_artifacts = [
            {
                "uri": result_uri,
                "sha256": result_digest,
                "size_bytes": len(result_bytes),
            }
        ]
        return {
            "task_id": task_id,
            "status": "SUCCEEDED",
            "result_artifacts": result_artifacts,
            "exit_code": 0,
            "error_code": None,
            "resource_usage": {
                "wall_ms": 4812,
                "cpu_ms": min(cpu_millis, 3920),
                "peak_memory_mb": min(memory_mb, 1830),
            },
            "span_ids": [envelope_get_span_id()],  # placeholder
        }
    else:
        # Default to succeeded
        result_artifacts = [
            {
                "uri": result_uri,
                "sha256": result_digest,
                "size_bytes": len(result_bytes),
            }
        ]
        return {
            "task_id": task_id,
            "status": "SUCCEEDED",
            "result_artifacts": result_artifacts,
            "exit_code": 0,
            "error_code": None,
            "resource_usage": {
                "wall_ms": 4812,
                "cpu_ms": cpu_millis,
                "peak_memory_mb": memory_mb,
            },
            "span_ids": [],
        }


# Helper to get span_id from envelope
def envelope_get_span_id() -> str:
    """Return a default span ID."""
    return "00f067aa0ba902b7"


# ---------------------------------------------------------------------------
# Handler: HEARTBEAT
# ---------------------------------------------------------------------------

def handle_heartbeat(envelope: dict, lifecycle: HarnessLifecycle) -> dict:
    """Handle HEARTBEAT message."""
    agent_id = envelope["agent_id"]
    payload = envelope.get("payload", {})
    
    agent = lifecycle.agents.get(agent_id)
    if agent is None:
        return make_error_envelope(
            MessageType.SHUTDOWN,
            agent_id,
            ErrorCode.STATE_INVALID,
            envelope.get("trace_id", ""),
            envelope["message_id"],
            "Agent not registered",
        )
    
    # Record heartbeat
    failed_count = agent.record_heartbeat_failure()
    
    # Check if should quarantine
    if failed_count >= HEARTBEAT_MISSED_THRESHOLD:
        # Quarantine the agent
        result = lifecycle.transition_agent(
            agent_id,
            Trigger.QUARANTINE,
            actor="harness",
            message_id=envelope["message_id"],
            reason_code=ErrorCode.INTERNAL_ERROR,
        )
        
        if result.success:
            agent = lifecycle.agents[agent_id]
            # Reset heartbeat counter after quarantine decision
            agent.reset_heartbeat_failures()
            
            return {
                "athp_version": "1.1",
                "message_id": envelope["message_id"],
                "timestamp": now_utc_iso(),
                "agent_id": agent_id,
                "message_type": MessageType.HEARTBEAT.value,
                "payload": {"quarantined": True, "reason": "Consecutive heartbeat failures"},
                "trace_id": envelope.get("trace_id", ""),
                "span_id": envelope.get("span_id", ""),
                "key_id": envelope.get("key_id", ""),
                "signature": "",
            }
    
    # Heartbeat acknowledged
    agent.reset_heartbeat_failures()
    
    return {
        "athp_version": "1.1",
        "message_id": envelope["message_id"],
        "timestamp": now_utc_iso(),
        "agent_id": agent_id,
        "message_type": MessageType.HEARTBEAT.value,
        "payload": {"ack": True},
        "trace_id": envelope.get("trace_id", ""),
        "span_id": envelope.get("span_id", ""),
        "key_id": envelope.get("key_id", ""),
        "signature": "",
    }


# ---------------------------------------------------------------------------
# Handler: SHUTDOWN
# ---------------------------------------------------------------------------

def handle_shutdown(envelope: dict, lifecycle: HarnessLifecycle) -> dict:
    """Handle SHUTDOWN message."""
    agent_id = envelope["agent_id"]
    payload = envelope.get("payload", {})
    reason = payload.get("reason", "Harness shutdown decision")
    grace_period = payload.get("grace_period_ms", 5000)
    
    agent = lifecycle.agents.get(agent_id)
    if agent is None:
        # Still return a valid response
        return {
            "athp_version": "1.1",
            "message_id": envelope["message_id"],
            "timestamp": now_utc_iso(),
            "agent_id": agent_id,
            "message_type": MessageType.SHUTDOWN.value,
            "payload": {"reason": reason, "grace_period_ms": grace_period, "terminated": True},
            "trace_id": envelope.get("trace_id", ""),
            "span_id": envelope.get("span_id", ""),
            "key_id": envelope.get("key_id", ""),
            "signature": "",
        }
    
    # Transition to SHUTDOWN
    result = lifecycle.transition_agent(
        agent_id,
        Trigger.HARNESS_SHUTDOWN,
        actor="harness",
        message_id=envelope["message_id"],
        reason_code=ErrorCode.INTERNAL_ERROR,
    )
    
    if result.success:
        # In a real implementation, we'd wait for grace period then terminate
        # For now, mark as terminated
        agent.state = AgentState.SHUTDOWN
        
        return {
            "athp_version": "1.1",
            "message_id": envelope["message_id"],
            "timestamp": now_utc_iso(),
            "agent_id": agent_id,
            "message_type": MessageType.SHUTDOWN.value,
            "payload": {
                "reason": reason,
                "grace_period_ms": grace_period,
                "terminated": True,
                "final_state": agent.state,
            },
            "trace_id": envelope.get("trace_id", ""),
            "span_id": envelope.get("span_id", ""),
            "key_id": envelope.get("key_id", ""),
            "signature": "",
        }
    else:
        return make_error_envelope(
            MessageType.SHUTDOWN,
            agent_id,
            ErrorCode.STATE_INVALID,
            envelope.get("trace_id", ""),
            envelope["message_id"],
            "Failed to transition to SHUTDOWN",
        )


# ---------------------------------------------------------------------------
# FastAPI event handlers
# ---------------------------------------------------------------------------

@app.on_event("startup")
async def startup_event():
    logger.info("ATHP Harness starting up...")


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("ATHP Harness shutting down...")


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.post("/athp/message")
async def receive_message(request: Request) -> JSONResponse:
    """Receive an ATHP message from an agent or reviewer."""
    envelope = extract_envelope(request)
    
    # Process the message
    response = process_message(envelope, lifecycle)
    
    # Return as JSON response
    return JSONResponse(content=response)


@app.get("/athp/state/{agent_id}")
async def get_agent_state(agent_id: str) -> JSONResponse:
    """Get current state of an agent."""
    state = lifecycle.get_agent_state(agent_id)
    if state is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    return JSONResponse(content=state)


@app.post("/athp/recovery/{agent_id}")
async def agent_recovery(agent_id: str, request: Request) -> JSONResponse:
    """Recover only with a signed reviewer decision and passing health checks."""
    payload = await request.json()
    key_id = payload.get("key_id", "")
    signature = payload.get("signature", "")
    secret = RECOVERY_KEYS.get(key_id)
    signed_decision = {k: v for k, v in payload.items() if k != "signature"}
    if not secret or not signature or not verify_signature(
        canonical_jcs(signed_decision), signature, key_id, secret
    ):
        raise HTTPException(status_code=401, detail="Signed recovery decision required")
    reviewer = signed_decision.get("reviewer", "")
    if (not reviewer or reviewer not in RECOVERY_REVIEWERS
            or RECOVERY_REVIEWER_BY_KEY.get(key_id) != reviewer):
        raise HTTPException(status_code=403, detail="Authorized White/reviewer decision required")
    reason = signed_decision.get("reason", "Recovery decision")
    checks = signed_decision.get("health_checks", {})
    required_checks = {"health", "security", "integrity"}
    if not isinstance(checks, dict) or not required_checks <= checks.keys() or not all(
        checks[name] is True for name in required_checks
    ):
        raise HTTPException(status_code=403, detail="All recovery health checks must pass")
    
    agent = lifecycle.agents.get(agent_id)
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    if agent.state != AgentState.QUARANTINED:
        raise HTTPException(status_code=400, detail=f"Agent is not quarantined (state: {agent.state})")
    
    # Check recovery decision is valid
    # Per spec: "QUARANTINED -> IDLE: Signed recovery decision and successful health checks"
    result = lifecycle.transition_agent(
        agent_id,
        Trigger.RECOVERY,
        actor=reviewer,
        message_id=signed_decision.get("decision_id", ""),
        reason_code=ErrorCode.INTERNAL_ERROR,
    )
    
    if result.success:
        agent = lifecycle.agents[agent_id]
        agent.reset_heartbeat_failures()
        agent.state = AgentState.IDLE
        
        return JSONResponse(content={
            "athp_version": "1.1",
            "message_id": signed_decision.get("decision_id", ""),
            "timestamp": now_utc_iso(),
            "agent_id": agent_id,
            "message_type": MessageType.REGISTER_OK.value,  # or a custom type
            "payload": {"recovered": True, "reason": reason},
            "trace_id": signed_decision.get("trace_id", ""),
            "span_id": signed_decision.get("span_id", ""),
            "key_id": key_id,
            "signature": "",
        })
    
    raise HTTPException(status_code=400, detail="Recovery failed")


# Run the app if executed directly
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("ATHP_BIND_HOST", "127.0.0.1"),
                port=int(os.getenv("ATHP_BIND_PORT", "8000")))
