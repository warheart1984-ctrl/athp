"""ATHP lifecycle state machine and transition enforcement."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional, NamedTuple

from ._common import (
    AgentState,
    ErrorCode,
    Trigger,
    TRANSITION_RULES,
    now_utc_iso,
    now_utc_timestamp,
    ATHPVersion,
    make_error_envelope,
    MessageType,
)


class EvidenceSpan(NamedTuple):
    """Immutable evidence span for a state transition."""
    previous_state: AgentState
    new_state: AgentState
    trigger: Trigger
    decision_id: str
    message_id: str
    actor: str  # "harness" or "reviewer"
    timestamp: str
    reason_code: ErrorCode


class TransitionResult(NamedTuple):
    """Result of a state transition attempt."""
    success: bool
    new_state: AgentState
    evidence: Optional[EvidenceSpan]
    error: Optional[dict]


class LifecycleState:
    """Manages agent lifecycle state with enforced transitions."""

    def __init__(self, agent_id: str, initial_state: AgentState = AgentState.INIT):
        self.agent_id = agent_id
        self.state = initial_state
        self._session_id: Optional[str] = None
        self._registered_version: Optional[str] = None
        self._message_dedup: dict[str, dict] = {}  # message_id -> outcome
        self._task_dedup: dict[tuple[str, str], dict] = (  # (agent_id, idempotency_key) -> result
            {}
        )
        self._heartbeat_failures = 0
        self._evidence_log: list[EvidenceSpan] = []
        self._decision_counter = 0
        self._version_negotiated: bool = False

    @property
    def session_id(self) -> Optional[str]:
        return self._session_id

    @session_id.setter
    def session_id(self, sid: str) -> None:
        self._session_id = sid

    @property
    def registered_version(self) -> Optional[str]:
        return self._registered_version

    @registered_version.setter
    def registered_version(self, ver: str) -> None:
        self._registered_version = ver

    def can_execute_tasks(self) -> bool:
        """Agent can execute tasks only when IDLE and session valid."""
        return self.state == AgentState.IDLE and self._session_id is not None

    def can_accept_tasks(self) -> bool:
        """Agent can accept new tasks."""
        return self.state in (AgentState.IDLE, AgentState.EXECUTING)

    def transition(self, trigger: Trigger, actor: str = "harness", 
                   message_id: Optional[str] = None, 
                   reason_code: ErrorCode = ErrorCode.INTERNAL_ERROR) -> TransitionResult:
        """Attempt a state transition. Returns result with evidence or error."""
        key = (self.state.value, trigger.value)
        
        if key not in TRANSITION_RULES:
            return TransitionResult(
                success=False,
                new_state=self.state,
                evidence=None,
                error=self._error_state_invalid_transition(trigger),
            )
        
        new_state = AgentState(TRANSITION_RULES[key])
        
        # Build evidence span
        decision_id = f"dec-{uuid.uuid4()}"
        evidence = EvidenceSpan(
            previous_state=self.state,
            new_state=new_state,
            trigger=trigger,
            decision_id=decision_id,
            message_id=message_id or "",
            actor=actor,
            timestamp=now_utc_iso(),
            reason_code=reason_code,
        )
        
        # Check for illegal transitions
        if not self._is_legal_transition(trigger, new_state):
            return TransitionResult(
                success=False,
                new_state=self.state,
                evidence=None,
                error=self._error_state_invalid_transition(trigger),
            )
        
        self.state = new_state
        self._evidence_log.append(evidence)
        
        return TransitionResult(
            success=True,
            new_state=new_state,
            evidence=evidence,
            error=None,
        )
    
    def _is_legal_transition(self, trigger: Trigger, new_state: AgentState) -> bool:
        """Check if transition is legal given current context."""
        # INIT -> REJECTED is always legal
        if self.state == AgentState.INIT and new_state == AgentState.REJECTED:
            return True
        
        # ESCALATED pauses new task admission
        if new_state == AgentState.ESCALATED and self.state == AgentState.EXECUTING:
            return False  # Can't escalate from EXECUTING without going through QUARANTINED
        
        # QUARANTINED agent MUST NOT receive tasks
        if new_state == AgentState.QUARANTINED and self.state == AgentState.IDLE:
            # This is legal - quarantine from IDLE
            return True
        
        # Check that agent is not in a state that prohibits the transition
        if self.state == AgentState.SHUTDOWN:
            return False  # Cannot transition from SHUTDOWN
        
        if self.state == AgentState.REJECTED and trigger != Trigger.HARNESS_SHUTDOWN:
            return False  # Rejected agent can only go to SHUTDOWN
        
        return True
    
    def _error_state_invalid_transition(self, trigger: Trigger) -> dict:
        """Create error for invalid transition."""
        return {
            "code": ErrorCode.STATE_INVALID.value,
            "retryable": False,
            "message_id": "",
            "trace_id": "",
            "detail": f"Invalid transition from {self.state} with trigger {trigger}",
        }
    
    def record_dedup_message(self, message_id: str, outcome: dict) -> None:
        """Record a deduplicated message outcome."""
        self._message_dedup[message_id] = outcome
    
    def get_dedup_outcome(self, message_id: str) -> Optional[dict]:
        """Get stored outcome for a deduplicated message."""
        return self._message_dedup.get(message_id)
    
    def record_task_dedup(self, agent_id: str, idempotency_key: str, result: dict) -> None:
        """Record a task deduplication entry."""
        self._task_dedup[(agent_id, idempotency_key)] = result
    
    def get_task_dedup(self, agent_id: str, idempotency_key: str) -> Optional[dict]:
        """Get stored task result for deduplication."""
        return self._task_dedup.get((agent_id, idempotency_key))
    
    def record_heartbeat_failure(self) -> int:
        """Record a heartbeat failure. Returns current failure count."""
        self._heartbeat_failures += 1
        return self._heartbeat_failures
    
    def reset_heartbeat_failures(self) -> None:
        """Reset heartbeat failure counter."""
        self._heartbeat_failures = 0
    
    def should_quarantine(self) -> bool:
        """Check if agent should be quarantined based on heartbeat failures."""
        return self._heartbeat_failures >= HEARTBEAT_MISSED_THRESHOLD
    
    def to_dict(self) -> dict:
        """Serialize state for debugging/storage."""
        return {
            "agent_id": self.agent_id,
            "state": self.state.value,
            "session_id": self._session_id,
            "registered_version": self._registered_version,
            "heartbeat_failures": self._heartbeat_failures,
        }


class HarnessLifecycle:
    """Harness-level lifecycle management for multiple agents."""

    def __init__(self):
        self.agents: dict[str, LifecycleState] = {}
        self._session_counter = 0
    
    def get_or_create_agent(self, agent_id: str) -> LifecycleState:
        """Get existing agent state or create new one."""
        if agent_id not in self.agents:
            self.agents[agent_id] = LifecycleState(agent_id)
        return self.agents[agent_id]
    
    def register_agent(self, agent_id: str, version: str, session_id: str) -> None:
        """Record successful registration for an agent."""
        if agent_id in self.agents:
            agent = self.agents[agent_id]
            agent.registered_version = version
            agent.session_id = session_id
        else:
            agent = LifecycleState(agent_id)
            agent.registered_version = version
            agent.session_id = session_id
            self.agents[agent_id] = agent
    
    def transition_agent(self, agent_id: str, trigger: Trigger, actor: str = "harness",
                         message_id: Optional[str] = None,
                         reason_code: ErrorCode = ErrorCode.INTERNAL_ERROR) -> Optional[TransitionResult]:
        """Transition an agent's state. Returns result or None if agent not found."""
        if agent_id not in self.agents:
            return None
        agent = self.agents[agent_id]
        return agent.transition(trigger, actor, message_id, reason_code)
    
    def get_agent_state(self, agent_id: str) -> Optional[dict]:
        """Get agent state dict."""
        if agent_id not in self.agents:
            return None
        return self.agents[agent_id].to_dict()
    
    def get_all_states(self) -> dict[str, dict]:
        """Get all agent states."""
        return {aid: agent.to_dict() for aid, agent in self.agents.items()}
