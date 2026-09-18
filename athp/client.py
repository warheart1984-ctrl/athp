"""Agent-agnostic ATHP client and transports.

The client deliberately knows only the wire contract. Coding agents can use it
through the local transport, HTTP, or a small adapter of their own.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.request
import uuid
from typing import Any, Callable, Optional, Protocol

from .moon_base import ATHP_VERSION, Agent, Harness, MessageType, jcs_canonicalize


class Transport(Protocol):
    def send(self, envelope: dict) -> dict: ...


class LocalTransport:
    """Adapter for an in-process reference Harness."""

    def __init__(self, harness: Harness):
        self.harness = harness

    def send(self, envelope: dict) -> dict:
        return self.harness.handle_message(envelope)


class HttpTransport:
    """Minimal JSON-over-HTTP transport for remote ATHP servers."""

    def __init__(self, endpoint: str, timeout: float = 30.0):
        self.endpoint = endpoint
        self.timeout = timeout

    def send(self, envelope: dict) -> dict:
        body = json.dumps(envelope).encode("utf-8")
        request = urllib.request.Request(
            self.endpoint, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))


class ATHPClient:
    """Common client contract for any coding agent."""

    def __init__(self, agent_id: str, transport: Transport, secret: bytes,
                 key_id: str = "agent.default/2026-09"):
        self.agent_id = agent_id
        self.transport = transport
        self.secret = secret
        self.key_id = key_id
        self.session_id: Optional[str] = None

    def _key(self) -> bytes:
        if self.key_id == "agent.default/2026-09":
            return self.secret
        return hashlib.sha256(self.secret + self.key_id.encode()).digest()

    def _envelope(self, message_type: MessageType, payload: dict) -> dict:
        envelope = {
            "athp_version": ATHP_VERSION,
            "message_id": str(uuid.uuid4()),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "agent_id": self.agent_id,
            "message_type": message_type.value,
            "payload": payload,
            "trace_id": str(uuid.uuid4()),
            "span_id": str(uuid.uuid4())[-16:],
            "key_id": self.key_id,
            "signature": "",
        }
        if self.session_id:
            envelope["session_id"] = self.session_id
        canonical = jcs_canonicalize({k: v for k, v in envelope.items() if k != "signature"})
        envelope["signature"] = base64.urlsafe_b64encode(
            hmac.new(self._key(), canonical, hashlib.sha256).digest()).decode().rstrip("=")
        return envelope

    def send(self, message_type: MessageType, payload: dict) -> dict:
        response = self.transport.send(self._envelope(message_type, payload))
        if response.get("message_type") == MessageType.REGISTER_OK.value:
            self.session_id = response.get("session_id") or response.get("payload", {}).get("session_id")
            self.key_id = f"{self.agent_id}/2026-09"
        return response

    def register(self, capabilities: Optional[list[str]] = None) -> dict:
        return self.send(MessageType.REGISTER, {
            "supported_versions": ["1.1", "1.0"],
            "agent_version": "athp-client/0.1.0",
            "capabilities": capabilities or ["readonly_repo", "tests"],
            "resource_limits": {"cpu_millis": 2000, "memory_mb": 4096},
            "tool_profile": "ci-standard",
        })

    def accept_task(self, task: dict) -> dict:
        return self.send(MessageType.TASK_ACCEPT, task)

    def heartbeat(self) -> dict:
        return self.send(MessageType.HEARTBEAT, {})

    def shutdown(self, reason: str = "client shutdown") -> dict:
        return self.send(MessageType.SHUTDOWN, {"reason": reason, "grace_period_ms": 5000})

