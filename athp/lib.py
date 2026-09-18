"""High-level three-call library for coding-agent integrations."""

from __future__ import annotations

from typing import Any, Iterable, Optional

from .moon_base import Agent as CoreAgent, Harness


class Agent:
    """Small ergonomic wrapper over the certified reference Agent."""

    def __init__(self, agent_id: str, key_id: str = "agent.default/2026-09",
                 secret: bytes = b"athp-moon-base-shared-secret-2026"):
        self.agent_id = agent_id
        self.key_id = key_id
        self.secret = secret
        self._core: Optional[CoreAgent] = None
        self.last_response: Optional[dict] = None

    def register(self, harness: Harness, capabilities: Optional[list[str]] = None) -> dict:
        """Register and negotiate a session with a harness."""
        if harness._master_secret is None:
            harness._master_secret = self.secret
            harness.hmac_keys[self.key_id] = self.secret
        self._core = CoreAgent(self.agent_id, harness)
        self._core.key_id = self.key_id
        self.last_response = self._core.register(capabilities=capabilities)
        return self.last_response

    def task(self, harness: Harness, idempotency_key: str,
             tool_uses: Optional[list[dict]] = None, **payload: Any) -> dict:
        """Submit an idempotent task; replay returns the cached result."""
        if self._core is None:
            raise RuntimeError("register() must be called before task()")
        task = {"task_id": payload.pop("task_id", idempotency_key),
                "idempotency_key": idempotency_key,
                "agent_id": self.agent_id,
                "task_type": payload.pop("task_type", "coding.change"),
                "tool_uses": tool_uses or [], **payload}
        self.last_response = self._core.accept_task(task)
        return self.last_response

    def heartbeat(self) -> dict:
        if self._core is None:
            raise RuntimeError("register() must be called before heartbeat()")
        self.last_response = self._core.send_heartbeat()
        return self.last_response

    def shutdown(self, reason: str = "agent shutdown") -> dict:
        if self._core is None:
            raise RuntimeError("register() must be called before shutdown()")
        self.last_response = self._core.request_shutdown(reason)
        return self.last_response

