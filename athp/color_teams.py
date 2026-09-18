"""Coordinator for the nine specialized Color DevOps teams."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from .lib import Agent
from .moon_base import Harness


TEAM_MANDATES = {
    "red": "authorized adversarial testing",
    "blue": "defense, monitoring, and operations",
    "black": "deep diagnostics and incident investigation",
    "purple": "red/blue finding closure",
    "gold": "architecture, standards, and policy",
    "silver": "implementation and automation",
    "yellow": "quality and independent verification",
    "green": "delivery, rollout, and rollback",
    "white": "governance, evidence, and audit",
}


@dataclass
class TeamTask:
    task_id: str
    team: str
    idempotency_key: str
    payload: dict[str, Any]
    status: str = "ASSIGNED"
    result: Optional[dict] = None


class ColorTeamsCoordinator:
    """Route scoped DevOps work to registered color-team agents.

    The coordinator assigns work and records results; ATHP remains responsible
    for lifecycle, signing, idempotency, policy, and evidence enforcement.
    """

    def __init__(self, harness: Harness):
        self.harness = harness
        self.agents: dict[str, Agent] = {}
        self.tasks: dict[str, TeamTask] = {}

    def register_team(self, team: str, agent: Agent) -> dict:
        team = team.lower()
        if team not in TEAM_MANDATES:
            raise ValueError(f"Unknown color team: {team}")
        response = agent.register(self.harness, ["readonly_repo", "tests"])
        self.agents[team] = agent
        return response

    def assign(self, team: str, task_id: str, payload: dict,
               idempotency_key: Optional[str] = None) -> dict:
        team = team.lower()
        if team not in self.agents:
            raise RuntimeError(f"Team is not registered: {team}")
        key = idempotency_key or task_id
        task = TeamTask(task_id, team, key, dict(payload))
        self.tasks[task_id] = task
        task_payload = dict(payload)
        task_type = task_payload.pop("task_type", "devops.operation")
        result = self.agents[team].task(
            self.harness, key, task_id=task_id,
            task_type=task_type, **task_payload)
        task.result = result
        task.status = result.get("message_type", "UNKNOWN")
        return result

    def status(self) -> dict:
        return {
            "teams": {team: {"mandate": mandate, "registered": team in self.agents}
                      for team, mandate in TEAM_MANDATES.items()},
            "tasks": {task_id: {"team": task.team, "status": task.status}
                      for task_id, task in self.tasks.items()},
        }
