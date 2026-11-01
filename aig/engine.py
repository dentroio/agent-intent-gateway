"""Policy decision point.

Every tool call is evaluated in three layers, and every layer contributes a
human-readable reason so a decision can always be explained:

1. Identity  -- is this a known agent, acting for a principal it may act for?
2. Intent    -- does the agent's declared scope cover this tool?
3. Data flow -- given what this session has already read, may data reach
                this call's sink? (blocks multi-step exfiltration and
                prompt-injection-driven actions that single-call ACLs miss)

The most restrictive outcome wins.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

from .policy import SEVERITY, Policy


@dataclass
class Session:
    """State for one agent session. Labels accumulate as the agent reads data."""

    agent_id: str
    principal: str
    labels: set[str] = field(default_factory=set)
    # label -> tool call that introduced it, for explanations
    provenance: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Decision:
    action: str                 # allow | require_approval | deny
    reasons: tuple[str, ...]
    rules: tuple[str, ...]      # ids of the rules that produced the outcome
    sink: str | None = None

    @property
    def allowed(self) -> bool:
        return self.action == "allow"


def _matches(name: str, patterns: tuple[str, ...]) -> str | None:
    for p in patterns:
        if fnmatchcase(name, p):
            return p
    return None


def _principal_ok(principal: str, allowed: tuple[str, ...]) -> bool:
    return any(fnmatchcase(principal, p) for p in allowed)


class Engine:
    def __init__(self, policy: Policy):
        self.policy = policy

    def evaluate(self, session: Session, tool_name: str, args: dict[str, Any] | None = None) -> Decision:
        args = args or {}
        policy = self.policy

        # --- 1. identity -------------------------------------------------
        agent = policy.agents.get(session.agent_id)
        if agent is None:
            return Decision("deny", (f"unknown agent {session.agent_id!r}",), ("identity:unknown-agent",))
        if not _principal_ok(session.principal, agent.on_behalf_of):
            return Decision(
                "deny",
                (f"{agent.id} may not act on behalf of {session.principal!r} "
                 f"(allowed: {', '.join(agent.on_behalf_of)})",),
                ("identity:principal",),
            )

        tool = policy.tool(tool_name)
        if tool is None:
            return Decision("deny", (f"tool {tool_name!r} is not declared in policy",), ("identity:unknown-tool",))

        # --- 2. intent scope ---------------------------------------------
        if (p := _matches(tool_name, agent.deny)):
            return Decision("deny", (f"{agent.id} explicitly denied {p!r}",), (f"agent:{agent.id}:deny",))
        if (p := _matches(tool_name, agent.require_approval)):
            action, reasons, rules = "require_approval", [f"{tool_name} needs human approval for {agent.id} ({p!r})"], [f"agent:{agent.id}:approve"]
        elif (p := _matches(tool_name, agent.allow)):
            action, reasons, rules = "allow", [f"{tool_name} is within {agent.id}'s declared scope ({p!r})"], [f"agent:{agent.id}:allow"]
        else:
            action = policy.default
            reasons = [f"{tool_name} is outside {agent.id}'s declared purpose: {agent.purpose!r}"]
            rules = ["default"]
            if action == "deny":
                return Decision(action, tuple(reasons), tuple(rules))

        # --- 3. data flow --------------------------------------------------
        sink = tool.sink_for(args)
        targets = {sink, f"risk:{tool.risk}", *(f"writes:{w}" for w in tool.writes)}
        for flow in policy.flows:
            if flow.from_ not in session.labels:
                continue
            if flow.action == "allow" or not any(fnmatchcase(t, flow.to) for t in targets):
                continue  # flow rules only ever tighten a decision
            origin = session.provenance.get(flow.from_, "an earlier call")
            reason = (f"session holds {flow.from_!r} data (from {origin}); "
                      f"flow to {flow.to!r} is {flow.action.replace('_', ' ')}")
            if SEVERITY[flow.action] > SEVERITY[action]:
                action, reasons, rules = flow.action, [reason], [f"flow:{flow.id}"]
            elif SEVERITY[flow.action] == SEVERITY[action] and action != "allow":
                reasons.append(reason)
                rules.append(f"flow:{flow.id}")

        return Decision(action, tuple(reasons), tuple(rules), sink=sink)

    def record(self, session: Session, tool_name: str) -> None:
        """Call after an allowed call executes: the agent now holds what the tool returned."""
        tool = self.policy.tool(tool_name)
        if tool is None:
            return
        for label in tool.reads:
            if label not in session.labels:
                session.labels.add(label)
                session.provenance[label] = tool_name
