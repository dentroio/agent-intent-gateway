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

import time
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

from .labels import LabelStore
from .values import Evidence, ValueIndex
from .policy import SEVERITY, Agent, FlowRule, Policy


@dataclass
class Session:
    """State for one agent session. Labels accumulate as the agent reads data."""

    agent_id: str
    principal: str
    labels: set[str] = field(default_factory=set)
    # label -> tool call that introduced it, for explanations
    provenance: dict[str, str] = field(default_factory=dict)
    klass: str | None = None    # backend-assigned policy class, from a verified token only
    # extra identity context recorded with every decision (instance, device, token id)
    attrs: dict[str, str] = field(default_factory=dict)
    values: ValueIndex = field(default_factory=ValueIndex)   # value-level tracking (aig.values)


@dataclass(frozen=True)
class Match:
    """A flow rule that fired, whether or not it changed the decision.

    `reason` is redacted (no data values): it may leave the gateway as telemetry."""

    rule_id: str
    action: str                 # what the rule did, or would have done in observe mode
    enforced: bool
    reason: str
    intent_id: str | None = None
    artifact_id: str | None = None
    approval_ref: str | None = None


@dataclass(frozen=True)
class Decision:
    action: str                 # allow | require_approval | deny
    reasons: tuple[str, ...]
    rules: tuple[str, ...]      # ids of the rules that produced the outcome
    sink: str | None = None
    matches: tuple[Match, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.action == "allow"

    @property
    def observed(self) -> tuple[Match, ...]:
        """Observe-mode rules that would have tightened this decision."""
        return tuple(m for m in self.matches if not m.enforced)


def _in_scope(flow: FlowRule, agent: Agent, session: "Session", now_ms: int) -> bool:
    if flow.expires_at_ms is not None and now_ms > flow.expires_at_ms:
        return False
    if flow.agent_classes and not any(fnmatchcase(agent.agent_class or "", p) for p in flow.agent_classes):
        return False
    if flow.device_ids and session.attrs.get("device") not in flow.device_ids:
        return False
    return True


def _matches(name: str, patterns: tuple[str, ...]) -> str | None:
    for p in patterns:
        if fnmatchcase(name, p):
            return p
    return None


def _principal_ok(principal: str, allowed: tuple[str, ...]) -> bool:
    return any(fnmatchcase(principal, p) for p in allowed)


class Engine:
    def __init__(self, policy: Policy, labels: LabelStore | None = None):
        self.policy = policy
        self.labels = labels if labels is not None else LabelStore()

    def evaluate(self, session: Session, tool_name: str, args: dict[str, Any] | None = None,
                 now: float | None = None) -> Decision:
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
        if tool.args is not None and (extra := sorted(set(args) - set(tool.args))):
            return Decision(
                "deny",
                (f"{tool_name} called with undeclared argument(s) {', '.join(extra)} "
                 f"(declared: {', '.join(tool.args)})",),
                ("identity:undeclared-argument",),
            )

        # --- 2. intent scope ---------------------------------------------
        class_approval = None
        # Classes come only from verified tokens; local stdio sessions have none.
        if policy.classes is not None and session.klass is not None:
            rule = policy.classes.get(session.klass)
            if rule is None:
                return Decision("deny", (f"policy class {session.klass!r} is not defined in policy",),
                                ("class:unknown",))
            if (p := _matches(tool_name, rule.deny)):
                return Decision("deny", (f"class {rule.name!r} denies {p!r}",), (f"class:{rule.name}:deny",))
            if (p := _matches(tool_name, rule.require_approval)):
                class_approval = (f"class {rule.name!r} requires approval for {p!r}", f"class:{rule.name}:approve")

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
        if class_approval and action == "allow":
            action, reasons, rules = "require_approval", [class_approval[0]], [class_approval[1]]

        # --- 3. data flow --------------------------------------------------
        sink = tool.sink_for(args)
        targets = {sink, f"risk:{tool.risk}", *(f"writes:{w}" for w in tool.writes)}
        present: dict[str, Evidence] | None = None   # computed once, only if a value rule needs it
        matches: list[Match] = []
        now_ms = int((now if now is not None else time.time()) * 1000)
        for flow in policy.flows:
            if flow.from_ not in session.labels:
                continue
            if flow.action == "allow" or not any(fnmatchcase(t, flow.to) for t in targets):
                continue  # flow rules only ever tighten a decision
            if not _in_scope(flow, agent, session, now_ms):
                continue
            origin = session.provenance.get(flow.from_, "an earlier call")
            verb = flow.action.replace("_", " ")
            if flow.precision == "value":
                if present is None:
                    present = session.values.find(args)
                if flow.from_ in present:
                    effective = flow.action
                    ev = present[flow.from_]
                    reason = f"{ev.describe()}; flow to {flow.to!r} is {verb}"
                    redacted = f"{ev.describe(redact=True)}; flow to {flow.to!r} is {verb}"
                    rule = f"flow:{flow.id}"
                else:
                    effective = flow.residual
                    reason = redacted = (f"session holds {flow.from_!r} data (from {origin}) but no "
                                         f"{flow.from_!r} values were found in the arguments; residual "
                                         f"action is {effective.replace('_', ' ')}")
                    rule = f"flow:{flow.id}:residual"
                if effective == "allow":
                    continue
            else:
                effective = flow.action
                reason = redacted = (f"session holds {flow.from_!r} data (from {origin}); "
                                     f"flow to {flow.to!r} is {verb}")
                rule = f"flow:{flow.id}"

            matches.append(Match(flow.id, effective, flow.enforce, redacted, flow.intent_id, flow.artifact_id,
                                 flow.approval_ref))
            if not flow.enforce:
                continue  # observe mode: recorded above, decision unchanged
            if SEVERITY[effective] > SEVERITY[action]:
                action, reasons, rules = effective, [reason], [rule]
            elif SEVERITY[effective] == SEVERITY[action] and action != "allow":
                reasons.append(reason)
                rules.append(rule)

        return Decision(action, tuple(reasons), tuple(rules), sink=sink, matches=tuple(matches))

    def observe(self, session: Session, tool_name: str, args: dict[str, Any] | None, result_text: str) -> None:
        """Index the values in a tool result under the labels it carries."""
        tool = self.policy.tool(tool_name)
        if tool is None or not result_text:
            return
        session.values.add(result_text, self._incoming(tool, tool_name, args or {}))

    def _incoming(self, tool, tool_name: str, args: dict[str, Any]) -> dict[str, str]:
        incoming = {label: tool_name for label in tool.reads}
        if tool.loads:
            for label, origin in self.labels.get(tool.loads, tool.resource(tool.loads, args)).items():
                incoming.setdefault(label, f"{tool_name} <- {origin}")
        return incoming

    def record(self, session: Session, tool_name: str, args: dict[str, Any] | None = None) -> None:
        """Call once an allowed call goes ahead.

        The session picks up the labels of what the tool returns, including
        labels stored by whoever wrote that data; writes to a shared store
        stamp the written item with everything the session holds.
        """
        tool = self.policy.tool(tool_name)
        if tool is None:
            return
        args = args or {}

        if tool.stores and session.labels:
            resource = tool.resource(tool.stores, args) or tool.stores
            self.labels.add(resource, {
                label: f"{session.provenance.get(label, '?')}, written to {resource} by {session.agent_id}"
                for label in session.labels
            })

        for label, origin in self._incoming(tool, tool_name, args).items():
            if label not in session.labels:
                session.labels.add(label)
                session.provenance[label] = origin
