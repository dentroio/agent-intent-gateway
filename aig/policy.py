"""Intent policy schema.

A policy describes, for every agent, *who* it may act for, *why* it exists,
and *what* it may touch -- plus how data is allowed to move between
classifications once an agent has touched it.

Policies are plain YAML so they can be generated (e.g. by Clarion from observed
behaviour), reviewed in a pull request, and diffed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

ACTIONS = ("allow", "require_approval", "deny")
# Higher index = more restrictive. When several rules apply, the most restrictive wins.
SEVERITY = {a: i for i, a in enumerate(ACTIONS)}


class PolicyError(ValueError):
    """Raised when a policy document is malformed."""


ADDRESS = re.compile(r"^[^@\s,;<>\"'()\[\]]+@[a-z0-9.-]+$")


def _strings(value: Any) -> list[str] | None:
    """Flatten an argument into its string leaves; None if anything isn't a string."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        out: list[str] = []
        for v in value:
            leaves = _strings(v)
            if leaves is None:
                return None
            out += leaves
        return out
    return None


@dataclass(frozen=True)
class EgressRule:
    """Narrows a call's sink from its arguments, e.g. email to *@corp.example is internal.

    The rule applies only if *every* value in *every* listed argument matches,
    so one external Bcc, or one smuggled address, keeps the call external.
    With kind=email each value is split the way lenient mail servers split
    recipient lists and every piece must be one well-formed address
    (case-insensitive). Anything that fails to parse fails closed.
    """

    args: tuple[str, ...]
    pattern: str
    sink: str
    kind: str = "glob"   # glob | email

    def matches(self, call_args: dict[str, Any]) -> bool:
        values: list[str] = []
        for name in self.args:
            if name not in call_args or call_args[name] in (None, "", []):
                continue
            leaves = _strings(call_args[name])
            if leaves is None:
                return False
            values += leaves
        if not values:
            return False
        if self.kind == "email":
            pattern = self.pattern.lower()
            tokens = [t for v in values for t in re.split(r"[,;\s]+", v) if t]
            return bool(tokens) and all(
                ADDRESS.match(t.lower()) and fnmatchcase(t.lower(), pattern) for t in tokens
            )
        return all(fnmatchcase(v, self.pattern) for v in values)


@dataclass(frozen=True)
class Tool:
    name: str
    reads: frozenset[str] = frozenset()   # data labels this tool returns to the agent
    writes: frozenset[str] = frozenset()  # labels of systems it changes
    sink: str = "internal"                # where arguments end up by default
    egress_rules: tuple[EgressRule, ...] = ()
    risk: str = "low"                     # low | high
    args: tuple[str, ...] | None = None   # if declared, any other argument is refused
    stores: str | None = None             # shared store this tool writes session data into
    loads: str | None = None              # shared store this tool reads back from
    store_key: str | None = None          # argument naming the item within the store

    def sink_for(self, args: dict[str, Any]) -> str:
        for rule in self.egress_rules:
            if rule.matches(args):
                return rule.sink
        return self.sink

    def resource(self, store: str, args: dict[str, Any]) -> str | None:
        """Store item a call touches, or None for 'the whole store'."""
        if self.store_key and isinstance(args.get(self.store_key), str):
            return f"{store}:{args[self.store_key]}"
        return None


@dataclass(frozen=True)
class Agent:
    id: str
    purpose: str
    on_behalf_of: tuple[str, ...]
    allow: tuple[str, ...] = ()
    require_approval: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()


@dataclass(frozen=True)
class FlowRule:
    """Once a session holds data labelled `from_`, calls reaching `to` get `action`.

    `to` is matched against the call's sink (e.g. "external") and against
    "risk:<level>" and "writes:<label>" pseudo-sinks, so a rule like
    `from: untrusted, to: risk:high` stops prompt-injected content from
    driving high-risk actions.
    """

    id: str
    from_: str
    to: str
    action: str


@dataclass
class Policy:
    default: str
    tools: dict[str, Tool]
    agents: dict[str, Agent]
    flows: list[FlowRule] = field(default_factory=list)

    def tool(self, name: str) -> Tool | None:
        return self.tools.get(name)


def _patterns(value: Any, where: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return tuple(value)
    raise PolicyError(f"{where}: expected a string or list of strings")


def _action(value: Any, where: str) -> str:
    if value not in ACTIONS:
        raise PolicyError(f"{where}: action must be one of {', '.join(ACTIONS)}, got {value!r}")
    return value


def parse_policy(doc: dict[str, Any]) -> Policy:
    if not isinstance(doc, dict):
        raise PolicyError("policy must be a mapping")
    if doc.get("version") != 1:
        raise PolicyError("unsupported policy version (expected 1)")

    tools: dict[str, Tool] = {}
    for name, spec in (doc.get("tools") or {}).items():
        spec = spec or {}
        where = f"tools.{name}"
        rules = []
        for j, r in enumerate(spec.get("egress_rules", [])):
            rw = f"{where}.egress_rules[{j}]"
            names = _patterns(r.get("args", r.get("arg")), rw + ".args")
            if not names or "pattern" not in r or "sink" not in r:
                raise PolicyError(f"{rw}: needs args, pattern and sink")
            kind = r.get("kind", "glob")
            if kind not in ("glob", "email"):
                raise PolicyError(f"{rw}.kind must be glob or email")
            rules.append(EgressRule(args=names, pattern=r["pattern"], sink=r["sink"], kind=kind))
        risk = spec.get("risk", "low")
        if risk not in ("low", "high"):
            raise PolicyError(f"{where}.risk must be low or high")
        declared = spec.get("args")
        tools[name] = Tool(
            name=name,
            reads=frozenset(_patterns(spec.get("reads"), f"{where}.reads")),
            writes=frozenset(_patterns(spec.get("writes"), f"{where}.writes")),
            sink=spec.get("sink", "internal"),
            egress_rules=tuple(rules),
            risk=risk,
            args=None if declared is None else _patterns(declared, f"{where}.args"),
            stores=spec.get("stores"),
            loads=spec.get("loads"),
            store_key=spec.get("store_key"),
        )

    agents: dict[str, Agent] = {}
    for spec in doc.get("agents") or []:
        aid = spec.get("id")
        if not aid:
            raise PolicyError("every agent needs an id")
        if aid in agents:
            raise PolicyError(f"duplicate agent id {aid!r}")
        if not spec.get("purpose"):
            raise PolicyError(f"agent {aid!r} must declare a purpose")
        principals = _patterns(spec.get("on_behalf_of"), f"agents.{aid}.on_behalf_of")
        if not principals:
            raise PolicyError(f"agent {aid!r} must declare on_behalf_of")
        agents[aid] = Agent(
            id=aid,
            purpose=spec["purpose"],
            on_behalf_of=principals,
            allow=_patterns(spec.get("allow"), f"agents.{aid}.allow"),
            require_approval=_patterns(spec.get("require_approval"), f"agents.{aid}.require_approval"),
            deny=_patterns(spec.get("deny"), f"agents.{aid}.deny"),
        )

    flows = []
    for i, spec in enumerate(doc.get("flows") or []):
        flows.append(
            FlowRule(
                id=spec.get("id", f"flow-{i}"),
                from_=spec["from"],
                to=spec["to"],
                action=_action(spec.get("action"), f"flows[{i}]"),
            )
        )

    return Policy(
        default=_action(doc.get("default", "deny"), "default"),
        tools=tools,
        agents=agents,
        flows=flows,
    )


def load_policy(path: str | Path) -> Policy:
    with open(path, encoding="utf-8") as fh:
        return parse_policy(yaml.safe_load(fh))
