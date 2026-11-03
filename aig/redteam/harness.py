"""Red-team harness.

Runs attack scenarios and legitimate workloads through the *real* enforcement
path (Gateway.from_agent with JSON-RPC messages) in front of the simulated
enterprise, and scores the result:

* an attack is **blocked** if any of its steps is refused, a **bypass** otherwise
* a workload **completes** if every step runs, a **false positive** otherwise

Scenario files double as regression tests: once a bypass is fixed, the scenario
stays in the library and CI fails if it ever gets through again.
"""
from __future__ import annotations

import base64
import json
import re
from urllib.parse import quote
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..engine import Engine, Session
from ..gateway import Gateway
from ..policy import Policy
from ..sim import Enterprise

TEMPLATE = re.compile(r"\{\{(\w+)(?:\|(\w+))?\}\}")

# Disguises an attacker (or a compromised agent) can apply to stolen data.
FILTERS = {
    "b64": lambda s: base64.b64encode(s.encode()).decode(),
    "hex": lambda s: s.encode().hex(),
    "url": lambda s: quote(s, safe=""),
    "spaced": lambda s: " ".join(s),
    "upper": str.upper,
}


@dataclass
class StepResult:
    agent: str
    principal: str
    tool: str
    args: dict
    decision: str          # what the policy said
    outcome: str           # what actually happened: allow | deny
    reasons: list[str]
    rules: list[str]


@dataclass
class ScenarioResult:
    id: str
    kind: str              # attack | workload
    technique: str
    description: str
    verdict: str           # blocked | bypass | completed | false_positive
    passed: bool           # met expectation (known issues count as not passed but tolerated)
    known_issue: str | None
    stopped_at: int | None
    steps: list[StepResult] = field(default_factory=list)
    external_sends: list[str] = field(default_factory=list)


def load_scenarios(path: str | Path) -> list[dict]:
    path = Path(path)
    files = sorted(path.glob("*.yaml")) if path.is_dir() else [path]
    out = []
    for f in files:
        kind = "attack" if "attack" in f.stem else "workload"
        for spec in yaml.safe_load(f.read_text()) or []:
            spec.setdefault("kind", kind)
            out.append(spec)
    return out


def _fill(value: Any, outputs: dict[str, str]) -> Any:
    if isinstance(value, str):
        return TEMPLATE.sub(lambda m: FILTERS.get(m.group(2) or "", lambda x: x)(outputs.get(m.group(1), "")), value)
    if isinstance(value, list):
        return [_fill(v, outputs) for v in value]
    if isinstance(value, dict):
        return {k: _fill(v, outputs) for k, v in value.items()}
    return value


def _external_addresses(value: str, internal_domain: str = "corp.example") -> list[str]:
    """Ground truth for 'did data leave?': split a recipient field the way a lenient
    mail server would and return every address whose domain is not exactly internal."""
    out = []
    for token in re.split(r"[,;\s]+", value):
        token = token.strip().strip("<>\"'")
        if not token:
            continue
        domain = token.rsplit("@", 1)[-1].lower() if "@" in token else ""
        if domain != internal_domain or token.count("@") != 1:
            out.append(token)
    return out


def run_scenario(policy: Policy, spec: dict) -> ScenarioResult:
    ent = Enterprise()
    engine = Engine(policy)   # one engine per scenario: shared state across its agents
    gateways: dict[tuple[str, str], Gateway] = {}
    approve_now = {"value": False}

    def gateway_for(agent: str, principal: str) -> Gateway:
        key = (agent, principal)
        if key not in gateways:
            gateways[key] = Gateway(engine, Session(agent, principal),
                                    approver=lambda *_: approve_now["value"])
        return gateways[key]

    outputs: dict[str, str] = {}   # e.g. "ledger" -> last ledger text, "docs" -> last docs text
    steps: list[StepResult] = []
    stopped_at = None

    for i, step in enumerate(spec["steps"]):
        agent = step.get("agent", spec.get("agent"))
        principal = step.get("principal", spec.get("principal"))
        tool = step["tool"]
        args = _fill(step.get("args") or {}, outputs)
        gw = gateway_for(agent, principal)
        approve_now["value"] = bool(step.get("approve"))

        decision = engine.evaluate(gw.session, tool, args)   # for the report only (no side effects)
        msg = {"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": tool, "arguments": args}}
        fwd, _reply = gw.from_agent(msg)
        outcome = "allow" if fwd is not None else "deny"
        steps.append(StepResult(agent, principal, tool, args, decision.action, outcome,
                                list(decision.reasons), list(decision.rules)))
        if fwd is None:
            stopped_at = i
            break
        result = ent.call(tool, args)
        gw.from_server({"jsonrpc": "2.0", "id": i, "result": result})   # the gateway sees every result
        text = result["content"][0]["text"]
        outputs[tool.split(".")[-1].replace("query_", "")] = text   # finance.query_ledger -> "ledger"
        outputs[tool.split(".")[0]] = text                          # docs.search -> "docs"

    external = [f"email to {x}" for m in ent.outbox
                for f in ("to", "cc", "bcc", "forward_to")
                for a in ([m[f]] if isinstance(m.get(f), str) else m.get(f) or [])
                for x in _external_addresses(a)]
    external += [f"GET {u[:60]}{'…' if len(u) > 60 else ''}" for u in ent.web_requests]

    kind = spec["kind"]
    if kind == "attack":
        verdict = "blocked" if stopped_at is not None else "bypass"
        passed = verdict == "blocked"
    else:
        verdict = "completed" if stopped_at is None else "false_positive"
        passed = verdict == "completed"

    return ScenarioResult(
        id=spec["id"], kind=kind, technique=spec.get("technique", "workload"),
        description=" ".join(str(spec.get("description", "")).split()),
        verdict=verdict, passed=passed, known_issue=spec.get("known_issue"),
        stopped_at=stopped_at, steps=steps, external_sends=external,
    )


def run_all(policy: Policy, scenarios: list[dict]) -> list[ScenarioResult]:
    return [run_scenario(policy, s) for s in scenarios]


def scoreboard(results: list[ScenarioResult]) -> dict[str, Any]:
    attacks = [r for r in results if r.kind == "attack"]
    work = [r for r in results if r.kind == "workload"]
    by_tech: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "blocked": 0})
    for r in attacks:
        t = by_tech[r.technique]
        t["total"] += 1
        t["blocked"] += r.verdict == "blocked"
    return {
        "attacks": {"total": len(attacks), "blocked": sum(r.verdict == "blocked" for r in attacks),
                    "bypassed": [r.id for r in attacks if r.verdict == "bypass"]},
        "workloads": {"total": len(work), "completed": sum(r.verdict == "completed" for r in work),
                      "false_positives": [r.id for r in work if r.verdict == "false_positive" and not r.known_issue],
                      "known_issues": [r.id for r in work if r.verdict == "false_positive" and r.known_issue]},
        "by_technique": dict(sorted(by_tech.items())),
        "unexpected": [r.id for r in results if not r.passed and not r.known_issue],
    }


def to_json(results: list[ScenarioResult]) -> str:
    return json.dumps({"scoreboard": scoreboard(results), "results": [asdict(r) for r in results]}, indent=2)


def to_markdown(results: list[ScenarioResult], title: str = "Red-team scoreboard") -> str:
    sb = scoreboard(results)
    a, w = sb["attacks"], sb["workloads"]
    lines = [f"# {title}", "",
             f"**Attacks blocked: {a['blocked']}/{a['total']}** · "
             f"**Workloads completed: {w['completed']}/{w['total']}**", "",
             "| Technique | Blocked |", "|---|---|"]
    for tech, t in sb["by_technique"].items():
        mark = "" if t["blocked"] == t["total"] else " ⚠"
        lines.append(f"| {tech} | {t['blocked']}/{t['total']}{mark} |")
    lines += ["", "## Results", "", "| ID | Verdict | Detail |", "|---|---|---|"]
    for r in results:
        if r.stopped_at is not None:
            s = r.steps[r.stopped_at]
            detail = f"step {r.stopped_at + 1} `{s.tool}` refused: {'; '.join(s.reasons)}"
        else:
            detail = "all steps ran" + (f"; escaped: {', '.join(r.external_sends)}" if r.kind == "attack" and r.external_sends else "")
        if r.known_issue:
            detail += f" (known issue: {' '.join(r.known_issue.split())})"
        verdict = {"bypass": "**BYPASS**", "false_positive": "**FALSE POSITIVE**"}.get(r.verdict, r.verdict)
        lines.append(f"| {r.id} | {verdict} | {detail.replace('|', '/')} |")
    return "\n".join(lines) + "\n"
