"""Build the AIG console with an embedded demo snapshot.

    python scripts/build_console_demo.py      # writes docs/console-demo/index.html

The traffic is real gateway output, not hand-written records: the scenario
library is replayed through the Clarion-managed gateway (legitimate workloads
repeated as everyday traffic, every attack once), with one hash-chained
decision log and one AegisFlux event stream. Timestamps are spread over the
last day so the console reads like a working gateway; the console marks the
whole snapshot as demo data.
"""
from __future__ import annotations

import json
import random
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from aig import load_policy  # noqa: E402
from aig.aegis import OutcomeEmitter  # noqa: E402
from aig.clarion import apply_overlays, compile_intent  # noqa: E402
from aig.console import build_snapshot  # noqa: E402
from aig.ledger import Ledger  # noqa: E402
from aig.redteam import load_scenarios, run_all, run_scenario, scoreboard  # noqa: E402
from build_demo import INTENTS, check_js_verifier, configs, result_json  # noqa: E402

UI = ROOT / "ui" / "console"
OUT = ROOT / "docs" / "console-demo" / "index.html"
DEVICES = {"expense-bot": ["fin-laptop-07", "fin-laptop-11", "fin-vdi-03"], "research-assistant": ["dev-laptop-12", "dev-laptop-19"],
           "plant-monitor": ["ot-gw-01"]}


def main(rounds: int = 8, seed: int = 7) -> None:
    rng = random.Random(seed)
    key = Ed25519PrivateKey.generate()
    base = load_policy(ROOT / "examples" / "clarion" / "gateway-base.yaml")
    bundles, reports, titles = [], {}, {}
    for name in INTENTS:
        intent = json.loads((ROOT / "examples" / "clarion" / f"{name}.intent.json").read_text())
        res = compile_intent(intent, base, key=key, key_id="clarion-prod-2026-11")
        bundles.append(res.bundle)
        reports[intent["intent_id"]], titles[intent["intent_id"]] = res.report, intent["title"]
    policy = apply_overlays(base, bundles, key.public_key())

    scenarios = load_scenarios(ROOT / "scenarios")
    workloads = [s for s in scenarios if s["kind"] == "workload"]
    attacks = [s for s in scenarios if s["kind"] == "attack"]
    plan = [w for _ in range(rounds) for w in workloads] + attacks
    rng.shuffle(plan)

    t = [time.time() - 26 * 3600]

    def clock() -> float:
        t[0] += rng.uniform(40, 600) + rng.random() / 1000   # keep a fractional part, as real clocks do
        return round(t[0], 6)

    with tempfile.TemporaryDirectory() as d:
        tmp = Path(d)
        ledger = Ledger(tmp / "decisions.jsonl", clock=clock)
        emitter = OutcomeEmitter(tmp / "events.jsonl", actor_id="aig:aegis-gateway-01")
        emitter_clock = emitter.__call__

        def emit(session, tool, decision, final, record):
            # Outcome events share the decision's timestamp so both views line up.
            from aig.aegis import outcome_events
            events = outcome_events(session, tool, decision, final, record, emitter.actor_id,
                                    now_ms=int((record or {}).get("ts", time.time()) * 1000))
            with open(tmp / "events.jsonl", "a", encoding="utf-8") as fh:
                for e in events:
                    fh.write(json.dumps(e, sort_keys=True) + "\n")
        del emitter_clock

        counter = {"n": 0}

        def attrs_for(agent, principal, spec):
            counter["n"] += 1
            return {"instance": f"inst-{rng.randrange(16**6):06x}", "device": rng.choice(DEVICES.get(agent, ["unknown-device"]))}

        for spec in plan:
            run_scenario(policy, spec, ledger=ledger, on_decision=emit, attrs_for=attrs_for)

        cfgs, _ = configs()
        redteam = {"configs": []}
        for k, name, desc, pol in cfgs:
            results = run_all(pol, scenarios)
            redteam["configs"].append({"key": k, "name": name, "description": desc,
                                       "scoreboard": scoreboard(results), "results": [result_json(r) for r in results]})
        commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
        snap = build_snapshot(policy, decisions_path=tmp / "decisions.jsonl", events_path=tmp / "events.jsonl",
                              redteam=redteam, bundles=bundles, intent_reports=reports, demo=True, commit=commit or "unknown",
                              gateway={"transport": "HTTP behind the steering gateway", "audience": "aegis-gateway-01"})
        for it in snap["intents"]:
            it["title"] = titles.get(it["intent_id"])
        assert snap["chain"]["ok"], snap["chain"]
        check_js_verifier(snap["decisions"], tmp)

    subprocess.run(["npm", "run", "build", "--silent"], cwd=UI, check=True)
    page = (UI / "dist" / "index.html").read_text()
    marker = "window.__AIG_SNAPSHOT__ = null"
    assert page.count(marker) == 1, "snapshot placeholder missing from the built console"
    page = page.replace(marker, "window.__AIG_SNAPSHOT__ = " + json.dumps(snap, separators=(",", ":")).replace("</", "<\\/"))
    # Published pages get their own document skeleton, so keep only the content.
    import re
    for pat in (r"<!doctype html>\s*", r"<html[^>]*>\s*", r"</html>\s*", r"<head>\s*", r"</head>\s*", r"<body>\s*",
                r"</body>\s*", r'<meta charset="UTF-8"\s*/?>\s*', r'<meta name="viewport"[^>]*>\s*'):
        page = re.sub(pat, "", page, count=1, flags=re.I)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(page)
    kinds = {}
    from aig.console import outcome_kind
    for r in snap["decisions"]:
        kinds[outcome_kind(r)] = kinds.get(outcome_kind(r), 0) + 1
    print(f"{len(snap['decisions'])} decisions {kinds}, {len(snap['events'])} outcome events; chain verified in Python and JS")
    print(f"wrote {OUT} ({len(page) // 1024} KB)")


if __name__ == "__main__":
    main()
