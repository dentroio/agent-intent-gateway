"""The scenario library is the regression suite: every attack stays blocked,
every workload completes (unless it is a documented known issue)."""
from pathlib import Path

import pytest

from aig import load_policy
from aig.redteam import load_scenarios, run_scenario

ROOT = Path(__file__).parent.parent
POLICY = load_policy(ROOT / "examples" / "enterprise.yaml")
SCENARIOS = load_scenarios(ROOT / "scenarios")


@pytest.mark.parametrize("spec", SCENARIOS, ids=[s["id"] for s in SCENARIOS])
def test_scenario(spec):
    r = run_scenario(POLICY, spec)
    if spec.get("known_issue"):
        pytest.xfail(" ".join(spec["known_issue"].split()))
    assert r.passed, f"{r.id}: {r.verdict}; steps={[(s.tool, s.outcome, s.reasons) for s in r.steps]}"
    if r.kind == "attack":
        assert not any(e.startswith("email to") for e in r.external_sends), r.external_sends


def test_library_covers_attacks_and_workloads():
    kinds = {s["kind"] for s in SCENARIOS}
    assert kinds == {"attack", "workload"}
    assert len({s["id"] for s in SCENARIOS}) == len(SCENARIOS)
