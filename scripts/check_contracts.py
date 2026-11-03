"""Report drift between AIG's pinned AegisFlux contracts and a current AegisFlux checkout.

    python scripts/check_contracts.py ../aegisflux

Read-only: never modifies either repository. Exit code 0 means no drift,
1 means at least one contract changed upstream, 2 means a usage error.
"""
from __future__ import annotations

import difflib
import json
import sys
from pathlib import Path

PINNED = Path(__file__).resolve().parent.parent / "contracts" / "aegisflux"
UPSTREAM = {
    "segmentation-policy-intent.v1.schema.json": "schemas/segmentation/segmentation-policy-intent.v1.schema.json",
    "segmentation-compiled-artifact.v1.schema.json": "schemas/segmentation/segmentation-compiled-artifact.v1.schema.json",
    "segmentation-outcome-event.v1.schema.json": "schemas/segmentation/segmentation-outcome-event.v1.schema.json",
    "example.code_agent_mcp_bridge.intent.json": "schemas/segmentation/examples/code_agent_mcp_bridge.intent.json",
}


def _norm(path: Path) -> list[str]:
    return json.dumps(json.loads(path.read_text()), indent=1, sort_keys=True).splitlines()


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not Path(argv[1]).is_dir():
        print(__doc__.strip(), file=sys.stderr)
        return 2
    root, drift = Path(argv[1]), 0
    for pinned, rel in UPSTREAM.items():
        upstream = root / rel
        if not upstream.exists():
            print(f"MISSING  {rel} (removed or renamed upstream)")
            drift += 1
            continue
        diff = list(difflib.unified_diff(_norm(PINNED / pinned), _norm(upstream), "pinned", "upstream", lineterm="", n=1))
        if diff:
            drift += 1
            print(f"CHANGED  {rel}")
            for line in diff[2:40]:
                print(f"    {line}")
            if len(diff) > 40:
                print(f"    ... {len(diff) - 40} more lines")
        else:
            print(f"same     {rel}")
    print(f"\n{drift} contract(s) drifted" if drift else "\nno drift")
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
