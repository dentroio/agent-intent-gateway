#!/usr/bin/env bash
# Install AIG into ./.venv, write an observe-first starter policy from your real MCP
# servers' tools, and show what `aig wrap` would change. Changes no client config.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
CLIENT="${1:-cursor}"

echo "Installing AIG into $ROOT/.venv ..."
if command -v uv >/dev/null 2>&1; then
  uv venv --quiet --python 3.12 .venv
  uv pip install --quiet --python .venv/bin/python -e .
else
  PY="$(command -v python3.12 || command -v python3.11 || command -v python3.10 || command -v python3)"
  "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 10))' || {
    echo "AIG needs Python 3.10 or newer, or uv (brew install uv)."; exit 1; }
  "$PY" -m venv .venv
  .venv/bin/pip install --quiet -e .
fi
AIG="$ROOT/.venv/bin/aig"
echo "Installed: $AIG"
echo

echo "Discovering the tools your $CLIENT MCP servers offer (they start briefly, then stop) ..."
"$AIG" policy-init --client "$CLIENT" || true
echo

echo "Plan (nothing is changed):"
"$AIG" wrap --client "$CLIENT" --aig-command "$AIG"
cat <<EOF

When you're ready:
  $AIG wrap --client $CLIENT --aig-command $AIG --apply
  Restart $CLIENT and use its MCP tools as usual. Every call is now decided and logged by AIG.

Watch it:
  $AIG console --policy ~/.aig/policy.yaml --log ~/.aig/logs/$CLIENT.jsonl
  then open http://127.0.0.1:3040

Undo, any time:
  $AIG wrap --undo
EOF
