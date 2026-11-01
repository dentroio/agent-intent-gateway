"""Tamper-evident decision log.

Each record is one JSON line carrying the SHA-256 of the previous record, so
deleting, reordering or editing any entry breaks the chain from that point on.
Built for after-the-fact forensics: "what did this agent try, for whom, and why
was it allowed?"
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Iterator

GENESIS = "0" * 64


def _digest(prev: str, body: dict[str, Any]) -> str:
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + canonical).encode()).hexdigest()


class Ledger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._prev = GENESIS
        if self.path.exists():
            for rec in self._records():
                self._prev = rec["hash"]

    def _records(self) -> Iterator[dict[str, Any]]:
        with open(self.path, encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    yield json.loads(line)

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        body = {"ts": time.time(), **event, "prev": self._prev}
        record = {**body, "hash": _digest(self._prev, body)}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True) + "\n")
        self._prev = record["hash"]
        return record


def verify(path: str | Path) -> tuple[bool, int, str]:
    """Return (ok, records_checked, message)."""
    prev = GENESIS
    n = 0
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            if not line.strip():
                continue
            rec = json.loads(line)
            claimed = rec.pop("hash", None)
            if rec.get("prev") != prev:
                return False, n, f"line {lineno}: chain broken (record does not follow the previous one)"
            if _digest(prev, rec) != claimed:
                return False, n, f"line {lineno}: contents altered"
            prev = claimed
            n += 1
    return True, n, f"{n} records verified"
