"""Labels that outlive a session.

When an agent writes into a shared store (a docs space, a ticket queue, a
bucket), the data it writes carries the labels of everything that agent has
read. Any later reader -- a different agent, a different session -- picks
those labels up. This is what stops cross-agent laundering: finance data
written into "internal" docs is still finance data.

In-memory by default; give it a path to share labels between gateway
processes (one per agent session). File access is serialised with flock.
"""
from __future__ import annotations

import fcntl
import json
import os
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

# resource -> {label: provenance}
State = dict[str, dict[str, str]]


class LabelStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self._mem: State = {}
        self._lock = threading.Lock()

    @contextmanager
    def _state(self, write: bool) -> Iterator[State]:
        if self.path is None:
            with self._lock:
                yield self._mem
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        with os.fdopen(fd, "r+", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX if write else fcntl.LOCK_SH)
            raw = fh.read()
            state: State = json.loads(raw) if raw.strip() else {}
            yield state
            if write:
                fh.seek(0)
                fh.truncate()
                json.dump(state, fh, sort_keys=True)

    def add(self, resource: str, labels: dict[str, str]) -> None:
        if not labels:
            return
        with self._state(write=True) as st:
            item = st.setdefault(resource, {})
            for label, origin in labels.items():
                item.setdefault(label, origin)

    def get(self, store: str, resource: str | None) -> dict[str, str]:
        """Labels on one item, or on every item in the store when resource is None."""
        out: dict[str, str] = {}
        with self._state(write=False) as st:
            for key, labels in st.items():
                if key == resource or (resource is None and (key == store or key.startswith(store + ":"))):
                    for label, origin in labels.items():
                        out.setdefault(label, origin)
        return out
