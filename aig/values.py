"""Value-level data-flow tracking at the gateway.

Session-level labels answer "has this agent *seen* finance data?". Value-level
tracking answers "does *this call* carry finance data?", which is what an
egress decision actually needs.

How it works, without modifying the agent:

1. Every labelled tool result passing back through the gateway is broken into
   *atoms*: identifiers (TX-1042), numbers (18450), email addresses and
   distinctive words (Northwind). Atoms are indexed under the result's labels.
2. Every outgoing call's arguments are decoded (URL-encoding, HTML entities,
   base64, hex, nested JSON) and normalised (case, Unicode, punctuation and
   spacing), then searched for indexed atoms.
3. A label is *present* in a call if one strong atom (identifier, number,
   email) or `WORD_THRESHOLD` distinct words match.

What it cannot see: data an LLM has re-expressed in new words ("the cloud
vendor is owed roughly seventy-two thousand"). Flow rules therefore choose a
`residual` action for "session holds the label but no values were found";
integrity rules (prompt injection) should stay session-level, because
influence on a decision is not visible in values at all.

Atoms live only in gateway memory for the session's lifetime: the same data
is already in the agent's context. If the index fills up, the affected
labels fail closed back to session-level behaviour.
"""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import json
import re
import unicodedata
import zlib
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import unquote

WORD_THRESHOLD = 2
MIN_COMPACT = 5            # strong atoms at least this long are also found inside mangled text
MAX_ATOMS = 100_000
MAX_DECODE_DEPTH = 2

_EMAIL = re.compile(r"[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}")
_TOKEN = re.compile(r"[a-z0-9][a-z0-9_-]*")
_NUMBER = re.compile(r"(?<![a-z0-9.])\d[\d,]*(?:\.\d+)?")
_WORD = re.compile(r"[a-z]{5,}")
_B64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
_B32 = re.compile(r"[A-Z2-7]{16,}=*")
MAX_UNPACK = 1 << 20       # decompressed bytes per encoded token
HISTORY = 4096             # compact characters of earlier outbound calls kept per sink

# Words too common to identify anything on their own.
STOPWORDS = frozenset("""
about above after again against along already although always among another
answer anyone around attached based because before being below between both
cannot check class could customer daily dates details different during each
email every first following found from further given great having hours
however include including information internal invoice items known large
later least message might money month needs never number often
order other others paid payment pending please point possible process
received reply report request right scheduled second should since small
status still subject summary system thank thanks their there these thing
think those though three through today total under until update using
value vendor where which while within without would years""".split())


def _norm(text: str) -> str:
    t = unicodedata.normalize("NFKC", text).casefold()
    if not t.isascii():   # any script's decimal digits count as digits (Arabic-Indic, Devanagari, ...)
        t = "".join(str(unicodedata.decimal(c)) if c.isdecimal() and not c.isascii() else c for c in t)
    return t


def _compact(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text)


def _norm_number(raw: str) -> str | None:
    n = raw.replace(",", "")
    if "." in n:
        n = n.rstrip("0").rstrip(".")
    digits = n.replace(".", "")
    return n if len(digits) >= 4 else None


@dataclass
class Atoms:
    strong: set[str] = field(default_factory=set)   # identifiers, numbers, emails (compact forms)
    words: set[str] = field(default_factory=set)


def _leaves(value: Any, depth: int = 0) -> Iterable[str]:
    """String leaves of a JSON value. Keys are skipped: they name fields, they aren't data."""
    if isinstance(value, dict):
        for v in value.values():
            yield from _leaves(v, depth)
    elif isinstance(value, list):
        for v in value:
            yield from _leaves(v, depth)
    elif isinstance(value, bool) or value is None:
        return
    elif isinstance(value, (int, float)):
        yield str(value)
    elif isinstance(value, str):
        s = value.strip()
        if depth < 3 and s[:1] in "[{":
            try:
                yield from _leaves(json.loads(s), depth + 1)
                return
            except json.JSONDecodeError:
                pass
        yield value


def extract(text: str) -> Atoms:
    """Atoms of a tool result (or of one decoded argument)."""
    s = text.strip()
    if s[:1] in "[{":
        try:
            parts = list(_leaves(json.loads(s)))
        except json.JSONDecodeError:
            parts = [text]
    else:
        parts = [text]
    out = Atoms()
    for part in parts:
        t = _norm(part)
        out.strong.update(_EMAIL.findall(t))
        for tok in _TOKEN.findall(t):
            c = _compact(tok)
            if len(c) >= 4 and re.search(r"[a-z]", c) and re.search(r"\d", c):
                out.strong.add(c)
        for raw in _NUMBER.findall(t):
            if (n := _norm_number(raw)) is not None:
                out.strong.add(n)
        # Words inside email addresses ("example" in ap@fabrikam.example) are not data; the address is.
        out.words.update(w for w in _WORD.findall(_EMAIL.sub(" ", t)) if w not in STOPWORDS)
    return out


def _printable(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    ok = sum(ch.isprintable() or ch in "\n\r\t" for ch in s)
    return s if s and ok / len(s) > 0.9 else None


def _unpack(b: bytes) -> bytes:
    """Undo gzip / zlib compression, bounded so a decompression bomb can't stall the gateway."""
    if b[:2] == b"\x1f\x8b" or (len(b) > 1 and b[0] == 0x78 and (b[0] * 256 + b[1]) % 31 == 0):
        try:
            d = zlib.decompressobj(zlib.MAX_WBITS | 32)   # auto-detect gzip or zlib header
            return d.decompress(b, MAX_UNPACK)
        except zlib.error:
            return b
    return b


def _decoded_text(b: bytes) -> str | None:
    return _printable(_unpack(b))


def variants(text: str, depth: int = 0) -> list[str]:
    """The text plus every decoding of it the gateway knows how to undo."""
    out = [text]
    cands = [unquote(text), unquote(unquote(text)), html.unescape(text)]
    if depth == 0:
        cands += [text[::-1], codecs.encode(text, "rot13")]   # reversal and ROT13 cost nothing to undo
    for dec in cands:
        if dec not in out:
            out.append(dec)
    if depth >= MAX_DECODE_DEPTH:
        return out
    decoded: list[str] = []
    for tok in _B64.findall(text):
        for fn in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                if (s := _decoded_text(fn(tok + "=" * (-len(tok) % 4)))) is not None:
                    decoded.append(s)
                    break
            except (binascii.Error, ValueError):
                continue
    for tok in _B32.findall(text):
        try:
            if (s := _decoded_text(base64.b32decode(tok + "=" * (-len(tok) % 8)))) is not None:
                decoded.append(s)
        except (binascii.Error, ValueError):
            pass
    for tok in _HEX.findall(text):
        if (s := _decoded_text(bytes.fromhex(tok))) is not None:
            decoded.append(s)
    for s in decoded:
        out.extend(v for v in variants(s, depth + 1) if v not in out)
    return out


def _arg_texts(args: dict[str, Any]) -> list[tuple[str, str]]:
    out = []
    for name, value in args.items():
        for leaf in _leaves(value, depth=3):   # don't parse JSON-looking args yet; extract() does
            out.append((name, leaf))
    return out


@dataclass
class Evidence:
    label: str
    origin: str
    args: set[str] = field(default_factory=set)
    strong: set[str] = field(default_factory=set)
    words: set[str] = field(default_factory=set)
    overflow: bool = False

    def describe(self, redact: bool = False) -> str:
        """Human-readable evidence. redact=True leaves the data values out (for telemetry)."""
        if self.overflow:
            return f"{self.label!r} value index is full, so every call is treated as carrying it"
        if redact:
            return (f"argument {', '.join(sorted(self.args))} carries {self.label!r} values "
                    f"({len(self.strong)} identifiers/amounts, {len(self.words)} words) from {self.origin}")
        shown = sorted(self.strong)[:3] + sorted(self.words)[: max(0, 3 - len(self.strong))]
        more = len(self.strong) + len(self.words) - len(shown)
        vals = ", ".join(repr(v) for v in shown) + (f" +{more} more" if more > 0 else "")
        return (f"argument {', '.join(sorted(self.args))} carries {self.label!r} values "
                f"({vals}) from {self.origin}")


class ValueIndex:
    """Atoms seen in labelled tool results, per session."""

    def __init__(self, max_atoms: int = MAX_ATOMS):
        self.max_atoms = max_atoms
        self.strong: dict[str, dict[str, str]] = {}   # atom -> {label: origin}
        self.words: dict[str, dict[str, str]] = {}
        self.overflow: dict[str, str] = {}             # label -> origin
        self._prefixes: dict[str, list[str]] | None = None   # first MIN_COMPACT chars -> atoms

    def _prefix_index(self) -> dict[str, list[str]]:
        if self._prefixes is None:
            self._prefixes = {}
            for atom in self.strong:
                if len(atom) >= MIN_COMPACT:
                    self._prefixes.setdefault(atom[:MIN_COMPACT], []).append(atom)
        return self._prefixes

    def _in_compact(self, compact: str, min_end: int = 0) -> set[str]:
        """Strong atoms that occur anywhere inside mangled text: one dict lookup per position.

        With min_end, only occurrences that end after that offset count (used to search
        earlier outbound calls + this call, for matches that reach into this call)."""
        prefixes, found = self._prefix_index(), set()
        for i in range(max(0, min_end - 64), len(compact) - MIN_COMPACT + 1):
            for atom in prefixes.get(compact[i:i + MIN_COMPACT], ()):
                if compact.startswith(atom, i) and i + len(atom) > min_end:
                    found.add(atom)
        return found

    def __len__(self) -> int:
        return len(self.strong) + len(self.words)

    def add(self, text: str, labels: dict[str, str]) -> None:
        if not labels or not text:
            return
        atoms = extract(text)
        self._prefixes = None
        for table, found in ((self.strong, atoms.strong), (self.words, atoms.words)):
            for atom in found:
                if atom not in table and len(self) >= self.max_atoms:
                    for label, origin in labels.items():
                        self.overflow.setdefault(label, origin)
                    continue
                slot = table.setdefault(atom, {})
                for label, origin in labels.items():
                    slot.setdefault(label, origin)

    def find(self, args: dict[str, Any], history: dict[str, str] | None = None,
             sent_words: dict[str, set[str]] | None = None, raw: bool = False) -> dict[str, Evidence]:
        """Labels whose values appear in these arguments, with evidence.

        history: per argument, compact text of that argument in earlier calls to the same
        sink, so data split across several calls is found when its last piece is sent. sent_words: words of each
        label already sent to that sink. raw=True skips the presence threshold."""
        hits: dict[str, Evidence] = {}

        def hit(label: str, origin: str, arg: str) -> Evidence:
            ev = hits.setdefault(label, Evidence(label, origin))
            ev.args.add(arg)
            return ev

        if not (self.strong or self.words or self.overflow):
            return {}
        for arg, leaf in _arg_texts(args):
            for text in variants(leaf):
                atoms = extract(text)
                matched = (atoms.strong & self.strong.keys()) | self._in_compact(_compact(_norm(text)))
                for atom in matched:              # the compact pass survives spacing / punctuation games
                    for label, origin in self.strong[atom].items():
                        hit(label, origin, arg).strong.add(atom)
                for atom in atoms.words & self.words.keys():
                    for label, origin in self.words[atom].items():
                        hit(label, origin, arg).words.add(atom)

        # Data split across arguments, or across this call and earlier ones to the same sink.
        leaves = _arg_texts(args)
        if leaves and self.strong:
            single = {a for ev in hits.values() for a in ev.strong}   # already found in one argument
            names = sorted({n for n, _ in leaves})
            parts = [_compact(_norm(t)) for _, t in leaves]
            searches = [("".join(parts), 0, names, False), ("".join(reversed(parts)), 0, names, False)]
            for name in names:   # each argument continued from the same argument in earlier calls
                prev = (history or {}).get(name, "")
                if prev:
                    cur = "".join(_compact(_norm(t)) for n, t in leaves if n == name)
                    searches.append((prev + cur, len(prev), [name], True))
            for joined, start, where, earlier in searches:
                for atom in self._in_compact(joined, start):
                    if atom in single:
                        continue
                    for label, origin in self.strong[atom].items():
                        ev = hit(label, origin, where[0])
                        ev.args.update(where)
                        if earlier:
                            ev.args.add("earlier calls")
                        ev.strong.add(atom)
        if raw:
            return hits

        sent_words = sent_words or {}
        present = {l: e for l, e in hits.items()
                   if e.strong or len(e.words | sent_words.get(l, set())) >= WORD_THRESHOLD}
        for l, e in present.items():
            if not e.strong and len(e.words) < WORD_THRESHOLD:
                e.args.add("earlier calls")
        for label, origin in self.overflow.items():
            present.setdefault(label, Evidence(label, origin, overflow=True))
        return present
