"""Firmware version parsing and affected-range checks.

Firmware strings in the wild are messy ("V4.5.0", "32.011", "21.00.01", "V2.9 SP1").
We compare the first dotted run of digits in each string, numerically, padding the
shorter one with zeros. Anything after it ("SP1", "-beta") is ignored, and a string
with no digits can't be compared (the result is then 'unknown', never a guess).
"""
from __future__ import annotations

import re

from .models import VersionRange

_NUM = re.compile(r"\d+(?:[._]\d+)*")

AFFECTED = "affected"
NOT_AFFECTED = "not affected"
UNKNOWN = "unknown"


def parse_version(s: str | None) -> tuple[int, ...] | None:
    if not s:
        return None
    m = _NUM.search(str(s))
    if not m:
        return None
    return tuple(int(p) for p in re.split(r"[._]", m.group(0)))


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def range_contains(r: VersionRange, version: tuple[int, ...]) -> bool | None:
    """True/False, or None if the range's own bounds can't be parsed."""
    if r.all_versions:
        return True
    if r.start is not None:
        s = parse_version(r.start)
        if s is None:
            return None
        c = _cmp(version, s)
        if c < 0 or (c == 0 and not r.start_incl):
            return False
    if r.end is not None:
        e = parse_version(r.end)
        if e is None:
            return None
        c = _cmp(version, e)
        if c > 0 or (c == 0 and not r.end_incl):
            return False
    return True


def describe_range(r: VersionRange) -> str:
    if r.all_versions:
        return "all versions"
    if r.start is not None and r.end is not None and r.start == r.end and r.start_incl and r.end_incl:
        return f"= {r.start}"
    parts = []
    if r.start is not None:
        parts.append(f"{'>=' if r.start_incl else '>'} {r.start}")
    if r.end is not None:
        parts.append(f"{'<=' if r.end_incl else '<'} {r.end}")
    return ", ".join(parts)


def describe_ranges(ranges: list[VersionRange], limit: int = 200) -> str:
    seen: list[str] = []
    for r in ranges:
        d = describe_range(r)
        if d and d not in seen:
            seen.append(d)
    text = "; ".join(seen)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def check_firmware(firmware: str, ranges: list[VersionRange]) -> str:
    """Compare a PLC's firmware to affected ranges.

    Returns "" when no firmware was given, otherwise AFFECTED, NOT_AFFECTED or UNKNOWN.
    """
    if not firmware:
        return ""
    version = parse_version(firmware)
    if version is None or not ranges:
        return UNKNOWN
    results = [range_contains(r, version) for r in ranges]
    if any(x is True for x in results):
        return AFFECTED
    if any(x is None for x in results):
        return UNKNOWN
    return NOT_AFFECTED


def parse_vers(spec: str, product: str = "") -> list[VersionRange]:
    """Parse a CSAF/VERS string like 'vers:intdot/>=4.0|<4.5.0' into ranges.

    Returns [] if the spec can't be understood (callers treat that as 'unknown').
    """
    spec = spec.strip()
    if spec.lower().startswith("vers:"):
        spec = spec[5:]
    if "/" not in spec:
        return []
    _scheme, _, body = spec.partition("/")
    body = body.strip()
    if body == "*":
        return [VersionRange(product=product, all_versions=True)]

    constraints: list[tuple[str, str]] = []
    for token in body.split("|"):
        m = re.fullmatch(r"\s*(>=|<=|!=|<|>|=)?\s*(.+?)\s*", token)
        if not m:
            return []
        constraints.append((m.group(1) or "=", m.group(2)))

    ranges: list[VersionRange] = []
    i = 0
    while i < len(constraints):
        op, v = constraints[i]
        if op in (">", ">="):
            nxt = constraints[i + 1] if i + 1 < len(constraints) else None
            if nxt and nxt[0] in ("<", "<="):
                ranges.append(VersionRange(product, v, op == ">=", nxt[1], nxt[0] == "<="))
                i += 2
                continue
            ranges.append(VersionRange(product, start=v, start_incl=op == ">="))
        elif op in ("<", "<="):
            ranges.append(VersionRange(product, end=v, end_incl=op == "<="))
        elif op == "=":
            ranges.append(VersionRange(product, v, True, v, True))
        # '!=' carves a hole in another range; ignoring it only errs towards "affected".
        i += 1
    return ranges
