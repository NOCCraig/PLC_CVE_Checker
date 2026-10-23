"""Decide whether an advisory affects a PLC from the inventory.

A match requires BOTH:
  * the PLC's vendor appears in the advisory (vendor aliases are handled, e.g.
    "Allen-Bradley" == "Rockwell Automation"), and
  * the PLC's model appears in the advisory.

Confidence:
  high    - model found in the structured product list (CPE names / CSAF product tree)
  medium  - model only found in the free-text title/description

The model must appear as a whole token, so "S7-1200" matches "SIMATIC S7-1200 CPU"
but not "S7-12000". Separators are flexible: "S7 1200", "S7-1200" and "S71200" are equal.
"""
from __future__ import annotations

import re
from functools import lru_cache

from .models import CONFIDENCE_RANK, Advisory, Finding, Match, PLC, severity_from_cvss
from .versions import AFFECTED, NOT_AFFECTED, UNKNOWN, check_firmware, describe_ranges

_SEP = r"[\s\-_/\.]*"

# Groups of names that refer to the same maker. Unknown vendors still work -
# they just match on their own name.
_VENDOR_GROUPS: list[set[str]] = [
    {"rockwell automation", "rockwell", "allen-bradley", "allen bradley"},
    {"schneider electric", "schneider", "modicon", "telemecanique"},
    {"ge", "ge vernova", "ge digital", "ge automation", "ge fanuc", "general electric"},
    {"mitsubishi electric", "mitsubishi"},
    {"siemens"},
    {"omron"},
    {"abb"},
    {"honeywell"},
    {"beckhoff"},
    {"wago"},
    {"phoenix contact", "phoenixcontact"},
    {"eaton"},
    {"delta electronics", "delta"},
    {"yokogawa"},
    {"automationdirect", "automation direct", "koyo"},
]

_CORP_SUFFIXES = {"inc", "ltd", "llc", "gmbh", "ag", "corp", "corporation", "co",
                  "company", "plc", "sa", "kg", "limited"}


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


@lru_cache(maxsize=None)
def _alias_regex(alias: str) -> re.Pattern:
    chunks = re.findall(r"[a-z0-9]+", alias.lower())
    body = _SEP.join(re.escape(c) for c in chunks)
    return re.compile(r"(?<![a-z0-9])" + body + r"(?![a-z0-9])")


@lru_cache(maxsize=None)
def vendor_aliases(vendor: str) -> frozenset[str]:
    nv = _norm(vendor)
    for group in _VENDOR_GROUPS:
        for a in group:
            na = _norm(a)
            if na == nv or (len(na) >= 5 and na in nv):
                return frozenset(group)
    words = [w for w in re.findall(r"[a-z0-9]+", vendor.lower()) if w not in _CORP_SUFFIXES]
    aliases = {" ".join(words)} if words else set()
    if words and len(words[0]) >= 4:
        aliases.add(words[0])
    return frozenset(a for a in aliases if a)


def vendor_in_text(vendor: str, text: str) -> bool:
    low = text.lower()
    return any(_alias_regex(a).search(low) for a in vendor_aliases(vendor))


@lru_cache(maxsize=None)
def _model_regex(model: str) -> re.Pattern | None:
    chunks = re.findall(r"[a-z0-9]+", model.lower())
    if not chunks or len("".join(chunks)) < 3:
        return None  # too short to match safely
    body = _SEP.join(re.escape(c) for c in chunks)
    return re.compile(r"(?<![a-z0-9])" + body + r"(?![a-z0-9])")


def model_in_text(model: str, text: str) -> bool:
    rx = _model_regex(model)
    return bool(rx and rx.search(text.lower()))


def match_one(plc: PLC, adv: Advisory) -> Match | None:
    vendor_haystack = " ".join([*adv.vendors, *adv.products, adv.title, adv.description])
    if not vendor_in_text(plc.vendor, vendor_haystack):
        return None
    matched = [p for p in adv.products if model_in_text(plc.model, p)]
    if matched:
        ranges = [r for r in adv.ranges if r.product in matched]
        return Match(plc, adv, "high", f"Model found in affected product: {matched[0]}",
                     check_firmware(plc.firmware, ranges), describe_ranges(ranges))
    free_text = f"{adv.title} {adv.description}"
    if model_in_text(plc.model, free_text):
        # Text-only mention: no version ranges, so a given firmware can't be checked.
        return Match(plc, adv, "medium", "Model mentioned in advisory text",
                     check_firmware(plc.firmware, []), "")
    return None


def find_matches(plcs: list[PLC], advisories: list[Advisory], min_confidence: str = "medium") -> list[Match]:
    floor = CONFIDENCE_RANK[min_confidence]
    out: list[Match] = []
    for plc in plcs:
        for adv in advisories:
            m = match_one(plc, adv)
            if m and CONFIDENCE_RANK[m.confidence] >= floor:
                out.append(m)
    return out


def consolidate(matches: list[Match]) -> list[Finding]:
    """Merge the same CVE reported by several sources into one row per PLC."""
    grouped: dict[tuple, Finding] = {}
    for m in matches:
        a = m.advisory
        key = (m.plc, a.cve_id or a.advisory_id)
        f = grouped.get(key)
        if f is None:
            grouped[key] = Finding(
                plc=m.plc, cve_id=a.cve_id, confidence=m.confidence, cvss=a.cvss,
                severity=a.severity or severity_from_cvss(a.cvss),
                known_exploited=a.known_exploited, sources=[a.source],
                advisory_ids=[a.advisory_id] if a.advisory_id else [],
                published=a.published, title=a.title or a.description[:200],
                reason=m.reason, urls=[a.url] if a.url else [],
                firmware_status=m.firmware_status, affected_versions=m.affected_versions,
            )
            continue
        if CONFIDENCE_RANK[m.confidence] > CONFIDENCE_RANK[f.confidence]:
            f.confidence, f.reason = m.confidence, m.reason
        if a.cvss is not None and (f.cvss is None or a.cvss > f.cvss):
            f.cvss = a.cvss
            f.severity = a.severity or severity_from_cvss(a.cvss)
        f.known_exploited = f.known_exploited or a.known_exploited
        f.firmware_status = _merge_status(f.firmware_status, m.firmware_status)
        if m.affected_versions and m.affected_versions not in f.affected_versions:
            f.affected_versions = "; ".join(filter(None, [f.affected_versions, m.affected_versions]))
        if a.source not in f.sources:
            f.sources.append(a.source)
        if a.advisory_id and a.advisory_id not in f.advisory_ids:
            f.advisory_ids.append(a.advisory_id)
        if a.url and a.url not in f.urls:
            f.urls.append(a.url)
        if not f.title and (a.title or a.description):
            f.title = a.title or a.description[:200]
        if a.published and (not f.published or a.published < f.published):
            f.published = a.published
    return sorted(
        grouped.values(),
        key=lambda f: (-(f.cvss or 0), f.plc.vendor, f.plc.model, f.cve_id),
    )


_STATUS_PRIORITY = {AFFECTED: 3, UNKNOWN: 2, NOT_AFFECTED: 1, "": 0}


def _merge_status(a: str, b: str) -> str:
    """Be conservative when sources disagree: affected > unknown > not affected."""
    return a if _STATUS_PRIORITY[a] >= _STATUS_PRIORITY[b] else b


def split_ruled_out(findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
    """Separate findings whose affected versions exclude the PLC's firmware."""
    kept = [f for f in findings if f.firmware_status != NOT_AFFECTED]
    ruled_out = [f for f in findings if f.firmware_status == NOT_AFFECTED]
    return kept, ruled_out
