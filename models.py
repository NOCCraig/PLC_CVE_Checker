"""Shared data structures."""
from __future__ import annotations

from dataclasses import dataclass, field

CONFIDENCE_RANK = {"low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class PLC:
    """One row of the PLC inventory spreadsheet."""

    vendor: str
    model: str
    location: str = ""
    owner: str = ""
    row: int = 0  # spreadsheet row number, for traceability
    firmware: str = ""  # optional; enables the affected-version check


@dataclass(frozen=True)
class VersionRange:
    """A range of affected versions for one product. Bounds are strings as
    published; versions.py parses them when comparing."""

    product: str
    start: str | None = None
    start_incl: bool = True
    end: str | None = None
    end_incl: bool = True
    all_versions: bool = False


@dataclass
class Advisory:
    """A vulnerability record from any source, normalised to one shape."""

    cve_id: str
    source: str  # "NVD" or "CISA"
    title: str = ""
    description: str = ""
    published: str = ""  # ISO date (YYYY-MM-DD)
    modified: str = ""  # ISO date (YYYY-MM-DD)
    cvss: float | None = None
    severity: str = ""
    advisory_id: str = ""
    url: str = ""
    vendors: list[str] = field(default_factory=list)
    # Structured product names: CPE vendor/product pairs (NVD) or the CSAF
    # product tree (CISA). Matches here are "high" confidence.
    products: list[str] = field(default_factory=list)
    # Affected version ranges per product (same product strings as above).
    ranges: list[VersionRange] = field(default_factory=list)
    known_exploited: bool = False


@dataclass
class Match:
    plc: PLC
    advisory: Advisory
    confidence: str  # "high" or "medium"
    reason: str
    firmware_status: str = ""  # "", "affected", "not affected" or "unknown"
    affected_versions: str = ""  # human-readable affected ranges, if known


@dataclass
class Finding:
    """One PLC x one CVE, merged across sources."""

    plc: PLC
    cve_id: str
    confidence: str
    cvss: float | None
    severity: str
    known_exploited: bool
    sources: list[str]
    advisory_ids: list[str]
    published: str
    title: str
    reason: str
    urls: list[str]
    firmware_status: str = ""
    affected_versions: str = ""


def severity_from_cvss(score: float | None) -> str:
    if score is None:
        return ""
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"
