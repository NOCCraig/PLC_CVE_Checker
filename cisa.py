"""CISA sources.

* ICS advisories, read from CISA's public CSAF repository on GitHub
  (https://github.com/cisagov/CSAF). These are machine-readable and name the
  affected vendor/product, which is exactly what we need to match PLCs.
* Known Exploited Vulnerabilities (KEV) catalog, used to flag CVEs that are
  being exploited in the wild.

Downloaded advisories are cached on disk, so repeat runs only fetch what changed.
"""
from __future__ import annotations

import csv
import io
import json
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import requests

from .models import Advisory, VersionRange
from .versions import parse_vers

log = logging.getLogger(__name__)

CSAF_BASE = "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _parse_ts(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def list_advisories(session: requests.Session, since: datetime | None) -> list[tuple[str, str]]:
    """Return (relative_path, last_updated_timestamp) from CISA's changes.csv."""
    r = session.get(CSAF_BASE + "changes.csv", timeout=60)
    r.raise_for_status()
    out = []
    for row in csv.reader(io.StringIO(r.text)):
        if len(row) < 2:
            continue
        path, ts = row[0], row[1]
        if since and _parse_ts(ts) < since:
            continue
        out.append((path, ts))
    return out


def _fetch_document(session: requests.Session, path: str, ts: str, cache_dir: Path | None) -> dict:
    cache_file = None
    if cache_dir:
        cache_file = cache_dir / "cisa" / path.replace("/", "_")
        if cache_file.exists():
            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                if cached.get("updated") == ts:
                    return cached["doc"]
            except (OSError, ValueError):
                pass
    r = session.get(CSAF_BASE + path, timeout=60)
    r.raise_for_status()
    doc = r.json()
    if cache_file:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        cache_file.write_text(json.dumps({"updated": ts, "doc": doc}), encoding="utf-8")
    return doc


def _split_name(full: str) -> tuple[str, str | None]:
    """'ControlLogix 1756-L83E : vers:intdot/<4.5' -> (name, 'intdot/<4.5')."""
    base, _, spec = full.partition(" : vers:")
    return base.strip(), (spec.strip() or None)


_PLAIN_VERSION = re.compile(r"[Vv]?\d+(?:[._]\d+)*")


def _walk_branches(
    branches: list[dict] | None,
    vendors: set[str],
    names: set[str],
    pid_info: dict[str, tuple[str, str | None]],
    product_name: str = "",
) -> None:
    """Collect vendors, product names and, per product id, (name, version spec).

    CISA's CSAF puts the affected versions on the branch *above* each product, e.g.
    category product_version_range, name 'vers:intdot/>=3.1.6', so we pass the nearest
    product name and that branch's spec down to the product entry.
    """
    for b in branches or []:
        cat, name = b.get("category"), b.get("name", "")
        here = product_name
        if cat == "vendor" and name:
            vendors.add(name)
        elif cat in ("product_name", "product_family") and name:
            names.add(name)
            here = name
        spec = None
        if cat in ("product_version", "product_version_range") and name:
            if name.lower().startswith("vers:"):
                spec = name[5:]
            elif cat == "product_version" and _PLAIN_VERSION.fullmatch(name.strip()):
                spec = "generic/=" + name.strip()
        _register(b.get("product"), names, pid_info, here, spec)
        _walk_branches(b.get("branches"), vendors, names, pid_info, here)


def _register(product: dict | None, names: set[str], pid_info: dict,
              parent_name: str = "", spec: str | None = None) -> None:
    if not product or not product.get("name"):
        return
    base, inline_spec = _split_name(product["name"])
    if parent_name:
        base = parent_name
    names.add(base)
    if product.get("product_id"):
        pid_info[product["product_id"]] = (base, spec or inline_spec)


def parse_csaf(doc: dict) -> list[Advisory]:
    """One Advisory per CVE in a CSAF document.

    When a vulnerability lists its affected products (product_status.known_affected)
    only those products - and their version ranges - are attached to that CVE, so one
    big advisory doesn't smear every CVE across every product it mentions.
    """
    document = doc.get("document", {})
    tracking = document.get("tracking", {})
    adv_id = tracking.get("id", "")
    title = document.get("title", "")
    published = (tracking.get("initial_release_date") or "")[:10]
    modified = (tracking.get("current_release_date") or "")[:10]
    url = f"https://www.cisa.gov/news-events/ics-advisories/{adv_id.lower()}" if adv_id else ""

    vendors: set[str] = set()
    all_names: set[str] = set()
    pid_info: dict[str, tuple[str, str | None]] = {}
    tree = doc.get("product_tree", {})
    _walk_branches(tree.get("branches"), vendors, all_names, pid_info)
    for fpn in tree.get("full_product_names", []) or []:
        _register(fpn, all_names, pid_info)

    def ranges_for(pids) -> list[VersionRange]:
        out: list[VersionRange] = []
        for pid in pids:
            base, spec = pid_info[pid]
            if spec:
                for r in parse_vers(spec, product=base):
                    if r not in out:
                        out.append(r)
        return out

    out = []
    for v in doc.get("vulnerabilities", []) or []:
        cve = v.get("cve", "")
        cvss, sev = None, ""
        for score in v.get("scores", []) or []:
            for key in ("cvss_v4", "cvss_v3"):
                data = score.get(key)
                if data and data.get("baseScore") is not None:
                    if cvss is None or data["baseScore"] > cvss:
                        cvss, sev = data["baseScore"], (data.get("baseSeverity") or "").upper()

        known = [p for p in (v.get("product_status", {}).get("known_affected") or []) if p in pid_info]
        if known:
            products = sorted({pid_info[p][0] for p in known})
            ranges = ranges_for(known)
        else:
            products = sorted(all_names)
            ranges = ranges_for(pid_info)
        out.append(Advisory(
            cve_id=cve, source="CISA",
            title=f"{title} - {v['title']}" if v.get("title") else title,
            published=published, modified=modified, cvss=cvss, severity=sev,
            advisory_id=adv_id, url=url, vendors=sorted(vendors),
            products=products, ranges=ranges,
        ))
    return out


def fetch_advisories(
    session: requests.Session,
    since: datetime | None = None,
    cache_dir: Path | None = None,
    workers: int = 8,
    progress: Callable[[str], None] | None = None,
) -> list[Advisory]:
    entries = list_advisories(session, since)
    if progress:
        progress(f"CISA: {len(entries)} advisories to read")

    def load(entry: tuple[str, str]) -> list[Advisory]:
        path, ts = entry
        try:
            return parse_csaf(_fetch_document(session, path, ts, cache_dir))
        except (requests.RequestException, ValueError) as e:
            log.warning("Skipping CISA advisory %s: %s", path, e)
            return []

    advisories: list[Advisory] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for batch in pool.map(load, entries):
            advisories.extend(batch)
    return advisories


def fetch_kev(session: requests.Session) -> set[str]:
    """CVE ids in CISA's Known Exploited Vulnerabilities catalog."""
    r = session.get(KEV_URL, timeout=60)
    r.raise_for_status()
    return {v["cveID"] for v in r.json().get("vulnerabilities", [])}
