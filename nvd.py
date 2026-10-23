"""NVD (National Vulnerability Database) CVE API 2.0 source.

One keyword query is made per unique PLC model. Vendor filtering happens
afterwards in matching.py, so differing vendor spellings don't lose results.

Rate limits: 5 requests / 30 s without an API key, 50 / 30 s with one.
Get a free key at https://nvd.nist.gov/developers/request-an-api-key
"""
from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Callable

import requests

from .models import Advisory, PLC, VersionRange

log = logging.getLogger(__name__)

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2000


class NvdClient:
    def __init__(self, session: requests.Session, api_key: str | None = None,
                 sleep: Callable[[float], None] = time.sleep):
        self.session = session
        self.api_key = api_key
        self.delay = 0.7 if api_key else 6.5
        self._sleep = sleep
        self._last = 0.0

    def _get(self, params: dict) -> dict:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        for attempt in range(6):
            wait = self.delay - (time.monotonic() - self._last)
            if wait > 0:
                self._sleep(wait)
            self._last = time.monotonic()
            try:
                r = self.session.get(NVD_URL, params=params, headers=headers, timeout=60)
            except requests.RequestException as e:
                log.warning("NVD request error (%s); retrying", e)
                self._sleep(5 * (attempt + 1))
                continue
            if r.status_code == 200:
                return r.json()
            if r.status_code in (403, 429, 503):  # throttled / temporarily unavailable
                backoff = 10 * (attempt + 1)
                log.warning("NVD returned %s; waiting %ss", r.status_code, backoff)
                self._sleep(backoff)
                continue
            r.raise_for_status()
        raise RuntimeError("NVD API kept failing after several retries")

    def keyword_search(self, keyword: str) -> list[dict]:
        items: list[dict] = []
        start = 0
        while True:
            data = self._get({"keywordSearch": keyword, "resultsPerPage": PAGE_SIZE,
                              "startIndex": start})
            batch = data.get("vulnerabilities", [])
            items.extend(batch)
            start += len(batch)
            if not batch or start >= data.get("totalResults", 0):
                return items


def _cpe_range(product: str, cpe_version: str, match: dict) -> VersionRange:
    """Affected versions for one cpeMatch entry: explicit bounds, a single
    version in the CPE name, or (no bounds, '*'/'-') every version."""
    start_incl, start_excl = match.get("versionStartIncluding"), match.get("versionStartExcluding")
    end_incl, end_excl = match.get("versionEndIncluding"), match.get("versionEndExcluding")
    if start_incl or start_excl or end_incl or end_excl:
        return VersionRange(
            product,
            start=start_incl or start_excl, start_incl=bool(start_incl),
            end=end_incl or end_excl, end_incl=bool(end_incl),
        )
    if cpe_version not in ("*", "-", ""):
        v = cpe_version.replace("\\", "")
        return VersionRange(product, v, True, v, True)
    return VersionRange(product, all_versions=True)


def parse_cve(item: dict) -> Advisory:
    cve = item["cve"]
    cid = cve["id"]
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")

    cvss, sev = None, ""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            data = arr[0].get("cvssData", {})
            cvss = data.get("baseScore")
            sev = data.get("baseSeverity") or arr[0].get("baseSeverity", "")
            break

    vendors: set[str] = set()
    products: set[str] = set()
    ranges: list[VersionRange] = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) <= 4:
                    continue
                vendor, product = parts[3].replace("_", " "), parts[4].replace("_", " ")
                name = f"{vendor} {product}"
                vendors.add(vendor)
                products.add(name)
                # Hardware entries are often marked vulnerable=false ("runs on");
                # only vulnerable entries say which versions are affected.
                if m.get("vulnerable", True):
                    r = _cpe_range(name, parts[5] if len(parts) > 5 else "*", m)
                    if r not in ranges:
                        ranges.append(r)

    return Advisory(
        cve_id=cid, source="NVD", description=desc,
        published=(cve.get("published") or "")[:10],
        modified=(cve.get("lastModified") or "")[:10],
        cvss=cvss, severity=(sev or "").upper(), advisory_id=cid,
        url=f"https://nvd.nist.gov/vuln/detail/{cid}",
        vendors=sorted(vendors), products=sorted(products), ranges=ranges,
        known_exploited=bool(cve.get("cisaExploitAdd")),
    )


def fetch_advisories(
    plcs: list[PLC],
    session: requests.Session,
    api_key: str | None = None,
    since: datetime | None = None,
    progress: Callable[[str], None] | None = None,
) -> list[Advisory]:
    client = NvdClient(session, api_key)
    models = sorted({p.model for p in plcs}, key=str.lower)
    found: dict[str, Advisory] = {}
    for i, model in enumerate(models, 1):
        if progress:
            progress(f"NVD {i}/{len(models)}: {model}")
        for item in client.keyword_search(model):
            adv = parse_cve(item)
            if since and adv.modified and adv.modified < since.date().isoformat():
                continue
            found[adv.cve_id] = adv
    return list(found.values())
