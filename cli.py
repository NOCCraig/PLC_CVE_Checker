"""Command line entry point.

    python -m plc_cve_checker my_plcs.xlsx
    python -m plc_cve_checker my_plcs.xlsx -o report.xlsx --since 90d --nvd-api-key KEY
"""
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

from . import cisa, nvd
from .inventory import InventoryError, load_inventory
from .matching import consolidate, find_matches, split_ruled_out
from .report import write_report

log = logging.getLogger("plc_cve_checker")

DEFAULT_CACHE = Path.home() / ".cache" / "plc_cve_checker"


def parse_since(value: str) -> datetime | None:
    """'365d' (days back), '2025-06-01' (a date) or 'all'."""
    v = value.strip().lower()
    if v == "all":
        return None
    m = re.fullmatch(r"(\d+)d", v)
    if m:
        return datetime.now(timezone.utc) - timedelta(days=int(m.group(1)))
    try:
        return datetime.fromisoformat(v).replace(tzinfo=timezone.utc)
    except ValueError:
        raise argparse.ArgumentTypeError("use a number of days like 180d, a date like 2025-06-01, or 'all'")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="plc_cve_checker",
        description="Check CVEs (NVD + CISA ICS advisories) against a spreadsheet of PLCs.",
    )
    p.add_argument("inventory", help="PLC spreadsheet (.xlsx, .xlsm or .csv)")
    p.add_argument("-o", "--output", help="report file (default: <inventory name>_cve_report_<date>.xlsx)")
    p.add_argument("--sheet", help="worksheet name (default: first sheet)")
    p.add_argument("--vendor-col", help="header of the vendor column, if not auto-detected")
    p.add_argument("--model-col", help="header of the model column, if not auto-detected")
    p.add_argument("--location-col", help="header of the location column")
    p.add_argument("--owner-col", help="header of the owner column")
    p.add_argument("--firmware-col", help="header of the (optional) firmware version column")
    p.add_argument("--sources", default="nvd,cisa", help="comma list of: nvd, cisa (default: both)")
    p.add_argument("--since", type=parse_since, default=parse_since("365d"),
                   help="only advisories updated since this point: 180d, 2025-06-01 or all "
                        "(default: 365d)")
    p.add_argument("--min-confidence", choices=["medium", "high"], default="medium",
                   help="'high' keeps only matches where the model is in the product list")
    p.add_argument("--nvd-api-key", default=os.environ.get("NVD_API_KEY"),
                   help="NVD API key (or set NVD_API_KEY); makes NVD lookups ~10x faster")
    p.add_argument("--include-unaffected", action="store_true",
                   help="also list CVEs whose affected versions exclude the PLC's firmware "
                        "(by default they are left out and only counted)")
    p.add_argument("--no-kev", action="store_true", help="don't flag CISA Known Exploited CVEs")
    p.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE, help=f"default: {DEFAULT_CACHE}")
    p.add_argument("--fail-on-match", action="store_true",
                   help="exit with code 2 if any match is found (useful for scheduled runs)")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = "plc-cve-checker/0.1 (+python-requests)"
    return s


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(message)s", stream=sys.stderr)

    sources = {s.strip().lower() for s in args.sources.split(",") if s.strip()}
    unknown = sources - {"nvd", "cisa"}
    if unknown or not sources:
        log.error("Unknown --sources value(s): %s", ", ".join(sorted(unknown)) or "(none)")
        return 1

    try:
        inv = load_inventory(
            args.inventory, args.sheet,
            {"vendor": args.vendor_col, "model": args.model_col,
             "location": args.location_col, "owner": args.owner_col,
             "firmware": args.firmware_col},
        )
    except InventoryError as e:
        log.error("Inventory problem: %s", e)
        return 1
    for w in inv.warnings:
        log.warning(w)
    with_fw = sum(1 for p in inv.plcs if p.firmware)
    log.info("Loaded %d PLCs (%d unique models) from %s",
             len(inv.plcs), len({p.model for p in inv.plcs}), args.inventory)
    if "firmware" in inv.columns:
        log.info("Firmware column '%s' found: %d of %d PLCs have a value, so their versions "
                 "will be checked against each CVE's affected ranges.",
                 inv.columns["firmware"], with_fw, len(inv.plcs))
    else:
        log.info("No firmware column found; matching on vendor + model only.")

    session = make_session()
    advisories, warnings = [], list(inv.warnings)
    failed = 0
    progress = lambda msg: log.info(msg)  # noqa: E731

    if "nvd" in sources:
        try:
            got = nvd.fetch_advisories(inv.plcs, session, args.nvd_api_key, args.since, progress)
            log.info("NVD: %d CVEs fetched", len(got))
            advisories += got
        except Exception as e:  # keep going with the other source
            failed += 1
            warnings.append(f"NVD lookup failed: {e}")
            log.error("NVD lookup failed: %s", e)
    if "cisa" in sources:
        try:
            got = cisa.fetch_advisories(session, args.since, args.cache_dir, progress=progress)
            log.info("CISA: %d CVE records read", len(got))
            advisories += got
        except Exception as e:
            failed += 1
            warnings.append(f"CISA advisory lookup failed: {e}")
            log.error("CISA advisory lookup failed: %s", e)

    if failed == len(sources):
        log.error("All sources failed; no report written.")
        return 1

    if not args.no_kev:
        try:
            kev = cisa.fetch_kev(session)
            for a in advisories:
                a.known_exploited = a.known_exploited or a.cve_id in kev
        except Exception as e:
            warnings.append(f"Couldn't load CISA KEV catalog (exploited flags may be missing): {e}")
            log.warning("KEV catalog unavailable: %s", e)

    findings = consolidate(find_matches(inv.plcs, advisories, args.min_confidence))
    findings, ruled_out = split_ruled_out(findings)
    if args.include_unaffected:
        findings = sorted(findings + ruled_out,
                          key=lambda f: (-(f.cvss or 0), f.plc.vendor, f.plc.model, f.cve_id))

    out = Path(args.output) if args.output else Path(
        f"{Path(args.inventory).stem}_cve_report_{datetime.now():%Y%m%d}.xlsx")
    run_info = {
        "Inventory file": str(args.inventory),
        "Sources": ", ".join(sorted(s.upper() for s in sources)),
        "Advisories updated since": args.since.date().isoformat() if args.since else "all time",
        "Advisories scanned": str(len(advisories)),
        "Minimum confidence": args.min_confidence,
        "Firmware column": inv.columns.get("firmware", "(none - vendor + model matching only)"),
        "CVEs ruled out by firmware version": str(len(ruled_out)),
    }
    write_report(out, findings, inv.plcs, run_info, warnings)

    affected = {f.plc for f in findings}
    kev_count = sum(f.known_exploited for f in findings)
    log.info("")
    log.info("%d PLC/CVE matches across %d of %d PLCs (%d known exploited).",
             len(findings), len(affected), len(inv.plcs), kev_count)
    if ruled_out:
        log.info("%d more CVE(s) were ruled out because the PLC firmware is outside the affected "
                 "versions%s.", len(ruled_out),
                 " (shown in the report)" if args.include_unaffected else " (use --include-unaffected to list them)")
    unchecked = sum(1 for f in findings if f.plc.firmware and f.firmware_status == "unknown")
    if unchecked:
        log.info("%d match(es) couldn't be version-checked (no version data) - review manually.", unchecked)
    log.info("Report written to %s", out)
    return 2 if (findings and args.fail_on_match) else 0


if __name__ == "__main__":
    raise SystemExit(main())
