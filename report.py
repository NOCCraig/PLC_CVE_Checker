"""Write the Excel report."""
from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from .models import Finding, PLC

FIRMWARE_FILL = {
    "affected": PatternFill("solid", fgColor="F4B6B6"),
    "unknown": PatternFill("solid", fgColor="FFF2B3"),
    "not affected": PatternFill("solid", fgColor="D9EAD3"),
}
HEADER_FILL = PatternFill("solid", fgColor="1F3864")
HEADER_FONT = Font(bold=True, color="FFFFFF")
SEVERITY_FILL = {
    "CRITICAL": PatternFill("solid", fgColor="F4B6B6"),
    "HIGH": PatternFill("solid", fgColor="F9D6A5"),
    "MEDIUM": PatternFill("solid", fgColor="FFF2B3"),
    "LOW": PatternFill("solid", fgColor="D9EAD3"),
}


def _style_sheet(ws, widths: list[int], wrap_cols: set[int] = frozenset()) -> None:
    for c in ws[1]:
        c.fill, c.font = HEADER_FILL, HEADER_FONT
        c.alignment = Alignment(vertical="center", wrap_text=True)
    for i, w in enumerate(widths, 1):
        ws.column_dimensions[get_column_letter(i)].width = w
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.alignment = Alignment(vertical="top", wrap_text=c.column in wrap_cols)
    ws.freeze_panes = "A2"
    if ws.max_row > 1:
        ws.auto_filter.ref = ws.dimensions


def write_report(
    path: str | Path,
    findings: list[Finding],
    plcs: list[PLC],
    run_info: dict[str, str],
    warnings: list[str],
) -> None:
    wb = Workbook()

    # --- Summary ---------------------------------------------------------
    ws = wb.active
    ws.title = "Summary"
    affected = {f.plc for f in findings}
    sev = Counter(f.severity or "UNKNOWN" for f in findings)
    rows: list[tuple[str, object]] = [
        ("PLC CVE check", ""),
        ("Run at", datetime.now().strftime("%Y-%m-%d %H:%M")),
        *run_info.items(),
        ("", ""),
        ("PLCs in inventory", len(plcs)),
        ("PLCs with a firmware version listed", sum(1 for p in plcs if p.firmware)),
        ("PLCs with at least one match", len(affected)),
        ("PLC/CVE matches", len(findings)),
        ("  Critical", sev.get("CRITICAL", 0)),
        ("  High", sev.get("HIGH", 0)),
        ("  Medium", sev.get("MEDIUM", 0)),
        ("  Low", sev.get("LOW", 0)),
        ("  Unscored", sev.get("UNKNOWN", 0)),
        ("  Known exploited (CISA KEV)", sum(f.known_exploited for f in findings)),
        ("  Firmware confirmed affected", sum(f.firmware_status == "affected" for f in findings)),
        ("  Firmware not checkable - review", sum(f.firmware_status == "unknown" for f in findings)),
        ("  Firmware outside affected versions", sum(f.firmware_status == "not affected" for f in findings)),
        ("", ""),
        ("How to read this", "Matches use vendor + model only (the inventory has no firmware "
                             "version), so every row means 'this product line has a CVE' - check "
                             "the affected versions in the advisory against the firmware you run. "
                             "'high' = model is in the advisory's product list; 'medium' = model "
                             "only appears in the advisory text. When the inventory has a "
                             "firmware column, 'Firmware check' compares it to the advisory's "
                             "affected versions: 'affected' is confirmed, 'unknown' means the "
                             "advisory had no usable version data or the firmware couldn't be "
                             "parsed - verify those by hand."),
    ]
    for w in warnings:
        rows.append(("Warning", w))
    for r in rows:
        ws.append(list(r))
    ws["A1"].font = Font(bold=True, size=14)
    ws.column_dimensions["A"].width = 34
    ws.column_dimensions["B"].width = 100
    for row in ws.iter_rows(min_row=2):
        row[0].font = Font(bold=True)
        row[1].alignment = Alignment(wrap_text=True, vertical="top", horizontal="left")

    # --- Matches ---------------------------------------------------------
    ws = wb.create_sheet("Matches")
    ws.append(["Location", "Owner", "Vendor", "Model", "Firmware", "Firmware check",
               "Affected versions", "CVE", "Severity", "CVSS", "Known exploited",
               "Confidence", "Sources", "Advisories", "Published", "Title / description",
               "Matched on", "Link", "Inventory row"])
    for f in findings:
        ws.append([
            f.plc.location, f.plc.owner, f.plc.vendor, f.plc.model, f.plc.firmware,
            f.firmware_status, f.affected_versions, f.cve_id, f.severity,
            f.cvss, "YES" if f.known_exploited else "", f.confidence, ", ".join(f.sources),
            ", ".join(f.advisory_ids), f.published, f.title, f.reason,
            f.urls[0] if f.urls else "", f.plc.row,
        ])
        row = ws.max_row
        if f.urls:
            ws.cell(row, 18).hyperlink = f.urls[0]
            ws.cell(row, 18).style = "Hyperlink"
        fill = SEVERITY_FILL.get(f.severity)
        if fill:
            ws.cell(row, 9).fill = fill
        if f.known_exploited:
            ws.cell(row, 11).font = Font(bold=True, color="C00000")
        status_fill = FIRMWARE_FILL.get(f.firmware_status)
        if status_fill:
            ws.cell(row, 6).fill = status_fill
    _style_sheet(ws, [18, 16, 18, 18, 11, 13, 26, 18, 11, 7, 10, 11, 12, 24, 12, 60, 42, 40, 9],
                 {7, 16, 17})

    # --- By PLC ----------------------------------------------------------
    ws = wb.create_sheet("By PLC")
    ws.append(["Location", "Owner", "Vendor", "Model", "Firmware", "Matches",
               "Confirmed affected", "Highest CVSS", "Known exploited", "CVEs", "Inventory row"])
    by_plc: dict[PLC, list[Finding]] = {p: [] for p in plcs}
    for f in findings:
        by_plc.setdefault(f.plc, []).append(f)
    ordered = sorted(by_plc.items(),
                     key=lambda kv: (-max((f.cvss or 0) for f in kv[1]) if kv[1] else 1,
                                     kv[0].vendor.lower(), kv[0].model.lower()))
    for plc, fs in ordered:
        top = max((f.cvss for f in fs if f.cvss is not None), default=None)
        confirmed = sum(f.firmware_status == "affected" for f in fs)
        ws.append([plc.location, plc.owner, plc.vendor, plc.model, plc.firmware, len(fs),
                   confirmed if plc.firmware else "", top,
                   sum(f.known_exploited for f in fs) or "",
                   ", ".join(f.cve_id for f in fs), plc.row])
    _style_sheet(ws, [18, 16, 18, 18, 11, 9, 11, 12, 10, 70, 9], {10})

    wb.save(path)
