# PLC CVE Checker

Checks CVEs against a spreadsheet of your PLCs and writes an Excel report of which
PLCs have known vulnerabilities.

**Sources:** NVD (CVE API 2.0) and CISA ICS advisories (CSAF). CVEs in CISA's Known
Exploited Vulnerabilities catalog are flagged.

## Setup

```
pip install -r requirements.txt
```

Requires Python 3.10+. A free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key)
is optional but makes NVD lookups about 10x faster (set `NVD_API_KEY` or use `--nvd-api-key`).

## Usage

```
python -m plc_cve_checker my_plcs.xlsx
python -m plc_cve_checker my_plcs.xlsx -o report.xlsx --since 180d
python -m plc_cve_checker my_plcs.csv --sources cisa --min-confidence high
python -m plc_cve_checker sample/plc_inventory_sample.xlsx
```

| Option | Meaning |
|---|---|
| `inventory` | Spreadsheet (.xlsx, .xlsm, .csv). Required. |
| `-o, --output` | Report path. Default `<inventory>_cve_report_<date>.xlsx`. |
| `--sheet` | Worksheet name (default: first sheet). |
| `--vendor-col`, `--model-col`, `--location-col`, `--owner-col` | Header names, if auto-detection fails. |
| `--firmware-col` | Header of the firmware column, if not auto-detected. |
| `--include-unaffected` | Also list CVEs whose affected versions exclude the PLC's firmware. |
| `--sources` | `nvd`, `cisa` or `nvd,cisa` (default both). |
| `--since` | Only advisories updated since `180d`, `2025-06-01`, or `all` (default `365d`). |
| `--min-confidence` | `medium` (default) or `high`. |
| `--no-kev` | Skip the Known Exploited flag. |
| `--fail-on-match` | Exit code 2 when anything matches (handy for scheduled runs). |

## Spreadsheet format

Needs a **Vendor** and a **Model** column; **Location** and **Owner** are carried into the
report. An optional **Firmware** column (also recognised as Firmware Version, FW, Version,
Revision) turns on the firmware check described below - fill it in for as many PLCs as you
have; blanks are fine. Common header names are recognised (Manufacturer, Part Number, Site, ...), and the
header row can be anywhere in the first 15 rows.

## How matching works

A CVE matches a PLC when the **vendor** and the **model** both appear in it. Vendor aliases are
handled (Allen-Bradley = Rockwell Automation, Modicon = Schneider Electric, ...).

- **high**: the model is in the advisory's structured product list (CPE names / CSAF product tree)
- **medium**: the model only appears in the advisory's title or description

## Firmware check (optional)

If a PLC has a firmware value, it is compared with the affected version ranges in the NVD
and CISA data and each match gets a **Firmware check**:

- **affected**: the firmware is inside an affected range
- **not affected**: the firmware is outside every affected range. These CVEs are left out of the
  report by default and only counted on the Summary sheet (`--include-unaffected` lists them)
- **unknown**: the advisory has no usable version data, the match came from advisory text only,
  or the firmware couldn't be parsed. These stay in the report - review them by hand

PLCs without a firmware value (or inventories with no firmware column) behave as before: a match
means "this product line has a CVE", not "this exact unit is vulnerable".

How it decides, and its limits:

- Versions are compared numerically using the first dotted number in the string (`V4.5.0`,
  `32.011`, `V2.9 SP1` -> 2.9). Service packs and other suffixes are ignored.
- If several product variants contain your model name (say an S7-1500 CPU and the S7-1500
  Software Controller), a PLC is "affected" when any of their ranges contains its firmware. That
  errs towards over-reporting rather than missing something.
- When NVD and CISA disagree, the more cautious answer wins (affected > unknown > not affected).
- CISA advisories are read per CVE using each CVE's own list of affected products, so a large
  multi-product advisory no longer attaches every CVE to every product it mentions.

Tips: the model must appear as a whole token (`S7-1200` matches `SIMATIC S7-1200 CPU`, not
`S7-12000`), and models shorter than 3 characters are ignored. If your inventory says
`1756-L83E` but advisories talk about `ControlLogix 5580`, add the family name to the model
column (or add a vendor alias group in `matching.py`).

## Report

- **Summary**: counts, run settings, warnings
- **Matches**: one row per PLC x CVE (firmware check, affected versions, severity, CVSS, known exploited, sources, links)
- **By PLC**: every PLC in the inventory with its match count, so clean ones are visible too

## Automating later

The tool is a plain CLI, so scheduling is just a cron entry / Task Scheduler job. Use
`--fail-on-match` for a non-zero exit code when something is found. CISA advisories are cached
in `~/.cache/plc_cve_checker`, so repeat runs only download what changed.

## Tests

```
python -m unittest discover -s tests
```

## Layout

```
plc_cve_checker/
  cli.py        arguments + orchestration
  inventory.py  spreadsheet loader
  nvd.py        NVD API source
  cisa.py       CISA CSAF advisories + KEV
  matching.py   vendor/model matching, firmware status, merging duplicates
  versions.py   firmware parsing, version ranges, CSAF 'vers:' strings
  report.py     Excel output
```
