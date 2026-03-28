#!/usr/bin/env python3
"""
gap-analysis.py — PCI DSS 4.0.1 Gap Analysis

Compares evidence collected (output of export-logs.py) against the full
list of required PCI DSS controls from the crosswalk CSV.
Flags controls as PASS ✅, PARTIAL ⚠️, or MISSING ❌ and outputs a
gap memo and action checklist in Markdown.

Usage:
    python ./scripts/gap-analysis.py \\
        --evidence-dir ./examples \\
        --crosswalk ./crosswalk/pci_to_soc2.csv \\
        --out ./examples/GAP_ANALYSIS.md

Author: suresh-1001 | License: MIT
"""

import argparse
import csv
import glob
import json
import os
import sys
from datetime import datetime, timezone

SCRIPT_VERSION = "1.0.0"

STATUS_PASS    = "✅ PASS"
STATUS_PARTIAL = "⚠️  PARTIAL"
STATUS_MISSING = "❌ MISSING"

# ─────────────────────────────────────────────
# LOADERS
# ─────────────────────────────────────────────

def load_crosswalk(path: str) -> list[dict]:
    if not os.path.isfile(path):
        print(f"[!] Crosswalk not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    print(f"[+] Crosswalk: {len(rows)} controls loaded")
    return rows


def load_collected_controls(evidence_dir: str) -> set[str]:
    """Scan all normalized JSON files and return the set of control_ids collected."""
    collected = set()
    pattern = os.path.join(evidence_dir, "**", "*.json")
    for fp in glob.glob(pattern, recursive=True):
        try:
            with open(fp, "r", encoding="utf-8") as f:
                data = json.load(f)
            records = data if isinstance(data, list) else [data]
            for rec in records:
                ctrl = rec.get("meta", {}).get("control_id") or rec.get("meta", {}).get("control")
                if ctrl:
                    collected.add(ctrl.strip())
        except (json.JSONDecodeError, OSError):
            pass
    print(f"[+] Evidence: {len(collected)} control(s) with collected artifacts")
    return collected

# ─────────────────────────────────────────────
# ANALYSIS
# ─────────────────────────────────────────────

def analyze(crosswalk: list[dict], collected: set[str]) -> list[dict]:
    results = []
    for row in crosswalk:
        ctrl = row["PCI_Control"].strip()
        if ctrl in collected:
            status = STATUS_PASS
        else:
            status = STATUS_MISSING
        results.append({
            "control":     ctrl,
            "title":       row.get("PCI_Requirement_Title", ""),
            "soc2_cc":     row.get("SOC2_CC", ""),
            "evidence":    row.get("Evidence_Type", ""),
            "status":      status,
        })
    return results

# ─────────────────────────────────────────────
# REPORT RENDERING
# ─────────────────────────────────────────────

def render_gap_report(results: list[dict], evidence_dir: str) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total   = len(results)
    passed  = sum(1 for r in results if r["status"] == STATUS_PASS)
    missing = sum(1 for r in results if r["status"] == STATUS_MISSING)
    partial = sum(1 for r in results if r["status"] == STATUS_PARTIAL)
    pct     = round((passed / total) * 100) if total else 0

    lines = [
        "# PCI DSS 4.0.1 — Gap Analysis Report",
        "",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Report Date** | {now} |",
        f"| **Evidence Directory** | `{evidence_dir}` |",
        f"| **Total Controls** | {total} |",
        f"| **Pass** | {passed} ({pct}%) |",
        f"| **Partial** | {partial} |",
        f"| **Missing** | {missing} |",
        f"| **Generator Version** | {SCRIPT_VERSION} |",
        "",
        "---",
        "",
        "## 📊 Control Status Summary",
        "",
        "| Control | Requirement | SOC 2 CC | Evidence Type | Status |",
        "|---|---|---|---|---|",
    ]

    for r in results:
        lines.append(
            f"| `{r['control']}` | {r['title']} | `{r['soc2_cc']}` | {r['evidence']} | {r['status']} |"
        )

    lines += ["", "---", ""]

    # Gap memo — missing controls only
    missing_items = [r for r in results if r["status"] != STATUS_PASS]
    lines += [
        "## ❌ Gap Memo — Controls Requiring Action",
        "",
    ]
    if not missing_items:
        lines.append("_All controls have collected evidence. No gaps identified._\n")
    else:
        lines.append(f"The following **{len(missing_items)} control(s)** have missing or incomplete evidence:\n")
        for r in missing_items:
            lines += [
                f"### `{r['control']}` — {r['title']}",
                f"- **Status:** {r['status']}",
                f"- **SOC 2 CC:** `{r['soc2_cc']}`",
                f"- **Required Evidence:** {r['evidence']}",
                f"- **Action:** Collect and normalize evidence, then re-run gap analysis.",
                "",
            ]

    lines += ["---", ""]

    # Action checklist
    lines += [
        "## ✅ Action Checklist",
        "",
        "Use this checklist to track remediation before QSA submission:",
        "",
    ]
    for r in results:
        checkbox = "x" if r["status"] == STATUS_PASS else " "
        lines.append(f"- [{checkbox}] `{r['control']}` — {r['title']}")

    lines += [
        "",
        "---",
        "",
        "## 📝 Notes",
        "",
        "_Add QSA feedback, re-test dates, and remediation owner here._",
        "",
        f"_Generated by gap-analysis.py v{SCRIPT_VERSION} on {now}_",
        "",
    ]

    return "\n".join(lines)

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="PCI DSS 4.0.1 gap analysis against collected evidence.")
    ap.add_argument("--evidence-dir", required=True,  help="Root directory containing normalized evidence JSON")
    ap.add_argument("--crosswalk",    required=True,  help="Path to crosswalk/pci_to_soc2.csv")
    ap.add_argument("--out",          required=True,  help="Output path for gap analysis Markdown report")
    args = ap.parse_args()

    print()
    print("========================================")
    print(" PCI DSS Gap Analyzer")
    print(f" Evidence  : {args.evidence_dir}")
    print(f" Crosswalk : {args.crosswalk}")
    print(f" Output    : {args.out}")
    print("========================================")
    print()

    crosswalk = load_crosswalk(args.crosswalk)
    collected = load_collected_controls(args.evidence_dir)
    results   = analyze(crosswalk, collected)

    passed  = sum(1 for r in results if r["status"] == STATUS_PASS)
    missing = sum(1 for r in results if r["status"] == STATUS_MISSING)
    print(f"[+] Results: {passed} PASS / {missing} MISSING / {len(results)} total")

    report = render_gap_report(results, args.evidence_dir)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"[✓] Gap analysis written: {args.out}")
    print()


if __name__ == "__main__":
    main()
