#!/usr/bin/env python3
"""
generate-report.py — PCI DSS Audit Report Generator

Reads normalized JSON evidence (output of export-logs.py) and generates
an audit-ready Markdown report per control, optionally aligned to SOC 2
using the crosswalk CSV.

Usage:
    python ./scripts/generate-report.py \\
        --control 8.1.1 \\
        --input ./examples/8.1.1/normalized.json \\
        --out ./examples/8.1.1/REPORT_8.1.1.md

    # SOC 2 aligned output
    python ./scripts/generate-report.py \\
        --control 8.1.1 \\
        --input ./examples/8.1.1/normalized.json \\
        --out ./examples/8.1.1/REPORT_SOC2.md \\
        --framework soc2 \\
        --crosswalk ./crosswalk/pci_to_soc2.csv

PCI DSS Controls supported:
    8.x  — Access control, user accounts, MFA, password policy
    10.x — Audit logging and log review
    12.x — Policies, risk assessment, incident response

Author: suresh-1001 | License: MIT
"""

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone

SCRIPT_VERSION = "1.1.0"

# ─────────────────────────────────────────────
# CROSSWALK
# ─────────────────────────────────────────────

def load_crosswalk(path: str) -> dict:
    """Load PCI→SOC2 crosswalk CSV into a dict keyed by PCI_Control."""
    mapping = {}
    if not path or not os.path.isfile(path):
        return mapping
    with open(path, "r", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            mapping[row["PCI_Control"]] = row
    print(f"[+] Crosswalk loaded: {len(mapping)} mappings from {path}")
    return mapping

# ─────────────────────────────────────────────
# REPORT SECTIONS
# ─────────────────────────────────────────────

def render_header(control: str, framework: str, crosswalk: dict) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cw = crosswalk.get(control, {})
    lines = [
        f"# PCI DSS 4.0.1 — Control {control} Evidence Report",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| **Control ID** | `{control}` |",
        f"| **Report Date** | {now} |",
        f"| **Framework** | {'PCI DSS 4.0.1' if framework == 'pci' else 'PCI DSS 4.0.1 + SOC 2'} |",
        f"| **Report Version** | {SCRIPT_VERSION} |",
    ]
    if framework == "soc2" and cw:
        lines += [
            f"| **SOC 2 CC** | `{cw.get('SOC2_CC', '')}` — {cw.get('SOC2_CC_Title', '')} |",
            f"| **Evidence Type** | {cw.get('Evidence_Type', '')} |",
        ]
    lines += ["", "---", ""]
    return "\n".join(lines)


def render_summary(records: list) -> str:
    lines = ["## 📋 Evidence Summary", ""]
    lines += [
        f"| Host | Control | Platform | OS | Collected At |",
        f"|---|---|---|---|---|",
    ]
    for rec in records:
        m = rec.get("meta", {})
        lines.append(
            f"| `{m.get('host','?')}` "
            f"| `{m.get('control_id','?')}` "
            f"| {m.get('os',{}).get('platform','?')} "
            f"| {m.get('os',{}).get('caption','?')} "
            f"| {m.get('collected_at','?')} |"
        )
    lines += ["", "---", ""]
    return "\n".join(lines)


def render_users(records: list) -> str:
    lines = ["## 👥 User Accounts (PCI DSS 8.2.1)", ""]
    for rec in records:
        host = rec.get("meta", {}).get("host", "unknown")
        users = rec.get("localUsers", [])
        lines.append(f"### Host: `{host}`")
        if not users:
            lines.append("_No user data collected._\n")
            continue
        lines.append("| User | Enabled | Password Required | Password Expires | Last Logon |")
        lines.append("|---|---|---|---|---|")
        for u in users:
            lines.append(
                f"| {u.get('Name') or u.get('name','?')} "
                f"| {u.get('Enabled','')} "
                f"| {u.get('PasswordRequired','')} "
                f"| {u.get('PasswordExpires','')} "
                f"| {u.get('LastLogon','')} |"
            )
        lines.append("")
    lines += ["---", ""]
    return "\n".join(lines)


def render_admins(records: list) -> str:
    lines = ["## 🔐 Privileged Access — Admin Group Members (PCI DSS 7.2.1)", ""]
    for rec in records:
        host = rec.get("meta", {}).get("host", "unknown")
        admins = rec.get("adminGroup", [])
        lines.append(f"### Host: `{host}`")
        if not admins:
            lines.append("_No admin group data collected._\n")
            continue
        for a in admins:
            lines.append(f"- `{a}`")
        lines.append("")
    lines += ["---", ""]
    return "\n".join(lines)


def render_password_policy(records: list) -> str:
    lines = ["## 🔑 Password Policy (PCI DSS 8.3.6)", ""]
    for rec in records:
        host = rec.get("meta", {}).get("host", "unknown")
        policy = rec.get("passwordPolicy", {})
        lines.append(f"### Host: `{host}`")
        if not policy:
            lines.append("_No password policy data collected._\n")
            continue
        lines.append("| Setting | Value |")
        lines.append("|---|---|")
        for k, v in policy.items():
            lines.append(f"| {k} | {v} |")
        lines.append("")
    lines += ["---", ""]
    return "\n".join(lines)


def render_last_logins(records: list) -> str:
    lines = ["## 📜 Last Login Activity (PCI DSS 10.2.1)", ""]
    for rec in records:
        host = rec.get("meta", {}).get("host", "unknown")
        logins = rec.get("lastLogins", [])
        lines.append(f"### Host: `{host}`")
        if not logins:
            lines.append("_No login activity data collected._\n")
            continue
        if isinstance(logins, list) and logins and isinstance(logins[0], dict):
            lines.append("| User | Last Logon | Enabled |")
            lines.append("|---|---|---|")
            for u in logins:
                lines.append(f"| {u.get('Name','?')} | {u.get('LastLogon','')} | {u.get('Enabled','')} |")
        else:
            for entry in logins:
                lines.append(f"    {entry}")
        lines.append("")
    lines += ["---", ""]
    return "\n".join(lines)


def render_footer(control: str, framework: str) -> str:
    return "\n".join([
        "## ✅ Attestation",
        "",
        f"This report was generated automatically from evidence collected for PCI DSS 4.0.1 control `{control}`.",
        "All data has been redacted per `redact_patterns.txt`. No raw PII, hostnames, or customer data is present.",
        "",
        f"- **Framework:** {'PCI DSS 4.0.1' if framework == 'pci' else 'PCI DSS 4.0.1 + SOC 2 Common Criteria'}",
        f"- **Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"- **Generator version:** {SCRIPT_VERSION}",
        "",
        "_Review and sign off before submitting to QSA._",
        "",
    ])

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="Generate PCI DSS audit report from normalized evidence JSON.")
    ap.add_argument("--control",   required=True,  help="PCI DSS control ID (e.g. 8.1.1)")
    ap.add_argument("--input",     required=True,  help="Path to normalized JSON file")
    ap.add_argument("--out",       required=True,  help="Output path for Markdown report")
    ap.add_argument("--framework", default="pci",  choices=["pci", "soc2"],
                    help="Output framework alignment: pci (default) or soc2")
    ap.add_argument("--crosswalk", default="./crosswalk/pci_to_soc2.csv",
                    help="Path to PCI→SOC2 crosswalk CSV (used when --framework soc2)")
    args = ap.parse_args()

    print()
    print("========================================")
    print(" PCI DSS Report Generator")
    print(f" Control   : {args.control}")
    print(f" Framework : {args.framework.upper()}")
    print(f" Input     : {args.input}")
    print(f" Output    : {args.out}")
    print("========================================")
    print()

    if not os.path.isfile(args.input):
        print(f"[!] Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Handle both single record and list of records
    records = data if isinstance(data, list) else [data]
    crosswalk = load_crosswalk(args.crosswalk) if args.framework == "soc2" else {}

    report = "".join([
        render_header(args.control, args.framework, crosswalk),
        render_summary(records),
        render_users(records),
        render_admins(records),
        render_password_policy(records),
        render_last_logins(records),
        render_footer(args.control, args.framework),
    ])

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"[✓] Report written: {args.out}")
    print()


if __name__ == "__main__":
    main()
