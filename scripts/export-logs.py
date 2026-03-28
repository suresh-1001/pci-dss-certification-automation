#!/usr/bin/env python3
"""
export-logs.py — PCI DSS Evidence Normalizer

Reads raw JSON evidence artifacts produced by collect-evidence.ps1,
normalizes them into a merged JSON file and a flat CSV report,
and optionally redacts sensitive fields before output.

Usage:
    python ./scripts/export-logs.py --input ./examples/8.1.1 --output ./examples/8.1.1/normalized

    # With redaction patterns
    python ./scripts/export-logs.py \\
        --input ./examples/10.2.1 \\
        --output ./examples/10.2.1/normalized \\
        --redact ./redact_patterns.txt

    # Export CSV only
    python ./scripts/export-logs.py \\
        --input ./examples/8.1.1 \\
        --output ./examples/8.1.1/normalized \\
        --format csv

PCI DSS Controls supported:
    8.1.1 / 8.2.1 / 8.3.6 — User accounts, admin group, password policy
    10.2.1                 — Last login / access activity

Author: suresh-1001 | License: MIT
"""

import argparse
import csv
import glob
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any

# ─────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────

SCRIPT_VERSION = "1.1.0"

# Fields to redact if found anywhere in the evidence (hostname patterns, emails, IPs)
DEFAULT_REDACT_PATTERNS = [
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",               # IPv4 addresses
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",  # Email addresses
]

CSV_COLUMNS = [
    "collected_at",
    "host",
    "control_id",
    "collector_version",
    "platform",
    "os_caption",
    "systems_in_scope",
    "user_name",
    "user_enabled",
    "password_required",
    "password_expires",
    "last_logon",
    "uid",
    "shell",
]

# ─────────────────────────────────────────────
# REDACTION
# ─────────────────────────────────────────────

def load_redact_patterns(path: str | None) -> list[re.Pattern]:
    """Load redaction regex patterns from a file (one per line) plus defaults."""
    patterns = [re.compile(p) for p in DEFAULT_REDACT_PATTERNS]
    if path and os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    try:
                        patterns.append(re.compile(line))
                    except re.error as e:
                        print(f"[!] Invalid redact pattern '{line}': {e}", file=sys.stderr)
    return patterns


def redact_value(value: Any, patterns: list[re.Pattern]) -> Any:
    """Recursively redact string values in dicts/lists matching any pattern."""
    if isinstance(value, str):
        for p in patterns:
            value = p.sub("[REDACTED]", value)
        return value
    elif isinstance(value, dict):
        return {k: redact_value(v, patterns) for k, v in value.items()}
    elif isinstance(value, list):
        return [redact_value(i, patterns) for i in value]
    return value

# ─────────────────────────────────────────────
# NORMALIZATION
# ─────────────────────────────────────────────

def normalize_record(raw: dict) -> dict:
    """
    Normalize a raw evidence JSON record into a consistent schema.
    Adds normalizer_version and normalized_at fields for audit trail.
    """
    meta = raw.get("meta", {})
    os_info = meta.get("os", {})

    return {
        "meta": {
            "control_id":         meta.get("control_id") or meta.get("control", "unknown"),
            "collector_version":  meta.get("collector_version", "unknown"),
            "normalizer_version": SCRIPT_VERSION,
            "collected_at":       meta.get("collected_at", ""),
            "normalized_at":      datetime.now(timezone.utc).isoformat(),
            "host":               meta.get("host", "unknown"),
            "systems_in_scope":   meta.get("systems_in_scope", []),
            "os": {
                "platform": os_info.get("platform", ""),
                "caption":  os_info.get("caption", ""),
                "version":  os_info.get("version", ""),
                "build":    os_info.get("build", ""),
            },
        },
        "passwordPolicy": raw.get("passwordPolicy", {}),
        "adminGroup":     raw.get("adminGroup", []),
        "localUsers":     raw.get("localUsers", []),
        "lastLogins":     raw.get("lastLogins", []),
    }


def flatten_users(record: dict) -> list[dict]:
    """Flatten a normalized record into one row per user for CSV output."""
    meta = record.get("meta", {})
    rows = []

    users = record.get("localUsers", [])
    if not users:
        # Emit one metadata-only row if no users collected (e.g. Linux /etc/passwd empty)
        rows.append({col: "" for col in CSV_COLUMNS} | {
            "collected_at":     meta.get("collected_at", ""),
            "host":             meta.get("host", ""),
            "control_id":       meta.get("control_id", ""),
            "collector_version": meta.get("collector_version", ""),
            "platform":         meta.get("os", {}).get("platform", ""),
            "os_caption":       meta.get("os", {}).get("caption", ""),
            "systems_in_scope": ",".join(meta.get("systems_in_scope", [])),
        })
        return rows

    for u in users:
        rows.append({
            "collected_at":      meta.get("collected_at", ""),
            "host":              meta.get("host", ""),
            "control_id":        meta.get("control_id", ""),
            "collector_version": meta.get("collector_version", ""),
            "platform":          meta.get("os", {}).get("platform", ""),
            "os_caption":        meta.get("os", {}).get("caption", ""),
            "systems_in_scope":  ",".join(meta.get("systems_in_scope", [])),
            # Windows fields
            "user_name":         u.get("Name") or u.get("name", ""),
            "user_enabled":      u.get("Enabled", ""),
            "password_required": u.get("PasswordRequired", ""),
            "password_expires":  u.get("PasswordExpires", ""),
            "last_logon":        u.get("LastLogon", ""),
            # Linux fields
            "uid":               u.get("UID", ""),
            "shell":             u.get("Shell", ""),
        })

    return rows

# ─────────────────────────────────────────────
# I/O
# ─────────────────────────────────────────────

def load_evidence_files(input_dir: str) -> list[dict]:
    """Glob all evidence_*.json files from the input directory."""
    pattern = os.path.join(input_dir, "evidence_*.json")
    files = sorted(glob.glob(pattern))
    if not files:
        print(f"[!] No evidence_*.json files found in: {input_dir}", file=sys.stderr)
        sys.exit(1)
    print(f"[+] Found {len(files)} evidence file(s) in {input_dir}")
    records = []
    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8") as f:
                records.append(json.load(f))
            print(f"    ✓ Loaded: {os.path.basename(fp)}")
        except (json.JSONDecodeError, OSError) as e:
            print(f"    [!] Skipping {fp}: {e}", file=sys.stderr)
    return records


def write_json(data: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    print(f"[+] JSON written : {path}")


def write_csv(rows: list[dict], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    print(f"[+] CSV written  : {path}")

# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Normalize PCI DSS evidence JSON artifacts into merged JSON + CSV."
    )
    ap.add_argument("--input",  required=True,  help="Directory containing evidence_*.json files")
    ap.add_argument("--output", required=True,  help="Base output path (no extension)")
    ap.add_argument("--redact", default=None,   help="Path to redact_patterns.txt (optional)")
    ap.add_argument("--format", default="both", choices=["json", "csv", "both"],
                    help="Output format: json | csv | both (default: both)")
    args = ap.parse_args()

    print()
    print("========================================")
    print(" PCI DSS Evidence Normalizer")
    print(f" Version  : {SCRIPT_VERSION}")
    print(f" Input    : {args.input}")
    print(f" Output   : {args.output}")
    print(f" Redact   : {args.redact or 'defaults only'}")
    print(f" Format   : {args.format}")
    print("========================================")
    print()

    # Load redaction patterns
    patterns = load_redact_patterns(args.redact)
    print(f"[+] Loaded {len(patterns)} redaction pattern(s)")

    # Load raw evidence files
    raw_records = load_evidence_files(args.input)

    # Normalize + redact
    normalized = []
    for raw in raw_records:
        norm = normalize_record(raw)
        norm = redact_value(norm, patterns)
        normalized.append(norm)

    print(f"[+] Normalized {len(normalized)} record(s)")

    # Write outputs
    if args.format in ("json", "both"):
        write_json(normalized, args.output + ".json")

    if args.format in ("csv", "both"):
        all_rows = []
        for rec in normalized:
            all_rows.extend(flatten_users(rec))
        write_csv(all_rows, args.output + "_users.csv")

    print()
    print(f"[✓] Normalization complete — {len(normalized)} record(s) processed")
    print()


if __name__ == "__main__":
    main()
