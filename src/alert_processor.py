"""
alert_processor.py — Python alert processing for the NIDS project.

Reads Suricata's EVE JSON log (logs/eve.json), extracts alert events,
normalises them into incident records, and stores them in:

  * data/incidents.json  — JSON array (dashboard-friendly)
  * data/incidents.db    — SQLite table (querying / reporting)

Optionally, when an IP exceeds --block-threshold alerts, it can trigger
src.response.block_ip() (controlled automated response).

Usage:
    # One-shot processing
    python3 -m src.alert_processor --input logs/eve.json

    # Live tail-follow with auto-blocking
    python3 -m src.alert_processor --input logs/eve.json --watch --auto-block

    # Safe test with bundled sample data
    python3 -m src.alert_processor --input tests/sample_eve.json
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import time
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUT = PROJECT_ROOT / "logs" / "eve.json"
DEFAULT_OUTPUT = PROJECT_ROOT / "data" / "incidents.json"
DEFAULT_DB = PROJECT_ROOT / "data" / "incidents.db"

SEVERITY_LABELS = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}


def normalise_severity(value) -> int:
    """Coerce a Suricata severity value to an int in 1..4 (default 3)."""
    try:
        sev = int(value)
    except (TypeError, ValueError):
        return 3
    return sev if 1 <= sev <= 4 else 3


def parse_eve_line(line: str) -> dict | None:
    """
    Parse one EVE JSON line. Returns a normalised incident dict for alert
    events, or None for non-alert / malformed lines.
    """
    line = line.strip()
    if not line:
        return None
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None

    if event.get("event_type") != "alert":
        return None

    alert = event.get("alert", {}) or {}
    src_ip = event.get("src_ip", "")
    dest_ip = event.get("dest_ip", "")

    return {
        "timestamp": event.get("timestamp", ""),
        "signature": alert.get("signature", "Unknown signature"),
        "signature_id": alert.get("signature_id", ""),
        "severity": normalise_severity(alert.get("severity", 3)),
        "severity_label": SEVERITY_LABELS[normalise_severity(alert.get("severity", 3))],
        "category": alert.get("category", ""),
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "dest_port": event.get("dest_port", ""),
        "protocol": (event.get("proto") or "").upper(),
        "action": alert.get("action", ""),
        "flow_id": event.get("flow_id", ""),
    }


def load_incidents(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []


def save_incidents(incidents: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(incidents, indent=2))


def save_to_db(incidents: list[dict], db_path: Path) -> None:
    """Store incidents in SQLite (table is recreated from the JSON store)."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS incidents (
                timestamp TEXT, signature TEXT, signature_id TEXT,
                severity INTEGER, severity_label TEXT, category TEXT,
                src_ip TEXT, dest_ip TEXT, dest_port TEXT,
                protocol TEXT, action TEXT, flow_id TEXT
            )"""
        )
        conn.execute("DELETE FROM incidents")
        conn.executemany(
            """INSERT INTO incidents VALUES
               (:timestamp, :signature, :signature_id, :severity,
                :severity_label, :category, :src_ip, :dest_ip, :dest_port,
                :protocol, :action, :flow_id)""",
            incidents,
        )
        conn.commit()
    finally:
        conn.close()


def process_file(input_path: Path, output_path: Path, db_path: Path,
                 existing: list[dict] | None = None,
                 start_offset: int = 0) -> tuple[list[dict], int]:
    """
    Process new lines from input_path (from start_offset).
    Returns (all_incidents, new_offset). Existing incidents are kept so
    repeated runs / --watch appends rather than overwrites.
    """
    incidents = list(existing) if existing is not None else load_incidents(output_path)
    seen = {(i.get("timestamp"), i.get("signature_id"), i.get("src_ip"),
             i.get("flow_id")) for i in incidents}

    if not input_path.exists():
        print(f"[alert_processor] input not found: {input_path}", file=sys.stderr)
        return incidents, start_offset

    new_count = 0
    with input_path.open("r", encoding="utf-8", errors="replace") as fh:
        fh.seek(start_offset)
        for line in fh:
            incident = parse_eve_line(line)
            if incident is None:
                continue
            key = (incident["timestamp"], incident["signature_id"],
                   incident["src_ip"], incident["flow_id"])
            if key in seen:
                continue
            seen.add(key)
            incidents.append(incident)
            new_count += 1
            print(f"  + [{incident['severity_label']}] "
                  f"{incident['signature']} "
                  f"({incident['src_ip']} -> {incident['dest_ip']})")
        offset = fh.tell()

    if new_count:
        save_incidents(incidents, output_path)
        save_to_db(incidents, db_path)
    print(f"[alert_processor] {new_count} new alert(s); "
          f"{len(incidents)} total stored.")
    return incidents, offset


def maybe_auto_block(incidents: list[dict], threshold: int,
                     dry_run: bool = False) -> list[dict]:
    """Block any source IP whose alert count reached the threshold."""
    counts = Counter(i["src_ip"] for i in incidents if i.get("src_ip"))
    offenders = [ip for ip, n in counts.items() if n >= threshold]

    if not offenders:
        return []

    from src.response import block_ip  # local import: keeps CLI usable standalone

    results = []
    for ip in offenders:
        result = block_ip(ip, dry_run=dry_run,
                          reason=f"{counts[ip]} alerts >= threshold {threshold}")
        print(f"  [response] {ip}: {result['message']}")
        results.append(result)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Process Suricata EVE JSON alerts into incidents.")
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT,
                        help="Suricata eve.json file")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT,
                        help="Incident JSON store")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB,
                        help="SQLite incident store")
    parser.add_argument("--watch", action="store_true",
                        help="Tail-follow the input file (Ctrl+C to stop)")
    parser.add_argument("--interval", type=float, default=2.0,
                        help="Poll interval in --watch mode (seconds)")
    parser.add_argument("--auto-block", action="store_true",
                        help="Block IPs that reach --block-threshold alerts")
    parser.add_argument("--block-threshold", type=int, default=5,
                        help="Alerts per IP before blocking (default: 5)")
    parser.add_argument("--dry-run", action="store_true",
                        help="With --auto-block: log blocks, don't run iptables")
    args = parser.parse_args(argv)

    incidents, offset = process_file(args.input, args.output, args.db)

    if args.auto_block:
        maybe_auto_block(incidents, args.block_threshold, dry_run=args.dry_run)

    if args.watch:
        print(f"[alert_processor] watching {args.input} "
              f"(poll every {args.interval}s) — Ctrl+C to stop.")
        try:
            while True:
                time.sleep(args.interval)
                if args.input.exists() and args.input.stat().st_size < offset:
                    offset = 0  # file was rotated/truncated
                incidents, offset = process_file(
                    args.input, args.output, args.db,
                    existing=incidents, start_offset=offset)
                if args.auto_block:
                    maybe_auto_block(incidents, args.block_threshold,
                                     dry_run=args.dry_run)
        except KeyboardInterrupt:
            print("\n[alert_processor] stopped.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
