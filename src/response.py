"""
response.py — Controlled automated response for the NIDS project.

Blocks confirmed malicious IP addresses with iptables and keeps an audit
trail in data/blocked_ips.json.

Safety rails:
  * Strict IP validation (rejects malformed input / shell injection).
  * Whitelist (data/whitelist.txt) — these IPs are NEVER blocked.
  * Dry-run mode for tests / safe exploration.
  * Every action is logged to the audit file.

Usage:
    from src.response import block_ip, unblock_ip, list_blocked, is_whitelisted

    block_ip("192.168.56.102", dry_run=True)
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
BLOCKED_FILE = DATA_DIR / "blocked_ips.json"
WHITELIST_FILE = DATA_DIR / "whitelist.txt"


def is_valid_ip(ip: str) -> bool:
    """Return True only for a syntactically valid IPv4/IPv6 address."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except (ValueError, AttributeError):
        return False


def load_whitelist(path: Path = WHITELIST_FILE) -> set[str]:
    """Load whitelisted IPs (one per line, '#' comments allowed)."""
    if not path.exists():
        return set()
    entries = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.add(line)
    return entries


def is_whitelisted(ip: str, path: Path = WHITELIST_FILE) -> bool:
    return ip in load_whitelist(path)


def _load_blocked() -> list[dict]:
    if not BLOCKED_FILE.exists():
        return []
    try:
        return json.loads(BLOCKED_FILE.read_text())
    except json.JSONDecodeError:
        return []


def _save_blocked(records: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    BLOCKED_FILE.write_text(json.dumps(records, indent=2))


def list_blocked() -> list[dict]:
    """Return the current block-list audit records."""
    return _load_blocked()


def _run_iptables(args: list[str]) -> tuple[bool, str]:
    """Run an iptables command; return (success, message)."""
    try:
        result = subprocess.run(
            ["iptables"] + args,
            capture_output=True, text=True, timeout=10,
        )
        return result.returncode == 0, (result.stderr or result.stdout).strip()
    except FileNotFoundError:
        return False, "iptables not found (not installed or not in PATH)"
    except PermissionError:
        return False, "permission denied — run with sudo to apply iptables rules"
    except subprocess.TimeoutExpired:
        return False, "iptables command timed out"


def block_ip(ip: str, dry_run: bool = False,
             reason: str = "", blocked_file: Path = BLOCKED_FILE) -> dict:
    """
    Block an IP address.

    Returns a result dict: {"ip", "blocked", "dry_run", "reason", "message"}.
    In dry-run mode no iptables command is executed — the action is only
    recorded in the audit file.
    """
    ip = (ip or "").strip()
    if not is_valid_ip(ip):
        return {"ip": ip, "blocked": False, "dry_run": dry_run,
                "reason": reason, "message": "invalid IP address"}

    if is_whitelisted(ip):
        return {"ip": ip, "blocked": False, "dry_run": dry_run,
                "reason": reason, "message": "IP is whitelisted — not blocked"}

    records = _load_blocked()
    if any(r.get("ip") == ip for r in records):
        return {"ip": ip, "blocked": False, "dry_run": dry_run,
                "reason": reason, "message": "IP already blocked"}

    if dry_run:
        message = "dry-run: iptables rule would be added"
        success = True
    else:
        success, message = _run_iptables(
            ["-A", "INPUT", "-s", ip, "-j", "DROP"])

    record = {
        "ip": ip,
        "blocked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "reason": reason,
        "dry_run": dry_run,
        "iptables_ok": success,
        "message": message,
    }
    records.append(record)
    # Honour a custom blocked_file for tests
    if blocked_file != BLOCKED_FILE:
        blocked_file.parent.mkdir(parents=True, exist_ok=True)
        existing = []
        if blocked_file.exists():
            try:
                existing = json.loads(blocked_file.read_text())
            except json.JSONDecodeError:
                existing = []
        existing.append(record)
        blocked_file.write_text(json.dumps(existing, indent=2))
    else:
        _save_blocked(records)

    return {"ip": ip, "blocked": success, "dry_run": dry_run,
            "reason": reason, "message": message}


def unblock_ip(ip: str, dry_run: bool = False) -> dict:
    """Remove an IP from the block list (and iptables, if applied)."""
    ip = (ip or "").strip()
    if not is_valid_ip(ip):
        return {"ip": ip, "unblocked": False, "message": "invalid IP address"}

    records = [r for r in _load_blocked() if r.get("ip") != ip]
    _save_blocked(records)

    if dry_run:
        return {"ip": ip, "unblocked": True, "message": "dry-run: rule would be removed"}

    ok, msg = _run_iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"])
    return {"ip": ip, "unblocked": ok,
            "message": msg or "removed from block list"}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="NIDS automated response")
    parser.add_argument("action", choices=["block", "unblock", "list"])
    parser.add_argument("ip", nargs="?", help="IP address to block/unblock")
    parser.add_argument("--dry-run", action="store_true",
                        help="Do not run iptables (log only)")
    args = parser.parse_args()

    if args.action == "list":
        print(json.dumps(list_blocked(), indent=2))
    elif not args.ip:
        parser.error("an IP address is required for block/unblock")
    elif args.action == "block":
        print(json.dumps(block_ip(args.ip, dry_run=args.dry_run), indent=2))
    else:
        print(json.dumps(unblock_ip(args.ip, dry_run=args.dry_run), indent=2))
