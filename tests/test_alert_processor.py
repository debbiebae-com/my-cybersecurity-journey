"""Unit tests for src/alert_processor.py and src/response.py.

Run:  python3 -m pytest tests/ -v
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.alert_processor import (  # noqa: E402
    normalise_severity,
    parse_eve_line,
    process_file,
)
from src.response import block_ip, is_valid_ip, is_whitelisted  # noqa: E402

SAMPLE = Path(__file__).parent / "sample_eve.json"


def test_normalise_severity():
    assert normalise_severity(1) == 1
    assert normalise_severity("2") == 2
    assert normalise_severity(99) == 3
    assert normalise_severity(None) == 3
    assert normalise_severity("bad") == 3


def test_parse_alert_line():
    line = SAMPLE.read_text().splitlines()[0]
    incident = parse_eve_line(line)
    assert incident is not None
    assert incident["src_ip"] == "192.168.56.102"
    assert incident["severity"] == 1
    assert incident["severity_label"] == "Critical"
    assert incident["signature_id"] == 1000020


def test_parse_non_alert_line_returns_none():
    line = SAMPLE.read_text().splitlines()[5]  # event_type == "flow"
    assert parse_eve_line(line) is None


def test_parse_malformed_line_returns_none():
    assert parse_eve_line("not json at all") is None
    assert parse_eve_line("") is None


def test_process_sample_file(tmp_path):
    output = tmp_path / "incidents.json"
    db = tmp_path / "incidents.db"
    incidents, _ = process_file(SAMPLE, output, db)
    # Sample file has 12 lines, 1 of which is a flow event -> 11 alerts
    assert len(incidents) == 11
    assert output.exists()
    assert db.exists()
    stored = json.loads(output.read_text())
    assert len(stored) == 11


def test_process_is_idempotent(tmp_path):
    output = tmp_path / "incidents.json"
    db = tmp_path / "incidents.db"
    process_file(SAMPLE, output, db)
    incidents, _ = process_file(SAMPLE, output, db)
    assert len(incidents) == 11  # no duplicates on re-run


def test_ip_validation():
    assert is_valid_ip("192.168.56.102")
    assert is_valid_ip("10.0.0.1")
    assert not is_valid_ip("999.999.999.999")
    assert not is_valid_ip("192.168.1.1; rm -rf /")
    assert not is_valid_ip("")


def test_block_ip_dry_run(tmp_path):
    blocked_file = tmp_path / "blocked.json"
    result = block_ip("192.168.56.102", dry_run=True,
                      blocked_file=blocked_file)
    assert result["blocked"] is True
    assert result["dry_run"] is True
    records = json.loads(blocked_file.read_text())
    assert records[0]["ip"] == "192.168.56.102"


def test_block_ip_rejects_invalid():
    result = block_ip("not-an-ip", dry_run=True)
    assert result["blocked"] is False


def test_whitelist(tmp_path):
    whitelist = tmp_path / "whitelist.txt"
    whitelist.write_text("127.0.0.1\n")
    assert is_whitelisted("127.0.0.1", whitelist)
    assert not is_whitelisted("192.168.56.102", whitelist)
