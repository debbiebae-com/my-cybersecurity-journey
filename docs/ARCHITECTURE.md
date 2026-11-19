# Architecture

## Overview

The NIDS is a pipeline: **capture → inspect → alert → process → respond →
visualise**. Each stage is a separate component so it can be tested and
replaced independently.

```
                        ┌─────────────────────────────────────────────┐
                        │              Ubuntu Linux (host / VM)       │
                        │                                             │
 Network                │   ┌──────────────┐   eve.json   ┌────────┐ │
 ─────────►  NIC ──────►│   │   Suricata   │─────────────►│ Python │ │
              (mirror /  │   │  IDS engine  │              │ alert  │ │
               promisc.) │   │  + local.    │              │processor│ │
                         │   │    rules     │              └───┬────┘ │
                         │   └──────────────┘                  │      │
                         │                                     ▼      │
                         │   ┌──────────────┐   block   ┌────────┐ │
                         │   │  response.py │◄──────────│threshold│ │
                         │   │  (iptables)  │           │ check  │ │
                         │   └──────────────┘           └────────┘ │
                         │                                             │
                         │   ┌──────────────────────────────────────┐ │
                         │   │  incidents.json / incidents.db       │ │
                         │   └──────────────────┬───────────────────┘ │
                         │                      │                     │
                         │   ┌──────────────────▼───────────────────┐ │
                         │   │  Streamlit Dashboard (dashboard/app.py)│ │
                         │   └──────────────────────────────────────┘ │
                         └─────────────────────────────────────────────┘
```

## Components

### 1. Network Monitoring Engine — Suricata
- Config: `suricata/suricata.yaml`
- Runs in promiscuous / mirrored mode on the lab interface.
- Outputs structured **EVE JSON** (`eve.json`) plus a human-readable
  `fast.log`. EVE JSON is the machine-readable source for everything
  downstream.

### 2. Intrusion Detection Rules — `suricata/rules/local.rules`
- Custom rules grouped by attack class:
  - Port scanning (SYN scans, multi-port probing)
  - ICMP scanning (echo-request sweeps / floods)
  - Suspicious connections (Telnet, SMB, RDP, FTP…)
  - Brute-force indicators (repeated SSH/FTP auth attempts)
  - Malicious traffic (sqlmap, Nikto, Metasploit, DNS tunnelling…)
- Each rule has a unique `sid` (1000001+) and a `severity` via
  `severity:1–4` (1 = most severe).

### 3. Alert Processing — `src/alert_processor.py`
- Reads `eve.json` line-by-line (JSON Lines format).
- Keeps only `event_type == "alert"` records; normalises each alert into a
  flat incident record:
  `timestamp, signature, severity, category, src_ip, dest_ip, dest_port,
  protocol, action, flow_id`.
- Persists incidents to:
  - `data/incidents.json` — append-only JSON array (dashboard-friendly)
  - `data/incidents.db` — SQLite table for querying/reporting
- Supports one-shot processing and `--watch` (tail-follow) mode.
- Tracks per-source-IP alert counts for the response stage.

### 4. Automated Response — `src/response.py`
- `block_ip(ip)` — adds an `iptables -A INPUT -s <ip> -j DROP` rule
  (requires root; falls back to a logged "dry-run" entry when unavailable).
- `unblock_ip(ip)` / `list_blocked()` — manage the block list.
- Safety rails:
  - Strict IP validation (rejects malformed input / injection attempts).
  - Whitelist file (`data/whitelist.txt`) — never block these.
  - Dry-run by default in tests; `--auto-block` must be passed explicitly.
  - Every action is written to `data/blocked_ips.json` (audit trail).

### 5. Security Dashboard — `dashboard/app.py`
- Streamlit app reading `data/incidents.json`.
- KPI cards: total alerts, unique attacker IPs, critical alerts, blocked IPs.
- Charts (Plotly): alerts over time, severity distribution, top signatures,
  top attacker IPs, protocol breakdown.
- Filters: severity, signature search, attacker IP search.
- Full incident table with raw alert details.
- **Demo mode:** if no incidents exist (or toggled on), generates realistic
  synthetic data so the dashboard can be evaluated without live traffic.

## Data Flow Example

1. Attacker runs `nmap -sS 192.168.56.101` against the lab network.
2. Suricata sees SYN packets to many ports from one source.
3. Rule `sid:1000002` (TCP SYN scan) fires → alert written to `eve.json`.
4. `alert_processor.py --watch` picks it up, stores the incident, and
   increments the counter for that source IP.
5. After `--block-threshold` (default 5) alerts, `response.py` blocks the IP.
6. The dashboard immediately shows the new alerts, the attacker's IP in the
   "Top Attackers" chart, and the blocked status.

## Security & Safety Notes

- Run Suricata and the lab in **VirtualBox** on an isolated host-only /
  internal network — never on a production or third-party network.
- Auto-blocking is **off by default**; enable it deliberately and review the
  audit log.
- The whitelist protects your own management IPs from accidental blocking.
