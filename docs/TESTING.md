# Testing Guide

> ⚠️ **Only test against systems you own or have explicit written permission
> to test.** All simulations below target your own isolated VirtualBox lab.

## Test Environment

| Role | Example |
|---|---|
| Suricata VM (sensor) | Ubuntu VM, host-only network `192.168.56.0/24` |
| Attacker VM | Kali / Ubuntu VM on the same internal network |
| Target VM (optional) | Ubuntu VM running SSH/HTTP |

## Automated Tests (unit tests)

```bash
pip install pytest
python3 -m pytest tests/ -v
```

Covers: EVE JSON parsing, severity normalisation, IP validation, and the
block-list logic (in dry-run mode — no real iptables changes).

## Manual Attack Simulations

Run from the **attacker VM** against the Suricata VM:

```bash
bash scripts/simulate_attacks.sh <sensor-ip>
```

| # | Simulation | Command | Expected detection |
|---|---|---|---|
| 1 | TCP SYN port scan | `nmap -sS <sensor-ip>` | `sid:1000002` — TCP SYN scan detected |
| 2 | Aggressive port scan | `nmap -A -T4 <sensor-ip>` | Multiple rules (scan + service probes) |
| 3 | ICMP sweep | `nmap -sn <subnet>` or `ping` sweep | `sid:1000010` — ICMP echo sweep |
| 4 | ICMP flood | `hping3 -1 --flood <sensor-ip>` | `sid:1000011` — ICMP flood |
| 5 | SSH brute force | `hydra -l root -P rockyou.txt ssh://<sensor-ip>` | `sid:1000020` — SSH brute force |
| 6 | FTP brute force | `hydra -l admin -P passwords.txt ftp://<sensor-ip>` | `sid:1000021` — FTP brute force |
| 7 | HTTP scanner UA | `curl -A "sqlmap/1.7" http://<sensor-ip>/` | `sid:1000030` — sqlmap user agent |
| 8 | Nikto scan | `nikto -h http://<sensor-ip>` | `sid:1000031` — Nikto user agent |
| 9 | Telnet connection | `nc <sensor-ip> 23` | `sid:1000005` — Telnet connection attempt |
| 10 | SMB probe | `nmap -p 445 <sensor-ip>` | `sid:1000006` — SMB connection attempt |

## Verifying Detection

1. **Suricata side:**
   ```bash
   tail -f logs/fast.log          # human-readable alerts
   tail -f logs/eve.json | jq .   # structured alerts
   ```
2. **Processor side:**
   ```bash
   python3 -m src.alert_processor --input logs/eve.json
   cat data/incidents.json | jq .
   ```
3. **Dashboard side:** open <http://localhost:8501> and confirm the new
   alerts, attacker IP and signature appear.
4. **Response side (if `--auto-block` enabled):**
   ```bash
   cat data/blocked_ips.json
   sudo iptables -L INPUT -n | grep DROP
   ```

## Recording Results

For each test, record in a table like this (and keep screenshots for the
project report):

| Date | Test | Source IP | Rule triggered (sid) | Alert in eve.json? | In dashboard? | IP blocked? | Notes |
|---|---|---|---|---|---|---|---|
| 2026-11-19 | TCP SYN scan | 192.168.56.102 | 1000002 | ✅ | ✅ | ✅ (after 5) | … |

## Sample Data Test (no lab needed)

```bash
python3 -m src.alert_processor --input tests/sample_eve.json
streamlit run dashboard/app.py
```

This loads the bundled sample alerts so you can verify the full pipeline
(processor → store → dashboard) without Suricata or a second VM.
