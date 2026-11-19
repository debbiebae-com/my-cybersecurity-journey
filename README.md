# My Cybersecurity Journey

## Network Intrusion Detection System (NIDS)

A cybersecurity project that monitors network traffic in real time, detects
suspicious activities and potential cyberattacks, generates security alerts,
and visualises threats on a web dashboard — helping network administrators
identify and respond to threats **before** they cause significant damage.

> Built with **Suricata** (detection engine) + **Python** (alert processing &
> automated response) + **Streamlit** (security dashboard) on **Ubuntu Linux**.

---

## How It Works

```
Network Traffic
      │
      ▼
┌─────────────┐   Rules    ┌──────────────────┐
│  Suricata   │◄───────────│ local.rules        │
│  (monitor & │            │ (port scan, ICMP,  │
│   inspect)  │            │  brute-force, …)   │
└──────┬──────┘            └──────────────────┘
       │ eve.json (JSON alerts)
       ▼
┌──────────────────┐     ┌────────────────────┐
│ alert_processor  │────►│ incidents.json /   │
│ (Python)         │     │ incidents.db       │
│ - parse & store  │     └─────────┬──────────┘
│ - count & score  │               │
└────────┬─────────┘               ▼
         │ threshold exceeded   ┌────────────────────┐
         ▼                      │ Streamlit Dashboard│
┌──────────────────┐            │ - alert counts     │
│ response.py      │            │ - attacker IPs     │
│ - block IP       │            │ - attack stats     │
│   (iptables)     │            │ - incident table   │
└──────────────────┘            └────────────────────┘
```

1. **Traffic monitoring** — Suricata watches the selected network interface.
2. **Traffic inspection** — packets are compared against detection rules.
3. **Threat detection** — port scans, ICMP probing, suspicious connections,
   brute-force indicators and known malicious signatures are flagged.
4. **Alert generation** — Suricata writes alerts to `eve.json`.
5. **Log processing** — Python reads, parses and stores the alerts.
6. **Incident response** — repeat/severe offenders can be blocked automatically
   (controlled, with a whitelist and dry-run mode).
7. **Visualisation** — the Streamlit dashboard shows alerts, threats and
   network-activity statistics.

## Attacks Detected

| Attack / Activity | What the system looks for |
|---|---|
| Port scanning | Attempts to discover open ports (SYN scans, many ports from one host) |
| Suspicious connections | Unusual / unauthorised connection attempts (Telnet, SMB, RDP…) |
| ICMP scanning | Suspicious ICMP probing (echo-request sweeps, floods) |
| Brute-force indicators | Repeated authentication attempts where visible |
| Malicious traffic | Traffic matching known signatures (sqlmap, Nikto, Metasploit…) |
| Suspicious network activity | Unusual patterns identified by configured rules |

> Detection depends on available traffic, visibility and configured rules.
> No IDS automatically identifies *every* possible cyberattack.

## Project Structure

```
my-cybersecurity-journey/
├── README.md                     ← you are here
├── requirements.txt              ← Python dependencies
├── docs/
│   ├── PROJECT_INTRODUCTION.md   ← full project brief & objectives
│   ├── SETUP_GUIDE.md            ← install & run instructions
│   ├── ARCHITECTURE.md           ← design & data flow
│   └── TESTING.md                ← how to simulate & verify attacks
├── suricata/
│   ├── suricata.yaml             ← Suricata configuration
│   └── rules/
│       └── local.rules           ← custom intrusion detection rules
├── src/
│   ├── alert_processor.py        ← parses eve.json → incidents store
│   └── response.py               ← controlled IP blocking (iptables)
├── dashboard/
│   └── app.py                    ← Streamlit security dashboard
├── scripts/
│   ├── setup.sh                  ← one-shot environment setup (Ubuntu)
│   ├── run_suricata.sh           ← start Suricata
│   └── simulate_attacks.sh       ← safe lab attack simulations
├── data/                         ← generated incidents (git-ignored)
└── tests/
    ├── test_alert_processor.py
    └── sample_eve.json           ← sample Suricata output for testing
```

## Quick Start

### 1. Setup (Ubuntu)

```bash
bash scripts/setup.sh
```

This installs Suricata, Python dependencies, and creates the `data/` and
`logs/` directories.

### 2. Run Suricata

```bash
sudo bash scripts/run_suricata.sh
# or directly:
sudo suricata -c suricata/suricata.yaml -S suricata/rules/local.rules -l logs/
```

> Edit `suricata/suricata.yaml` and set `default-interface` to your NIC
> (e.g. `eth0`, `ens33`, `wlan0`) before running.

### 3. Process Alerts

```bash
# One-shot: process the whole eve.json file
python3 -m src.alert_processor --input logs/eve.json

# Live: keep watching eve.json and auto-block repeat offenders
python3 -m src.alert_processor --input logs/eve.json --watch --auto-block
```

### 4. Launch the Dashboard

```bash
streamlit run dashboard/app.py
# open http://localhost:8501
```

No Suricata traffic yet? The dashboard ships with a **Demo mode** that
generates realistic sample incidents so you can explore it immediately.

### 5. Test Detection (in an isolated lab only!)

```bash
# in a separate terminal, against YOUR OWN lab VM — never a network you don't own
bash scripts/simulate_attacks.sh 192.168.56.101
```

See [docs/TESTING.md](docs/TESTING.md) for the full test plan.

## Roadmap

- [x] **Phase 1** — Environment setup (Ubuntu, VirtualBox lab, Git)
- [x] **Phase 2** — Suricata installation & configuration
- [x] **Phase 3** — Intrusion detection rules (`local.rules`)
- [x] **Phase 4** — Python alert processing (`alert_processor.py`)
- [x] **Phase 5** — Automated response mechanisms (`response.py`)
- [x] **Phase 6** — Dashboard development (Streamlit)
- [ ] **Phase 7** — Testing, documentation & GitHub submission
  - [ ] Run live attack simulations and capture screenshots
  - [ ] Record test results in `docs/TESTING.md`
  - [ ] Final review & submission

## Technologies

| Technology | Purpose |
|---|---|
| Ubuntu Linux | Operating environment |
| Suricata | Network intrusion detection |
| Python | Log processing & automation |
| Bash | System administration |
| JSON | Security event storage |
| Streamlit | Security dashboard |
| VirtualBox | Isolated testing environment |
| Git & GitHub | Version control & submission |

## Deliverables

- [x] Fully configured Suricata intrusion detection engine
- [x] Custom network intrusion detection rules
- [x] Python-based alert processing system
- [x] Security incident logging mechanism
- [x] Automated response mechanism
- [x] Functional web-based security dashboard
- [ ] Evidence of successful attack simulations & detection
- [x] GitHub repository with complete source code & documentation

## Disclaimer

This project is for **educational and defensive purposes only**. Only test
against systems and networks you own or have explicit written permission to
test. Never scan or attack third-party networks.
