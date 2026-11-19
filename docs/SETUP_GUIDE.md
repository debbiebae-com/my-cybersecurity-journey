# Setup Guide

## Prerequisites

- Ubuntu Linux 22.04+ (or Debian 12) — a VirtualBox VM is recommended
- Python 3.10+
- `sudo` access
- A second VM (e.g. Kali / Ubuntu) on the same VirtualBox internal network
  to act as the attacker for testing

## 1. Clone the repository

```bash
git clone https://github.com/debbiebae-com/my-cybersecurity-journey.git
cd my-cybersecurity-journey
```

## 2. Run the automated setup

```bash
bash scripts/setup.sh
```

This will:

1. Install Suricata and its dependencies (`apt`).
2. Install Python dependencies (`pip install -r requirements.txt`).
3. Create `data/`, `logs/` and `data/whitelist.txt`.
4. Verify the Suricata config and rules syntax.

> If you don't have root access (e.g. you're just exploring the code),
> skip the Suricata install and run the Python parts only:
>
> ```bash
> pip install -r requirements.txt
> python3 -m src.alert_processor --input tests/sample_eve.json
> streamlit run dashboard/app.py
> ```

## 3. Configure Suricata

Edit `suricata/suricata.yaml` and set your network interface:

```yaml
default-interface: eth0   # ← change to YOUR interface (ip a)
```

Find your interface with `ip -br a`. In VirtualBox it is often `ens33`,
`enp0s3` or `eth0`.

## 4. Start Suricata

```bash
sudo suricata -c suricata/suricata.yaml \
              -S suricata/rules/local.rules \
              -l logs/
```

- Alerts appear in `logs/eve.json` (JSON) and `logs/fast.log` (text).
- Stop with `Ctrl+C`.

## 5. Process alerts

```bash
# Process everything already in eve.json
python3 -m src.alert_processor --input logs/eve.json

# Or follow eve.json live and auto-block repeat offenders
python3 -m src.alert_processor --input logs/eve.json --watch --auto-block
```

Incidents are stored in `data/incidents.json` and `data/incidents.db`.

Useful options:

| Flag | Default | Description |
|---|---|---|
| `--input` | `logs/eve.json` | Suricata EVE JSON file |
| `--output` | `data/incidents.json` | Incident JSON store |
| `--db` | `data/incidents.db` | SQLite incident store |
| `--watch` | off | Tail-follow the input file |
| `--auto-block` | off | Block IPs over the threshold |
| `--block-threshold` | `5` | Alerts before an IP is blocked |
| `--dry-run` | off | Log blocks without running iptables |

## 6. Launch the dashboard

```bash
streamlit run dashboard/app.py
```

Open <http://localhost:8501>. If no incidents exist yet, enable
**Demo mode** in the sidebar to explore with sample data.

## 7. Simulate attacks (lab only!)

From the attacker VM, pointing at the Suricata VM:

```bash
bash scripts/simulate_attacks.sh <suricata-vm-ip>
```

See [TESTING.md](TESTING.md) for what each simulation should trigger.

## Troubleshooting

| Problem | Fix |
|---|---|
| `suricata: command not found` | Run `bash scripts/setup.sh` or install Suricata manually |
| `Permission denied` on `logs/` | `sudo chown -R $USER logs/` or run Suricata with `sudo` |
| No alerts in dashboard | Check `logs/eve.json` exists; run the alert processor; check the interface name in `suricata.yaml` |
| Dashboard shows demo data only | Turn off Demo mode and ensure `data/incidents.json` is populated |
| `iptables: Permission denied` | Auto-block needs root: `sudo python3 -m src.alert_processor ... --auto-block` |
