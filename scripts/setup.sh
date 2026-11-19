#!/usr/bin/env bash
# ============================================================================
# setup.sh — One-shot environment setup for the NIDS project (Ubuntu/Debian)
# ============================================================================
# Usage:  bash scripts/setup.sh
# Run from the project root. Requires sudo for the Suricata install.
# ============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."
echo "==> NIDS project setup in $(pwd)"

# --- 1. System packages + Suricata -------------------------------------------
if command -v suricata >/dev/null 2>&1; then
    echo "[setup] Suricata already installed: $(suricata -V 2>/dev/null || true)"
else
    echo "[setup] Installing Suricata and Python venv (this needs sudo)…"
    if ! (sudo apt-get update && sudo apt-get install -y suricata python3 python3-pip python3-venv); then
        echo "[setup] ERROR: Failed to install Suricata or Python packages via apt." >&2
        exit 1
    fi
fi

# --- 2. Python virtual environment & dependencies ----------------------------
echo "[setup] Setting up Python virtual environment (.venv)…"
if [ ! -d ".venv" ]; then
    if ! python3 -m venv .venv; then
        echo "[setup] ERROR: Failed to create .venv. Ensure python3-venv is installed." >&2
        exit 1
    fi
fi

echo "[setup] Installing Python dependencies into .venv…"
if ! .venv/bin/pip install --upgrade pip >/dev/null 2>&1; then
    echo "[setup] WARNING: pip upgrade failed, continuing with existing pip…"
fi
if ! .venv/bin/pip install -r requirements.txt; then
    echo "[setup] ERROR: Failed to install Python dependencies from requirements.txt." >&2
    exit 1
fi
echo "[setup] Python dependencies installed in .venv/"

# --- 3. Project directories ----------------------------------------------------
mkdir -p data logs
touch data/whitelist.txt
if ! grep -q "127.0.0.1" data/whitelist.txt 2>/dev/null; then
    cat >> data/whitelist.txt <<'EOF'
# IPs that must NEVER be auto-blocked (one per line)
127.0.0.1
::1
EOF
fi
echo "[setup] Created data/ and logs/ (whitelist: data/whitelist.txt)"

# --- 4. Validate Suricata config + rules ---------------------------------------
if ! command -v suricata >/dev/null 2>&1; then
    echo "[setup] ERROR: suricata command not found after installation." >&2
    exit 1
fi

echo "[setup] Validating Suricata configuration and custom rules…"
if ! sudo suricata -T -c suricata/suricata.yaml -S suricata/rules/local.rules; then
    echo "[setup] ERROR: Suricata configuration/rule validation failed!" >&2
    echo "        Check suricata/suricata.yaml (interface name) and suricata/rules/local.rules." >&2
    exit 1
fi
echo "[setup] Suricata config and rules OK"

echo ""
echo "==> Setup complete. Next steps:"
echo "    1. Activate venv:  source .venv/bin/activate"
echo "    2. Edit suricata/suricata.yaml -> set default-interface to your NIC (ip -br a)"
echo "    3. sudo suricata -c suricata/suricata.yaml -S suricata/rules/local.rules -l logs/"
echo "    4. python3 -m src.alert_processor --input logs/eve.json --watch --auto-block"
echo "    5. streamlit run dashboard/app.py"
