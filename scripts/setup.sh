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
    echo "[setup] Installing Suricata (this needs sudo)…"
    if sudo apt-get update && sudo apt-get install -y suricata python3 python3-pip python3-venv; then
        echo "[setup] Suricata installed."
    else
        echo "[setup] WARNING: could not install Suricata via apt (no network / package unavailable)."
        echo "        Continuing with the Python parts — install Suricata manually on your Ubuntu VM:"
        echo "        sudo apt-get install -y suricata"
    fi
fi

# --- 2. Python dependencies ---------------------------------------------------
echo "[setup] Installing Python dependencies…"
python3 -m pip install --user -r requirements.txt 2>/dev/null || \
python3 -m pip install --break-system-packages -r requirements.txt 2>/dev/null || \
echo "[setup] WARNING: pip install failed — run 'pip install -r requirements.txt' manually."

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
if command -v suricata >/dev/null 2>&1; then
    echo "[setup] Validating Suricata configuration…"
    sudo suricata -T -c suricata/suricata.yaml -S suricata/rules/local.rules \
        && echo "[setup] Suricata config OK" \
        || echo "[setup] WARNING: config validation failed — check suricata.yaml (interface name, rule paths)"
fi

echo ""
echo "==> Setup complete. Next steps:"
echo "    1. Edit suricata/suricata.yaml  -> set default-interface to your NIC (ip -br a)"
echo "    2. sudo suricata -c suricata/suricata.yaml -S suricata/rules/local.rules -l logs/"
echo "    3. python3 -m src.alert_processor --input logs/eve.json --watch"
echo "    4. streamlit run dashboard/app.py"
