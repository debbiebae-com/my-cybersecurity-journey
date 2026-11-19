#!/usr/bin/env bash
# ============================================================================
# run_suricata.sh — Start Suricata with this project's config and rules
# ============================================================================
# Usage:  sudo bash scripts/run_suricata.sh
# ============================================================================
set -euo pipefail

cd "$(dirname "$0")/.."
mkdir -p logs

if ! command -v suricata >/dev/null 2>&1; then
    echo "ERROR: suricata not found. Run: bash scripts/setup.sh" >&2
    exit 1
fi

echo "==> Starting Suricata (interface from suricata/suricata.yaml)…"
echo "    Alerts: logs/eve.json + logs/fast.log   (Ctrl+C to stop)"
sudo suricata -c suricata/suricata.yaml \
              -S suricata/rules/local.rules \
              -l logs/
