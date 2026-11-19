#!/usr/bin/env bash
# ============================================================================
# simulate_attacks.sh — Safe lab attack simulations for the NIDS project
# ============================================================================
# Usage:  bash scripts/simulate_attacks.sh <target-ip>
# Example: bash scripts/simulate_attacks.sh 192.168.56.101
#
# ⚠️  ONLY run this against systems you own / have permission to test
#     (e.g. your own VirtualBox lab). Never scan third-party networks.
# ============================================================================
set -uo pipefail

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip>   (the Suricata sensor VM in YOUR lab)" >&2
    echo "Example: $0 192.168.56.101" >&2
    exit 1
fi

echo "⚠️  Target: $TARGET — confirm this is YOUR OWN lab machine. [y/N]"
read -r -p "Continue? " confirm
case "$confirm" in [yY]|[yY][eE][sS]) ;; *) echo "Aborted."; exit 0;; esac

have() { command -v "$1" >/dev/null 2>&1; }

echo ""
echo "==> [1/6] TCP SYN port scan (nmap -sS)"
have nmap && nmap -sS "$TARGET" || echo "  (nmap not installed — skipping)"

echo ""
echo "==> [2/6] ICMP sweep (ping sweep)"
ping -c 2 -W 1 "$TARGET" >/dev/null 2>&1 || true
have nmap && nmap -sn "$TARGET" || echo "  (nmap not installed — skipping)"

echo ""
echo "==> [3/6] HTTP scanner user agents (sqlmap / Nikto)"
curl -s -A "sqlmap/1.7.2#stable" "http://$TARGET/" >/dev/null 2>&1 || true
curl -s -A "Nikto/2.5.0" "http://$TARGET/" >/dev/null 2>&1 || true
echo "  sent sqlmap + Nikto user-agent requests"

echo ""
echo "==> [4/6] SQL injection probe"
curl -s "http://$TARGET/?id=1%20UNION%20SELECT%201,2" >/dev/null 2>&1 || true
echo "  sent SQLi probe"

echo ""
echo "==> [5/6] Suspicious service probes (Telnet / SMB ports)"
for port in 23 445 3389; do
    timeout 2 bash -c "echo > /dev/tcp/$TARGET/$port" 2>/dev/null || true
done
echo "  probed ports 23, 445, 3389"

echo ""
echo "==> [6/6] SSH brute-force indicators (5 quick attempts)"
for i in 1 2 3 4 5; do
    timeout 3 ssh -o BatchMode=yes -o ConnectTimeout=2 \
        -o StrictHostKeyChecking=no "user$i@$TARGET" true 2>/dev/null || true
done
echo "  sent 5 SSH auth attempts"

echo ""
echo "==> Simulations complete. Check detection with:"
echo "    tail -f logs/fast.log"
echo "    python3 -m src.alert_processor --input logs/eve.json"
echo "    streamlit run dashboard/app.py"
