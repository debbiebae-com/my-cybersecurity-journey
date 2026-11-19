"""
app.py — Streamlit Security Dashboard for the NIDS project.

Visualises detected threats, network activities and security incidents
stored by src/alert_processor.py in data/incidents.json.

Run:
    streamlit run dashboard/app.py
    # open http://localhost:8501

If no real incidents exist yet, enable "Demo mode" in the sidebar to
explore the dashboard with realistic synthetic data.
"""

from __future__ import annotations

import json
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

INCIDENTS_FILE = PROJECT_ROOT / "data" / "incidents.json"
BLOCKED_FILE = PROJECT_ROOT / "data" / "blocked_ips.json"

SEVERITY_COLORS = {1: "#d62728", 2: "#ff7f0e", 3: "#bcbd22", 4: "#2ca02c"}

DEMO_SIGNATURES = [
    ("NIDS Port Scan: TCP SYN scan detected", 2, "attempted-recon"),
    ("NIDS Port Scan: Possible stealth SYN scan", 3, "attempted-recon"),
    ("NIDS ICMP Scan: Echo request sweep detected", 2, "attempted-recon"),
    ("NIDS ICMP Scan: ICMP flood detected", 1, "dos-attack"),
    ("NIDS Brute Force: Repeated SSH authentication attempts", 1, "attempted-admin"),
    ("NIDS Brute Force: Repeated FTP authentication attempts", 1, "attempted-admin"),
    ("NIDS Malicious: sqlmap user agent detected", 1, "trojan-activity"),
    ("NIDS Malicious: Nikto scanner user agent detected", 1, "trojan-activity"),
    ("NIDS Suspicious: SMB connection attempt", 3, "policy-violation"),
    ("NIDS Suspicious: Telnet connection attempt", 3, "policy-violation"),
    ("NIDS Malicious: SQL injection attempt in URI", 1, "web-application-attack"),
    ("NIDS Suspicious: Many failed TCP connections from single host", 2, "attempted-recon"),
]
DEMO_IPS = ["192.168.56.102", "192.168.56.103", "10.0.0.45", "172.16.5.9",
            "192.168.56.110"]
DEMO_DESTS = ["192.168.56.101", "192.168.56.1", "10.0.0.1"]


def generate_demo_data(n: int = 120) -> pd.DataFrame:
    """Generate realistic synthetic incidents for demo / evaluation."""
    random.seed(42)
    now = datetime.now()
    rows = []
    for _ in range(n):
        sig, sev, cat = random.choice(DEMO_SIGNATURES)
        ts = now - timedelta(minutes=random.randint(0, 60 * 12))
        rows.append({
            "timestamp": ts.isoformat(),
            "signature": sig,
            "signature_id": str(1000001 + DEMO_SIGNATURES.index((sig, sev, cat))),
            "severity": sev,
            "severity_label": {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}[sev],
            "category": cat,
            "src_ip": random.choice(DEMO_IPS),
            "dest_ip": random.choice(DEMO_DESTS),
            "dest_port": random.choice([22, 23, 80, 443, 445, 3389, 53, 21]),
            "protocol": random.choice(["TCP", "TCP", "TCP", "UDP", "ICMP"]),
            "action": "allowed",
            "flow_id": str(random.randint(100000, 999999)),
        })
    return pd.DataFrame(rows)


def load_incidents() -> pd.DataFrame:
    if not INCIDENTS_FILE.exists():
        return pd.DataFrame()
    try:
        data = json.loads(INCIDENTS_FILE.read_text())
    except json.JSONDecodeError:
        return pd.DataFrame()
    if not data:
        return pd.DataFrame()
    df = pd.DataFrame(data)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df.sort_values("timestamp").reset_index(drop=True)


def load_blocked() -> pd.DataFrame:
    if not BLOCKED_FILE.exists():
        return pd.DataFrame()
    try:
        data = json.loads(BLOCKED_FILE.read_text())
    except json.JSONDecodeError:
        return pd.DataFrame()
    return pd.DataFrame(data) if data else pd.DataFrame()


def main() -> None:
    st.set_page_config(page_title="NIDS Security Dashboard",
                       page_icon="🛡️", layout="wide")

    st.title("🛡️ Network Intrusion Detection System — Security Dashboard")
    st.caption("Real-time visualisation of detected threats, network "
               "activities and security incidents (Suricata + Python + Streamlit).")

    # ---- Sidebar -----------------------------------------------------------
    with st.sidebar:
        st.header("Controls")
        demo_mode = st.toggle("Demo mode (synthetic data)", value=False)
        refresh = st.button("🔄 Refresh data")
        st.divider()
        st.markdown("**Pipeline**")
        st.markdown("1. Suricata monitors traffic\n"
                    "2. Rules detect attacks\n"
                    "3. Python processes alerts\n"
                    "4. Repeat offenders can be blocked\n"
                    "5. This dashboard visualises everything")

    if refresh:
        st.rerun()

    # ---- Data --------------------------------------------------------------
    df = load_incidents()
    using_demo = False
    if demo_mode or df.empty:
        df = generate_demo_data()
        using_demo = True

    if using_demo:
        st.info("Showing **demo data** — run "
                "`python3 -m src.alert_processor --input logs/eve.json` "
                "to load real Suricata alerts, then turn Demo mode off.")

    blocked_df = load_blocked()

    # ---- Filters -----------------------------------------------------------
    with st.sidebar:
        st.divider()
        st.header("Filters")
        severities = sorted(df["severity"].unique().tolist())
        sev_labels = {1: "Critical", 2: "High", 3: "Medium", 4: "Low"}
        selected_sev = st.multiselect(
            "Severity", options=severities,
            default=severities,
            format_func=lambda s: f"{s} — {sev_labels.get(s, '')}")
        sig_search = st.text_input("Signature contains…", "")
        ip_search = st.text_input("Attacker IP contains…", "")

    filtered = df[df["severity"].isin(selected_sev)]
    if sig_search:
        filtered = filtered[filtered["signature"].str.contains(
            sig_search, case=False, na=False)]
    if ip_search:
        filtered = filtered[filtered["src_ip"].str.contains(
            ip_search, case=False, na=False)]

    # ---- KPI cards ---------------------------------------------------------
    total = len(filtered)
    unique_attackers = filtered["src_ip"].nunique() if total else 0
    critical = int((filtered["severity"] == 1).sum()) if total else 0
    blocked_count = len(blocked_df)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total alerts", total)
    col2.metric("Unique attacker IPs", unique_attackers)
    col3.metric("Critical alerts", critical)
    col4.metric("IPs blocked", blocked_count)

    st.divider()

    if total == 0:
        st.warning("No incidents match the current filters.")
        return

    # ---- Charts ------------------------------------------------------------
    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("Alerts over time")
        hourly = (filtered.set_index("timestamp")
                  .resample("1h").size().reset_index(name="count"))
        fig_time = px.line(hourly, x="timestamp", y="count",
                           title="Alert volume per hour", markers=True)
        st.plotly_chart(fig_time, use_container_width=True)

    with chart_col2:
        st.subheader("Alerts by severity")
        sev_counts = (filtered.groupby(["severity", "severity_label"])
                      .size().reset_index(name="count"))
        fig_sev = px.pie(sev_counts, names="severity_label", values="count",
                         title="Severity distribution",
                         color="severity_label",
                         color_discrete_map={v: SEVERITY_COLORS[k]
                                             for k, v in
                                             [(1, "Critical"), (2, "High"),
                                              (3, "Medium"), (4, "Low")]})
        st.plotly_chart(fig_sev, use_container_width=True)

    chart_col3, chart_col4 = st.columns(2)

    with chart_col3:
        st.subheader("Top attacker IPs")
        top_ips = (filtered["src_ip"].value_counts().head(10)
                   .reset_index(name="count"))
        top_ips.columns = ["src_ip", "count"]
        fig_ips = px.bar(top_ips, x="src_ip", y="count",
                         title="Alerts per source IP", color="count")
        st.plotly_chart(fig_ips, use_container_width=True)

    with chart_col4:
        st.subheader("Top signatures")
        top_sig = (filtered["signature"].value_counts().head(8)
                   .reset_index(name="count"))
        top_sig.columns = ["signature", "count"]
        fig_sig = px.bar(top_sig, x="count", y="signature",
                         orientation="h",
                         title="Most triggered detection rules")
        st.plotly_chart(fig_sig, use_container_width=True)

    st.subheader("Alerts by protocol")
    proto_counts = filtered["protocol"].value_counts().reset_index(name="count")
    proto_counts.columns = ["protocol", "count"]
    st.plotly_chart(px.bar(proto_counts, x="protocol", y="count",
                           title="Protocol breakdown"),
                    use_container_width=True)

    # ---- Blocked IPs -------------------------------------------------------
    st.divider()
    st.subheader("🚫 Blocked IP addresses (automated response)")
    if blocked_df.empty:
        st.caption("No IPs blocked yet. Enable `--auto-block` in the alert "
                   "processor to block repeat offenders.")
    else:
        st.dataframe(blocked_df, use_container_width=True, hide_index=True)

    # ---- Incident table ----------------------------------------------------
    st.divider()
    st.subheader(f"📋 Incident log ({total} shown)")
    display = filtered.copy()
    display["timestamp"] = display["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    st.dataframe(
        display[["timestamp", "severity_label", "signature", "src_ip",
                 "dest_ip", "dest_port", "protocol", "category"]],
        use_container_width=True, hide_index=True)

    with st.expander("Raw incident data (JSON)"):
        st.json(filtered.to_dict(orient="records")[:50])


if __name__ == "__main__":
    main()
