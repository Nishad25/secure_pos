#!/usr/bin/env python3
"""
POSGuard Security Operations Dashboard (Streamlit)
---------------------------------------------------
A polished, interactive front-end for the existing POSGuard backend.
This is an ADDITIONAL presentation layer -- it does not replace or modify
the FastAPI compliance dashboard (:9000) or the Ryu REST API (:8080).
It only consumes their existing endpoints.

Run with:
    pip install streamlit requests pandas
    streamlit run security_dashboard.py
"""

import time
from datetime import datetime

import pandas as pd
import requests
import streamlit as st

DASHBOARD_API = "http://localhost:9000"
RYU_API = "http://localhost:8080/posguard"
REFRESH_SECONDS = 5

st.set_page_config(
    page_title="POSGuard Security Operations",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .main { background-color: #0E1117; }
    .stMetric {
        background-color: #161B22;
        border: 1px solid #30363D;
        border-radius: 10px;
        padding: 16px;
    }
    div[data-testid="stMetricValue"] { font-size: 2.2rem; }
    .status-online {
        background-color: #1F4620; color: #4ADE80;
        padding: 4px 12px; border-radius: 20px; font-weight: 600; font-size: 0.85rem;
    }
    .status-quarantined {
        background-color: #4A1F1F; color: #F87171;
        padding: 4px 12px; border-radius: 20px; font-weight: 600; font-size: 0.85rem;
    }
    .severity-critical { color: #F87171; font-weight: 700; }
    .severity-warning { color: #FBBF24; font-weight: 600; }
    .severity-info { color: #60A5FA; }
    .block-container { padding-top: 2rem; }
</style>
""", unsafe_allow_html=True)


def api_get(url, timeout=3):
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        return resp.json(), None
    except requests.exceptions.RequestException as e:
        return None, str(e)


def api_post(url, timeout=3):
    try:
        resp = requests.post(url, timeout=timeout)
        return resp.json(), None
    except requests.exceptions.RequestException as e:
        return None, str(e)


with st.sidebar:
    st.markdown("## 🛡️ POSGuard")
    st.caption("Security Operations Console")
    st.divider()

    st.markdown("### Manual Terminal Control")
    target_ip = st.text_input("Terminal IP", placeholder="10.0.0.1")
    col_q, col_r = st.columns(2)
    with col_q:
        if st.button("🔒 Quarantine", use_container_width=True, type="primary"):
            if target_ip:
                result, err = api_post(f"{RYU_API}/quarantine/{target_ip}")
                if err:
                    st.error(f"Failed: {err}")
                else:
                    st.success(result.get("message", "Quarantined"))
            else:
                st.warning("Enter a terminal IP first")
    with col_r:
        if st.button("🔓 Release", use_container_width=True):
            if target_ip:
                result, err = api_post(f"{RYU_API}/release/{target_ip}")
                if err:
                    st.error(f"Failed: {err}")
                else:
                    st.success(result.get("message", "Released"))
            else:
                st.warning("Enter a terminal IP first")

    st.divider()
    auto_refresh = st.toggle("Auto-refresh", value=True)
    st.caption(f"Refreshes every {REFRESH_SECONDS}s when enabled")
    st.divider()
    st.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

st.title("Security Operations Dashboard")

compliance, compliance_err = api_get(f"{DASHBOARD_API}/api/compliance")
events, events_err = api_get(f"{DASHBOARD_API}/api/events")

if compliance_err:
    st.error(f"⚠️ Cannot reach compliance dashboard at {DASHBOARD_API} — is `dashboard/app.py` running? ({compliance_err})")
    st.stop()

pci_score = compliance.get("pci_score", 0)
critical_alerts = compliance.get("critical_alerts", 0)
total_events = compliance.get("total_events", 0)
terminals = compliance.get("terminals", [])

c1, c2, c3, c4 = st.columns(4)
score_delta = "Good" if pci_score >= 80 else ("Degraded" if pci_score >= 50 else "Critical")
c1.metric("PCI Compliance Score", f"{pci_score}", score_delta)
c2.metric("Critical Alerts", critical_alerts)
c3.metric("Total Events Logged", total_events)
quarantined_count = sum(1 for t in terminals if t["status"] == "Quarantined")
c4.metric("Terminals Quarantined", f"{quarantined_count} / {len(terminals)}")

st.divider()

left, right = st.columns([1, 1])

with left:
    st.subheader("Terminal Status")
    if not terminals:
        st.info("No terminals registered.")
    for t in terminals:
        badge_class = "status-online" if t["status"] == "Online" else "status-quarantined"
        icon = "🟢" if t["status"] == "Online" else "🔴"
        st.markdown(
            f"""<div style="display:flex; justify-content:space-between; align-items:center;
                 padding:12px; background:#161B22; border:1px solid #30363D; border-radius:8px; margin-bottom:8px;">
                <div>{icon} <b>{t['name']}</b> &nbsp; <code>{t['ip']}</code></div>
                <span class="{badge_class}">{t['status']}</span>
            </div>""",
            unsafe_allow_html=True,
        )

with right:
    st.subheader("Live Alert Feed")
    if events_err:
        st.warning(f"Could not load events: {events_err}")
    else:
        alert_list = events.get("events", [])
        if not alert_list:
            st.info("No alerts recorded yet.")
        else:
            for e in alert_list[:15]:
                sev = e.get("severity", "info")
                sev_class = f"severity-{sev}" if sev in ("critical", "warning") else "severity-info"
                ts = e.get("timestamp", "")[:19].replace("T", " ")
                st.markdown(
                    f"""<div style="padding:10px; background:#161B22; border-left:3px solid
                         {'#F87171' if sev=='critical' else '#FBBF24' if sev=='warning' else '#60A5FA'};
                         border-radius:4px; margin-bottom:6px;">
                        <span class="{sev_class}">{sev.upper()}</span>
                        <span style="color:#8B949E; font-size:0.8rem;"> &nbsp;{ts} &nbsp;·&nbsp; {e.get('source','')}</span><br/>
                        <span style="color:#C9D1D9;">{e.get('message','')}</span>
                    </div>""",
                    unsafe_allow_html=True,
                )

st.divider()

st.subheader("Compliance Score Trend")
if events and events.get("events"):
    rows = []
    running_critical = 0
    all_events_chrono = list(reversed(events["events"]))
    for e in all_events_chrono:
        if e.get("severity") == "critical":
            running_critical += 1
        score = max(0, 100 - 25 * running_critical)
        rows.append({"time": e.get("timestamp", "")[:19], "pci_score": score})
    if rows:
        df = pd.DataFrame(rows)
        st.line_chart(df.set_index("time")["pci_score"], height=250)
else:
    st.caption("No event history yet to plot.")

if auto_refresh:
    time.sleep(REFRESH_SECONDS)
    st.rerun()