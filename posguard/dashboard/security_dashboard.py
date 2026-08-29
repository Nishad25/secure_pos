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
    .status-throttled {
        background-color: #4A3A1F; color: #FBBF24;
        padding: 4px 12px; border-radius: 20px; font-weight: 600; font-size: 0.85rem;
    }
    .status-quarantined {
        background-color: #4A1F1F; color: #F87171;
        padding: 4px 12px; border-radius: 20px; font-weight: 600; font-size: 0.85rem;
    }
    .status-unresponsive {
        background-color: #3A3A3A; color: #9CA3AF;
        padding: 4px 12px; border-radius: 20px; font-weight: 600; font-size: 0.85rem;
    }
    .offense-badge {
        background-color: #30363D; color: #C9D1D9;
        padding: 2px 8px; border-radius: 12px; font-size: 0.72rem; margin-left: 8px;
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


def api_post(url, params=None, timeout=3):
    try:
        resp = requests.post(url, params=params or {}, timeout=timeout)
        return resp.json(), None
    except requests.exceptions.RequestException as e:
        return None, str(e)


with st.sidebar:
    st.markdown("## 🛡️ POSGuard")
    st.caption("Security Operations Console")
    st.divider()

    st.markdown("### Manual Terminal Control")
    target_ip = st.text_input("Terminal IP", placeholder="10.0.0.1")
    force_critical = st.checkbox(
        "Force (allow acting on payment gateway / server)",
        help="Gap #4 refuses to auto-act on 10.0.0.100 / 10.0.0.200 unless this is checked."
    )
    col_q, col_t, col_r = st.columns(3)
    with col_q:
        if st.button("🔒 Quarantine", use_container_width=True, type="primary"):
            if target_ip:
                result, err = api_post(f"{RYU_API}/quarantine/{target_ip}",
                                        params={'force': 'true'} if force_critical else {})
                st.error(f"Failed: {err}") if err else st.success(result.get("message", "Quarantined"))
            else:
                st.warning("Enter a terminal IP first")
    with col_t:
        if st.button("🐢 Throttle", use_container_width=True):
            if target_ip:
                result, err = api_post(f"{RYU_API}/throttle/{target_ip}",
                                        params={'force': 'true'} if force_critical else {})
                st.error(f"Failed: {err}") if err else st.success(result.get("message", "Throttled"))
            else:
                st.warning("Enter a terminal IP first")
    with col_r:
        if st.button("🔓 Release", use_container_width=True):
            if target_ip:
                result, err = api_post(f"{RYU_API}/release/{target_ip}")
                st.error(f"Failed: {err}") if err else st.success(result.get("message", "Released"))
            else:
                st.warning("Enter a terminal IP first")

    if st.button("↺ Reset offense history", use_container_width=True):
        if target_ip:
            result, err = api_post(f"{RYU_API}/reset/{target_ip}")
            st.error(f"Failed: {err}") if err else st.info(result.get("message", "Reset"))
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
health, health_err = api_get(f"{DASHBOARD_API}/api/health")
agents, agents_err = api_get(f"{DASHBOARD_API}/api/agents")
pci_controls, pci_controls_err = api_get(f"{DASHBOARD_API}/api/pci-controls")

if compliance_err:
    st.error(f"⚠️ Cannot reach compliance dashboard at {DASHBOARD_API} — is `dashboard/app.py` running? ({compliance_err})")
    st.stop()

pci_score = compliance.get("pci_score", 0)
pci_control_coverage = compliance.get("pci_control_coverage_percent", 0)
critical_alerts = compliance.get("critical_alerts", 0)
warning_alerts = compliance.get("warning_alerts", 0)
total_events = compliance.get("total_events", 0)
terminals = compliance.get("terminals", [])

c1, c2, c3, c4, c5, c6 = st.columns(6)
score_delta = "Good" if pci_score >= 80 else ("Degraded" if pci_score >= 50 else "Critical")
c1.metric("Live Incident Score", f"{pci_score}", score_delta,
          help="Drops with recent critical/warning events — 'how bad is it right now?'")
c2.metric("PCI DSS Control Coverage", f"{pci_control_coverage}%",
          help="Structural mapping to the 12 PCI DSS v4.0 requirements — see the panel below")
c3.metric("Critical Alerts", critical_alerts)
c4.metric("Warning Alerts", warning_alerts)
c5.metric("Total Events Logged", total_events)
quarantined_count = sum(1 for t in terminals if t["status"] == "Quarantined")
c6.metric("Terminals Quarantined", f"{quarantined_count} / {len(terminals)}")

st.divider()

# --- Real POS system health (Gap #16) ---
st.subheader("POS System Health — real processes, not simulated")
if health_err or not health:
    st.info("No health data yet — is `agents/pos_health_monitor.py` running?")
else:
    hcols = st.columns(len(health)) if health else []
    for col, (service, data) in zip(hcols, health.items()):
        with col:
            latest = data.get("latest")
            status = data.get("status", "unresponsive")
            badge_class = "status-online" if status == "online" else "status-unresponsive"
            icon = "🟢" if status == "online" else "⚪"
            if latest:
                uptime_min = latest["uptime_seconds"] / 60
                st.markdown(
                    f"""<div style="padding:14px; background:#161B22; border:1px solid #30363D;
                         border-radius:8px; margin-bottom:8px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <b>{icon} {service}</b>
                            <span class="{badge_class}">{status}</span>
                        </div>
                        <div style="color:#8B949E; font-size:0.85rem; margin-top:8px;">
                            PID {latest['pid']} &nbsp;·&nbsp; up {uptime_min:.0f} min
                        </div>
                        <div style="color:#C9D1D9; font-size:0.9rem; margin-top:4px;">
                            {latest['memory_mb']:.0f} MB &nbsp;·&nbsp; {latest['cpu_percent']:.1f}% CPU
                        </div>
                    </div>""",
                    unsafe_allow_html=True,
                )
                history = data.get("history", [])
                if len(history) > 1:
                    df = pd.DataFrame(history)
                    st.line_chart(df.set_index("timestamp")["memory_mb"], height=100)
            else:
                st.warning(f"{service}: no data yet")

st.divider()

# --- Agent liveness (Gap: "no tamper resistance") ---
st.subheader("Defense Agent Status")
if agents_err or not agents:
    st.info("No agent heartbeats yet — agents report in shortly after they start.")
else:
    acols = st.columns(len(agents)) if agents else []
    for col, (agent, info) in zip(acols, agents.items()):
        with col:
            is_up = info.get("status") == "online"
            badge_class = "status-online" if is_up else "status-quarantined"
            icon = "🟢" if is_up else "🔴"
            seen_ago = info.get("last_seen_seconds_ago", 0)
            st.markdown(
                f"""<div style="display:flex; justify-content:space-between; align-items:center;
                     padding:12px; background:#161B22; border:1px solid #30363D; border-radius:8px;">
                    <div>{icon} <b>{agent}</b></div>
                    <span class="{badge_class}">{'ALIVE' if is_up else 'DOWN'}</span>
                </div>
                <div style="color:#8B949E; font-size:0.78rem; margin-top:4px;">last heartbeat {seen_ago:.0f}s ago</div>""",
                unsafe_allow_html=True,
            )
    st.caption("A defense agent that's killed can't report its own death — a missed heartbeat "
               "is what surfaces that here, and raises a critical alert in the feed below.")

st.divider()

# --- PCI DSS control mapping (Gap: "toy compliance score") ---
st.subheader("PCI DSS v4.0 Control Mapping")
if pci_controls_err or not pci_controls:
    st.info("Could not load control mapping.")
else:
    status_style = {
        "enforced": ("🟢", "#4ADE80"),
        "partial": ("🟡", "#FBBF24"),
        "not_covered": ("🔴", "#F87171"),
        "out_of_scope": ("⚪", "#8B949E"),
    }
    for control in pci_controls.get("controls", []):
        icon, color = status_style.get(control["status"], ("⚪", "#8B949E"))
        capability = control.get("capability") or "Not addressed by POSGuard"
        st.markdown(
            f"""<div style="display:flex; gap:12px; padding:10px 12px; background:#161B22;
                 border-left:3px solid {color}; border-radius:4px; margin-bottom:6px;">
                <div style="flex:none; color:{color}; font-weight:700;">{icon} Req {control['requirement']}</div>
                <div>
                    <div style="color:#C9D1D9;">{control['title']}</div>
                    <div style="color:#8B949E; font-size:0.8rem; margin-top:2px;">{capability}</div>
                </div>
            </div>""",
            unsafe_allow_html=True,
        )

st.divider()

left, right = st.columns([1, 1])

with left:
    st.subheader("Terminal Status")
    if not terminals:
        st.info("No terminals registered.")
    for t in terminals:
        badge_map = {
            "Online": ("status-online", "🟢"),
            "Throttled": ("status-throttled", "🟡"),
            "Quarantined": ("status-quarantined", "🔴"),
        }
        badge_class, icon = badge_map.get(t["status"], ("status-online", "🟢"))
        offense = t.get("offense_count", 0)
        blocked = t.get("blocked_packets", 0)
        offense_html = f'<span class="offense-badge">offense #{offense}</span>' if offense else ""
        blocked_html = f'<span class="offense-badge">{blocked} pkts blocked</span>' if blocked else ""
        st.markdown(
            f"""<div style="display:flex; justify-content:space-between; align-items:center;
                 padding:12px; background:#161B22; border:1px solid #30363D; border-radius:8px; margin-bottom:8px;">
                <div>{icon} <b>{t['name']}</b> &nbsp; <code>{t['ip']}</code>{offense_html}{blocked_html}</div>
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
    running_warning = 0
    all_events_chrono = list(reversed(events["events"]))
    for e in all_events_chrono:
        if e.get("severity") == "critical":
            running_critical += 1
        elif e.get("severity") == "warning":
            running_warning += 1
        score = max(0, 100 - 25 * running_critical - 5 * running_warning)
        rows.append({"time": e.get("timestamp", "")[:19], "pci_score": score})
    if rows:
        df = pd.DataFrame(rows)
        st.line_chart(df.set_index("time")["pci_score"], height=250)
else:
    st.caption("No event history yet to plot.")

if auto_refresh:
    time.sleep(REFRESH_SECONDS)
    st.rerun()
