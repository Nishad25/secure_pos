#!/usr/bin/env python3
"""
POSGuard Compliance Dashboard API (Gap #15)
Collects alerts and telemetry from the RAM monitor / SDN controller / POS
health agent / instrumented app services, and exposes:
  - a live PCI-style compliance score
  - real POS-system health (Gap #16: real monitoring, not just simulated)
  - terminal status including graduated response state (Gap #4)
  - a live event feed

Run with:  python3 dashboard/app.py
Docs at:   http://localhost:9000/docs
"""
import time
from datetime import datetime, timezone

import requests
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

DASHBOARD_PORT = 9000
HEARTBEAT_STALE_AFTER_SECONDS = 15  # an agent that misses this long is treated as down
RYU_STATUS_URL = "http://localhost:8080/posguard/status"
RYU_TERMINALS_URL = "http://localhost:8080/posguard/terminals"

# Only used before the SDN controller has seen any traffic yet — once
# microseg.py auto-discovers real terminals, that list takes over. See
# sdn_apps/microseg.py's is_pos_terminal() for the classification rule.
FALLBACK_TERMINALS = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]


def _friendly_name(ip_address):
    return f"pos{ip_address.split('.')[-1]}"

SCORE_PENALTY_PER_CRITICAL = 25
SCORE_PENALTY_PER_WARNING = 5
MAX_EVENTS_RETURNED = 50
MAX_HEALTH_HISTORY = 120          # ~10 min of history at a 5s ping interval
HEALTH_STALE_AFTER_SECONDS = 15   # no ping in this long => service treated as down

app = FastAPI(title="POSGuard Compliance Dashboard")
events = []                 # in-memory event log, oldest first
health = {}                 # {service_name: {"latest": {...}, "history": [...]}}
agent_heartbeats = {}       # {agent_name: last_seen_unix_timestamp} — tamper/crash detection
_agent_down_alerted = set()  # avoid re-alerting every poll while an agent stays down

# --- PCI DSS v4.0 control mapping (Gap: "toy compliance score") ---
# The live event-penalty score below answers "how bad is it right now?" —
# this answers the different, PCI-relevant question: "which of the 12
# actual PCI DSS requirements does this system provide evidence for?"
# Both are reported; neither alone is the whole picture.
PCI_DSS_CONTROLS = [
    {"requirement": "1", "title": "Install and maintain network security controls",
     "status": "enforced", "capability": "Gap #1 micro-segmentation + Gap #4 reactive firewall/quarantine"},
    {"requirement": "2", "title": "Apply secure configurations to all system components",
     "status": "not_covered", "capability": None},
    {"requirement": "3", "title": "Protect stored account data",
     "status": "not_covered", "capability": "Gap #2's memory scan detects exposure but does not encrypt or tokenize data"},
    {"requirement": "4", "title": "Protect cardholder data with strong cryptography during transmission",
     "status": "not_covered", "capability": None},
    {"requirement": "5", "title": "Protect all systems and networks from malicious software",
     "status": "partial", "capability": "Gap #2 RAM-scrape detection — a specific technique, not general-purpose anti-malware"},
    {"requirement": "6", "title": "Develop and maintain secure systems and software",
     "status": "not_covered", "capability": None},
    {"requirement": "7", "title": "Restrict access to system components by business need to know",
     "status": "not_covered", "capability": "Known gap — the SDN and compliance REST APIs currently have no authentication"},
    {"requirement": "8", "title": "Identify users and authenticate access to system components",
     "status": "partial", "capability": "The POS app authenticates staff logins; POSGuard's own internal APIs do not"},
    {"requirement": "9", "title": "Restrict physical access to cardholder data",
     "status": "out_of_scope", "capability": "Physical security control, outside a software framework's scope"},
    {"requirement": "10", "title": "Log and monitor all access to system components and cardholder data",
     "status": "enforced", "capability": "Gap #15/#16 — live event feed, compliance API, real POS health monitoring"},
    {"requirement": "11", "title": "Test security of systems and networks regularly",
     "status": "partial", "capability": "attacks/simulate_attacks.py gives repeatable automated testing, not a full pen-test programme"},
    {"requirement": "12", "title": "Support information security with organizational policies and programs",
     "status": "out_of_scope", "capability": "Organizational/governance control, outside a software framework's scope"},
]


class AlertIn(BaseModel):
    message: str
    severity: str = "info"   # info | warning | critical
    source: str = "unknown"


class HealthIn(BaseModel):
    service: str             # e.g. "pos-backend", "payment-gateway"
    pid: int
    cpu_percent: float
    memory_mb: float
    uptime_seconds: float


class HeartbeatIn(BaseModel):
    agent: str                # e.g. "ram_monitor", "pos_health_monitor"


@app.post("/api/alert")
def post_alert(alert: AlertIn):
    event = {
        "message": alert.message,
        "severity": alert.severity,
        "source": alert.source,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    events.append(event)
    return {"success": True, "stored": event}


@app.get("/api/events")
def get_events():
    return {"events": list(reversed(events[-MAX_EVENTS_RETURNED:]))}


@app.post("/api/health")
def post_health(ping: HealthIn):
    now = datetime.now(timezone.utc)
    entry = health.setdefault(ping.service, {"latest": None, "history": []})

    restarted = (
        entry["latest"] is not None
        and entry["latest"]["pid"] != ping.pid
    )

    snapshot = {
        "pid": ping.pid,
        "cpu_percent": ping.cpu_percent,
        "memory_mb": ping.memory_mb,
        "uptime_seconds": ping.uptime_seconds,
        "timestamp": now.isoformat(),
    }
    entry["latest"] = snapshot
    entry["history"].append(snapshot)
    entry["history"] = entry["history"][-MAX_HEALTH_HISTORY:]

    if restarted:
        events.append({
            "message": f"{ping.service} restarted (new PID {ping.pid})",
            "severity": "warning",
            "source": "pos_health_monitor",
            "timestamp": now.isoformat(),
        })

    return {"success": True}


@app.get("/api/health")
def get_health():
    now = datetime.now(timezone.utc)
    out = {}
    for service, entry in health.items():
        latest = entry["latest"]
        age = (now - datetime.fromisoformat(latest["timestamp"])).total_seconds() if latest else None
        out[service] = {
            "latest": latest,
            "history": entry["history"],
            "status": "online" if age is not None and age <= HEALTH_STALE_AFTER_SECONDS else "unresponsive",
        }
    return out


@app.post("/api/heartbeat")
def post_heartbeat(hb: HeartbeatIn):
    now = time.time()
    was_down = hb.agent in _agent_down_alerted
    agent_heartbeats[hb.agent] = now
    if was_down:
        _agent_down_alerted.discard(hb.agent)
        events.append({
            "message": f"{hb.agent} is back online",
            "severity": "info",
            "source": "heartbeat_monitor",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
    return {"success": True}


def _check_agent_liveness():
    """A defense agent that's been killed can't report its own death — this
    is the other half of the loop: the dashboard notices the silence."""
    now = time.time()
    for agent, last_seen in agent_heartbeats.items():
        if now - last_seen > HEARTBEAT_STALE_AFTER_SECONDS and agent not in _agent_down_alerted:
            _agent_down_alerted.add(agent)
            events.append({
                "message": f"{agent} has stopped sending heartbeats — its defenses may be "
                           f"disabled (killed, crashed, or a tamper attempt)",
                "severity": "critical",
                "source": "heartbeat_monitor",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            })


@app.get("/api/agents")
def get_agents():
    _check_agent_liveness()
    now = time.time()
    return {
        agent: {
            "last_seen_seconds_ago": round(now - last_seen, 1),
            "status": "online" if now - last_seen <= HEARTBEAT_STALE_AFTER_SECONDS else "down",
        }
        for agent, last_seen in agent_heartbeats.items()
    }


def _pci_control_summary():
    counts = {"enforced": 0, "partial": 0, "not_covered": 0, "out_of_scope": 0}
    for control in PCI_DSS_CONTROLS:
        counts[control["status"]] += 1
    applicable = len(PCI_DSS_CONTROLS) - counts["out_of_scope"]
    covered = counts["enforced"] + 0.5 * counts["partial"]
    coverage_percent = round(100 * covered / applicable) if applicable else 0
    return counts, coverage_percent


@app.get("/api/pci-controls")
def get_pci_controls():
    counts, coverage_percent = _pci_control_summary()
    return {"controls": PCI_DSS_CONTROLS, "summary": counts, "coverage_percent": coverage_percent}


@app.get("/api/compliance")
def get_compliance():
    _check_agent_liveness()
    critical_alerts = sum(1 for e in events if e["severity"] == "critical")
    warning_alerts = sum(1 for e in events if e["severity"] == "warning")
    pci_score = max(0, 100
                     - SCORE_PENALTY_PER_CRITICAL * critical_alerts
                     - SCORE_PENALTY_PER_WARNING * warning_alerts)
    _, pci_control_coverage_percent = _pci_control_summary()

    quarantined_ips = set()
    throttled_ips = set()
    offense_counts = {}
    blocked_traffic = {}
    discovered_terminals = []
    try:
        resp = requests.get(RYU_STATUS_URL, timeout=2)
        status = resp.json()
        quarantined_ips = set(status.get("quarantined_hosts", []))
        throttled_ips = set(status.get("throttled_hosts", []))
        offense_counts = status.get("offense_counts", {})
        blocked_traffic = status.get("blocked_traffic", {})
    except requests.exceptions.RequestException:
        pass  # SDN controller not reachable — terminals just show as Online below

    try:
        resp = requests.get(RYU_TERMINALS_URL, timeout=2)
        discovered_terminals = resp.json().get("terminals", [])
    except requests.exceptions.RequestException:
        pass  # microseg.py not reachable yet — fall back below

    all_ips = discovered_terminals or FALLBACK_TERMINALS
    all_ips = sorted(set(all_ips) | quarantined_ips | throttled_ips,
                      key=lambda ip: int(ip.split(".")[-1]))

    terminals = []
    for ip in all_ips:
        if ip in quarantined_ips:
            status_label = "Quarantined"
        elif ip in throttled_ips:
            status_label = "Throttled"
        else:
            status_label = "Online"
        terminals.append({
            "name": _friendly_name(ip),
            "ip": ip,
            "status": status_label,
            "offense_count": offense_counts.get(ip, 0),
            "blocked_packets": blocked_traffic.get(ip, {}).get("packet_count", 0),
        })

    return {
        "pci_score": pci_score,
        "pci_control_coverage_percent": pci_control_coverage_percent,
        "critical_alerts": critical_alerts,
        "warning_alerts": warning_alerts,
        "total_events": len(events),
        "terminals": terminals,
    }


@app.get("/")
def root():
    return {"message": "POSGuard Compliance Dashboard API — see /docs"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=DASHBOARD_PORT)
