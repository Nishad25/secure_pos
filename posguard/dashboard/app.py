#!/usr/bin/env python3
"""
POSGuard Compliance Dashboard API (Gap #15)
Collects alerts from the RAM monitor / SDN controller and exposes a
live PCI-style compliance score, terminal status, and event feed.

Run with:  python3 dashboard/app.py
Docs at:   http://localhost:9000/docs
"""
from datetime import datetime, timezone

import requests
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel

DASHBOARD_PORT = 9000
RYU_STATUS_URL = "http://localhost:8080/posguard/status"

POS_TERMINALS = {
    "10.0.0.1": "pos1",
    "10.0.0.2": "pos2",
    "10.0.0.3": "pos3",
}

SCORE_PENALTY_PER_CRITICAL = 25
MAX_EVENTS_RETURNED = 50

app = FastAPI(title="POSGuard Compliance Dashboard")
events = []  # in-memory event log, oldest first


class AlertIn(BaseModel):
    message: str
    severity: str = "info"   # info | warning | critical
    source: str = "unknown"


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


@app.get("/api/compliance")
def get_compliance():
    critical_alerts = sum(1 for e in events if e["severity"] == "critical")
    pci_score = max(0, 100 - SCORE_PENALTY_PER_CRITICAL * critical_alerts)

    quarantined_ips = set()
    try:
        resp = requests.get(RYU_STATUS_URL, timeout=2)
        quarantined_ips = set(resp.json().get("quarantined_hosts", []))
    except requests.exceptions.RequestException:
        pass  # SDN controller not reachable — terminals just show as Online below

    terminals = [
        {"name": name, "ip": ip, "status": "Quarantined" if ip in quarantined_ips else "Online"}
        for ip, name in POS_TERMINALS.items()
    ]

    return {
        "pci_score": pci_score,
        "critical_alerts": critical_alerts,
        "total_events": len(events),
        "terminals": terminals,
    }


@app.get("/")
def root():
    return {"message": "POSGuard Compliance Dashboard API — see /docs"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=DASHBOARD_PORT)