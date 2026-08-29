#!/usr/bin/env python3
"""
POSGuard POS Health Monitor (Gap #16: real system monitoring)
Watches the REAL POS backend and REAL payment-gateway processes on this
host — not the simulated Mininet terminals — and reports their live
health (CPU, memory, uptime) to the compliance dashboard. Also detects a
service dying and restarting, which the dashboard turns into an alert.

This does not require root and does not touch the sdn_env venv — it only
needs psutil + requests, so it can run in any plain Python 3 environment.

Run with: python3 agents/pos_health_monitor.py
"""

import os
import sys
import time

import psutil
import requests

SCAN_INTERVAL = 5

# Gap: "single-host testbed" — override to run this agent on the actual
# POS backend server while the dashboard lives on a separate host:
#   POSGUARD_DASHBOARD_HOST=http://10.0.0.60:9000 python3 pos_health_monitor.py
DASHBOARD_HOST = os.environ.get("POSGUARD_DASHBOARD_HOST", "http://localhost:9000")
DASHBOARD_HEALTH_URL = DASHBOARD_HOST + "/api/health"
DASHBOARD_HEARTBEAT_URL = DASHBOARD_HOST + "/api/heartbeat"
HEARTBEAT_EVERY_N_CYCLES = 2   # every 2 scan cycles (~10s at SCAN_INTERVAL=5)

WATCHED_SERVICES = {
    "pos-backend": 8000,
    "payment-gateway": 5100,
}


def find_process_by_port(port):
    """Return the PID of whoever is listening on this port, or None."""
    for conn in psutil.net_connections(kind="inet"):
        if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port and conn.pid:
            return conn.pid
    return None


def report_health(service, pid):
    try:
        proc = psutil.Process(pid)
        payload = {
            "service": service,
            "pid": pid,
            "cpu_percent": proc.cpu_percent(interval=0.2),
            "memory_mb": proc.memory_info().rss / (1024 * 1024),
            "uptime_seconds": time.time() - proc.create_time(),
        }
        requests.post(DASHBOARD_HEALTH_URL, json=payload, timeout=2)
        return True
    except psutil.NoSuchProcess:
        return False
    except requests.exceptions.RequestException:
        return True  # process is fine, dashboard just wasn't reachable this cycle


def send_heartbeat():
    """Gap: 'no tamper resistance' — a missed heartbeat is how the
    dashboard notices this agent (and therefore real health visibility)
    has gone dark, rather than the panel just quietly going stale."""
    try:
        requests.post(DASHBOARD_HEARTBEAT_URL, json={"agent": "pos_health_monitor"}, timeout=2)
    except requests.exceptions.RequestException:
        pass


def main():
    print("POS Health Monitor started — watching:", ", ".join(WATCHED_SERVICES))
    known_pids = {service: None for service in WATCHED_SERVICES}
    cycle_count = 0

    while True:
        cycle_count += 1
        if cycle_count % HEARTBEAT_EVERY_N_CYCLES == 0:
            send_heartbeat()

        for service, port in WATCHED_SERVICES.items():
            pid = known_pids[service]

            if pid is None or not psutil.pid_exists(pid):
                pid = find_process_by_port(port)
                if pid is None:
                    print(f"  {service}: not running (nothing listening on port {port})")
                    known_pids[service] = None
                    continue
                known_pids[service] = pid
                print(f"  {service}: now tracking PID {pid} (port {port})")

            if not report_health(service, pid):
                known_pids[service] = None  # process died mid-cycle, re-discover next loop

        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nPOS Health Monitor stopped.")
        sys.exit(0)
