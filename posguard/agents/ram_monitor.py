#!/usr/bin/env python3
"""
POSGuard RAM Scrape Monitor (Gap #2)
Detects a process reading the POS backend's memory (the core technique
behind real-world RAM-scraping malware), then:
  1. kills the suspicious process
  2. tells the SDN controller to quarantine this terminal (closed-loop defense)
  3. sends an alert to the compliance dashboard (safe to run before Phase 7 exists)
"""

import sys
import time
import psutil
import requests

SCAN_INTERVAL = 2
SUSPICIOUS_RAM_MB = 50
POS_BACKEND_PORT = 8000
RYU_QUARANTINE_URL = "http://localhost:8080/posguard/quarantine/{ip}"
DASHBOARD_ALERT_URL = "http://localhost:9000/api/alert"
QUARANTINE_TARGET_IP = "10.0.0.1"  # the POS terminal this agent protects

KNOWN_SAFE_PROCESS_NAMES = {
    'node', 'npm', 'mongod', 'python3', 'python3.8', 'python3.10',
    'systemd', 'bash', 'sshd', 'ryu-manager', 'sudo',
}


def find_pos_process(port=POS_BACKEND_PORT):
    """Find the POS backend process: whoever is listening on its port."""
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port and conn.pid:
            return conn.pid
    return None


def get_processes_reading_memory_of(target_pid):
    """PIDs that currently have /proc/{target_pid}/mem open — the actual
    technique RAM-scraping malware relies on to pull card data out of a
    running process's memory."""
    readers = []
    mem_path = f"/proc/{target_pid}/mem"
    for proc in psutil.process_iter(['pid']):
        if proc.pid == target_pid:
            continue
        try:
            for f in proc.open_files():
                if f.path == mem_path:
                    readers.append(proc.pid)
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return readers


already_flagged = set()  # add this near the top, alongside SCAN_INTERVAL etc.


def find_suspicious_processes():
    """Unknown process using unusually large RAM — only reports NEW ones."""
    suspicious = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        try:
            name = (proc.info['name'] or '').lower()
            mem_mb = proc.info['memory_info'].rss / (1024 * 1024)
            if (name not in KNOWN_SAFE_PROCESS_NAMES
                    and mem_mb > SUSPICIOUS_RAM_MB
                    and proc.pid not in already_flagged):
                suspicious.append((proc.pid, name, mem_mb))
                already_flagged.add(proc.pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return suspicious


def quarantine_host(ip_address):
    try:
        resp = requests.post(RYU_QUARANTINE_URL.format(ip=ip_address), timeout=3)
        print(f"  -> SDN quarantine call: {resp.status_code} {resp.json()}")
    except requests.exceptions.RequestException as e:
        print(f"  -> WARNING: could not reach SDN controller ({e})")


def send_alert(message, severity="critical"):
    try:
        requests.post(DASHBOARD_ALERT_URL, json={
            "message": message, "severity": severity, "source": "ram_monitor"
        }, timeout=2)
    except requests.exceptions.RequestException:
        pass  # dashboard (Phase 7) may not exist yet — don't crash over it


def kill_process(pid):
    try:
        psutil.Process(pid).kill()
        print(f"  -> Killed suspicious process PID {pid}")
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print(f"  -> Could not kill PID {pid}: {e}")


def main():
    print("RAM Scrape Monitor started")

    pos_pid = find_pos_process()
    if pos_pid is None:
        print("WARNING: could not find the POS backend process (port 8000) — is it running?")
    else:
        print(f"Monitoring POS backend process PID {pos_pid}")

    while True:
        if pos_pid is not None:
            for reader_pid in get_processes_reading_memory_of(pos_pid):
                try:
                    name = psutil.Process(reader_pid).name()
                except psutil.NoSuchProcess:
                    continue
                print(f"ALERT: PID {reader_pid} ({name}) is reading POS process memory!")
                send_alert(f"RAM scraping detected: PID {reader_pid} reading POS memory")
                kill_process(reader_pid)
                quarantine_host(QUARANTINE_TARGET_IP)

        for pid, name, mem_mb in find_suspicious_processes():
            print(f"Suspicious process: PID {pid} ({name}) using {mem_mb:.1f} MB")

        time.sleep(SCAN_INTERVAL)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nRAM Scrape Monitor stopped.")
        sys.exit(0)