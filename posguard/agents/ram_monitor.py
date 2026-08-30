#!/usr/bin/env python3
"""
POSGuard RAM Scrape Monitor (Gap #2, extended)
Two independent detection techniques, both grounded in how real
RAM-scraping malware actually operates:

  1. Behavioral: catches any process that opens a handle to
     /proc/{target_pid}/mem — the mechanism the attack depends on,
     regardless of what it does with the memory once it's read it.
  2. Content-based: periodically scans the POS backend's and the
     payment gateway's OWN readable memory for Luhn-valid card-number
     patterns — a direct PCI-relevant signal of how much cleartext
     card data is currently exposed in memory, the same class of check
     real RAM-scraper YARA/detection rules use. Matches are always
     masked (first 6 / last 4 only) before they're logged or alerted —
     the scanner never stores or transmits a full PAN.

On a confirmed handle-based detection, this agent kills the reader and
quarantines the affected terminal with force=true (Gap #4's graduated
response deliberately requires a human override for critical infra —
this is the one case where an agent overrides that: a confirmed live
memory read from the payment gateway is worse left running than briefly
taken offline). A content-based finding or the coarser RAM-usage
heuristic is lower-confidence, so it only raises an alert — it never
triggers a network action on its own.
"""

import os
import re
import sys
import time
import psutil
import requests

SCAN_INTERVAL = 2
MEMORY_SCAN_EVERY_N_CYCLES = 15   # content scan is more expensive — run it less often
SUSPICIOUS_RAM_MB = 50

# Gap: "single-host testbed" — these used to be hardcoded to localhost,
# which meant this agent could only ever run on the same box as the
# controller and dashboard. Override via environment variables to run it
# on the actual POS backend server while the controller and dashboard
# live elsewhere:
#   POSGUARD_RYU_HOST=http://10.0.0.50:8080 POSGUARD_DASHBOARD_HOST=http://10.0.0.60:9000 python3 ram_monitor.py
RYU_HOST = os.environ.get("POSGUARD_RYU_HOST", "http://localhost:8080")
DASHBOARD_HOST = os.environ.get("POSGUARD_DASHBOARD_HOST", "http://localhost:9000")
RYU_QUARANTINE_URL = RYU_HOST + "/posguard/quarantine/{ip}"
RYU_THROTTLE_URL = RYU_HOST + "/posguard/throttle/{ip}"
DASHBOARD_ALERT_URL = DASHBOARD_HOST + "/api/alert"
DASHBOARD_HEARTBEAT_URL = DASHBOARD_HOST + "/api/heartbeat"
HEARTBEAT_INTERVAL_CYCLES = 5   # every 5 scan cycles (~10s at SCAN_INTERVAL=2)

# Real processes this agent protects — both the POS backend and the
# payment gateway are equally valid RAM-scraping targets in the real
# world. quarantine_ip is the symbolic Mininet terminal this real host
# process is treated as standing in for, matching the convention already
# used by pos_network.py / simulate_attacks.py.
WATCHED_TARGETS = {
    "pos-backend": {"port": 8000, "quarantine_ip": "10.0.0.1"},
    "payment-gateway": {"port": 5100, "quarantine_ip": "10.0.0.100"},
}

KNOWN_SAFE_PROCESS_NAMES = {
    'node', 'npm', 'mongod', 'python3', 'python3.8', 'python3.10',
    'systemd', 'bash', 'sshd', 'ryu-manager', 'sudo',
}

CARD_PATTERN = re.compile(r'(?:\d[ -]?){13,19}')
MAX_MEMORY_SCAN_BYTES = 5_000_000   # per process, per scan cycle — keep this fast
MAX_REGION_SIZE = 20_000_000        # skip huge mappings — not where card data lives

already_flagged = set()
already_alerted_patterns = {}  # {service_name: set(masked_pan)} — alert once per unique finding, not every scan
_cycle_count = 0


def find_process_by_port(port):
    """Find whoever is listening on this port — works for any real service."""
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


def find_suspicious_processes():
    """Unknown process using unusually large RAM — only reports NEW ones.
    Host-wide heuristic, not tied to a specific terminal, so it only ever
    raises a visibility alert — never a network action on its own."""
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


def luhn_valid(digits):
    total = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def mask_pan(digits):
    return f"{digits[:6]}...{digits[-4:]}"


def scan_process_memory_for_card_data(pid):
    """Read this process's own readable memory regions looking for
    Luhn-valid card-number patterns. Requires permission to read
    /proc/{pid}/mem (root, or same user) — silently returns no findings
    if that's not available rather than erroring the whole agent out."""
    findings = []
    bytes_read = 0
    try:
        with open(f"/proc/{pid}/maps", 'r') as maps_file:
            regions = []
            for line in maps_file:
                parts = line.split()
                if len(parts) < 2 or 'r' not in parts[1]:
                    continue
                start_str, end_str = parts[0].split('-')
                start, end = int(start_str, 16), int(end_str, 16)
                if end - start <= MAX_REGION_SIZE:
                    regions.append((start, end))

        with open(f"/proc/{pid}/mem", 'rb', 0) as mem_file:
            for start, end in regions:
                if bytes_read >= MAX_MEMORY_SCAN_BYTES:
                    break
                size = min(end - start, MAX_MEMORY_SCAN_BYTES - bytes_read)
                try:
                    mem_file.seek(start)
                    chunk = mem_file.read(size)
                except (OSError, ValueError):
                    continue
                bytes_read += size

                text = chunk.decode('latin-1', errors='ignore')
                for match in CARD_PATTERN.finditer(text):
                    candidate = re.sub(r'[ -]', '', match.group())
                    if 13 <= len(candidate) <= 19 and luhn_valid(candidate):
                        findings.append(mask_pan(candidate))
    except (FileNotFoundError, PermissionError, ProcessLookupError, psutil.NoSuchProcess):
        pass
    return findings


def quarantine_host(ip_address, force=False):
    try:
        url = RYU_QUARANTINE_URL.format(ip=ip_address)
        resp = requests.post(url, params={'force': 'true'} if force else {}, timeout=3)
        print(f"  -> SDN quarantine call: {resp.status_code} {resp.json()}")
    except requests.exceptions.RequestException as e:
        print(f"  -> WARNING: could not reach SDN controller ({e})")


def send_alert(message, severity="critical", source="ram_monitor"):
    try:
        requests.post(DASHBOARD_ALERT_URL, json={
            "message": message, "severity": severity, "source": source
        }, timeout=2)
    except requests.exceptions.RequestException:
        pass  # dashboard may not be running — don't crash over it


def send_heartbeat():
    """Gap: 'no tamper resistance' — this agent can't report its own death
    if it's killed, but a missed heartbeat is exactly how the dashboard
    notices that RAM-scrape detection has gone dark and raises a critical
    alert about it (see dashboard/app.py's _check_agent_liveness)."""
    try:
        requests.post(DASHBOARD_HEARTBEAT_URL, json={"agent": "ram_monitor"}, timeout=2)
    except requests.exceptions.RequestException:
        pass


def kill_process(pid):
    try:
        psutil.Process(pid).kill()
        print(f"  -> Killed suspicious process PID {pid}")
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print(f"  -> Could not kill PID {pid}: {e}")


def main():
    global _cycle_count
    print("RAM Scrape Monitor started — watching:", ", ".join(WATCHED_TARGETS))

    known_pids = {name: None for name in WATCHED_TARGETS}
    for name, target in WATCHED_TARGETS.items():
        pid = find_process_by_port(target["port"])
        known_pids[name] = pid
        if pid is None:
            print(f"WARNING: could not find {name} (port {target['port']}) — is it running?")
        else:
            print(f"Monitoring {name} process PID {pid}")

    while True:
        _cycle_count += 1

        if _cycle_count % HEARTBEAT_INTERVAL_CYCLES == 0:
            send_heartbeat()

        for name, target in WATCHED_TARGETS.items():
            pid = known_pids[name]
            if pid is None or not psutil.pid_exists(pid):
                pid = find_process_by_port(target["port"])
                known_pids[name] = pid
                if pid:
                    print(f"{name}: now tracking PID {pid}")
                continue

            # --- technique 1: behavioral, high confidence ---
            for reader_pid in get_processes_reading_memory_of(pid):
                try:
                    reader_name = psutil.Process(reader_pid).name()
                except psutil.NoSuchProcess:
                    continue
                print(f"ALERT: PID {reader_pid} ({reader_name}) is reading {name}'s memory!")
                send_alert(f"RAM scraping detected: PID {reader_pid} reading {name} memory",
                           severity="critical")
                kill_process(reader_pid)
                # confirmed live memory read — worth a forced quarantine even on critical infra
                quarantine_host(target["quarantine_ip"], force=True)

            # --- technique 2: content-based, run less often (it's more expensive) ---
            if _cycle_count % MEMORY_SCAN_EVERY_N_CYCLES == 0:
                findings = scan_process_memory_for_card_data(pid)
                if findings:
                    print(f"EXPOSURE: {name} memory holds {len(findings)} card-like pattern(s): "
                          f"{findings[:3]}{'...' if len(findings) > 3 else ''}")
                    # The same resident data gets found on every scan as long as it
                    # stays in memory — alert once per unique masked pattern per
                    # service, not every ~30s for the same persistent finding.
                    seen = already_alerted_patterns.setdefault(name, set())
                    new_findings = [f for f in findings if f not in seen]
                    seen.update(findings)
                    if new_findings:
                        send_alert(
                            f"{len(new_findings)} new Luhn-valid card-number pattern(s) found in "
                            f"{name} process memory — cleartext PAN exposure risk",
                            severity="warning", source="ram_monitor_content_scan"
                        )

        for pid, name, mem_mb in find_suspicious_processes():
            print(f"Suspicious process: PID {pid} ({name}) using {mem_mb:.1f} MB")
            send_alert(f"Unusual process {name} (PID {pid}) using {mem_mb:.1f} MB RAM",
                       severity="warning", source="ram_monitor_heuristic")

        time.sleep(SCAN_INTERVAL)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nRAM Scrape Monitor stopped.")
        sys.exit(0)
