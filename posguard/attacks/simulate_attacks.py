#!/usr/bin/env python3
"""
POSGuard Attack Simulator (Phase 8)

PREREQUISITES — start these separately, in their own terminals, first:
  1. ryu-manager sdn_apps/microseg.py sdn_apps/dynamic_fw.py --verbose
  2. cd Restaurant_POS_System/pos-backend && npm run dev
  3. sudo sdn_env/bin/python3 agents/ram_monitor.py   (for Gap #2's closed-loop test)
  4. (optional) the Phase 7 dashboard — if not running, that test is SKIPPED, not failed

Run with: sudo python3 attacks/simulate_attacks.py
(system python, same as pos_network.py — needed for the mininet import)
"""
import os
import time
import requests

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.log import setLogLevel

RYU_API = "http://localhost:8080/posguard"
HERE = os.path.dirname(os.path.abspath(__file__))
FAKE_SCRAPER = os.path.join(HERE, 'fake_ram_scraper.py')
VENV_PYTHON = os.path.join(HERE, '..', 'sdn_env', 'bin', 'python3')

results = []


def record(gap, description, passed, detail=""):
    results.append({'gap': gap, 'test': description, 'passed': passed, 'detail': detail})
    status = "SKIPPED" if passed is None else ("PASS" if passed else "FAIL")
    print(f"[{status}] Gap #{gap}: {description}" + (f" — {detail}" if detail else ""))


def build_topology():
    net = Mininet(controller=RemoteController, switch=OVSSwitch)
    net.addController('c0', ip='127.0.0.1', port=6633)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')

    pos1 = net.addHost('pos1', ip='10.0.0.1/24')
    pos2 = net.addHost('pos2', ip='10.0.0.2/24')
    pos3 = net.addHost('pos3', ip='10.0.0.3/24')
    gateway = net.addHost('gateway', ip='10.0.0.100/24')
    server = net.addHost('server', ip='10.0.0.200/24')

    for h in [pos1, pos2, pos3, gateway, server]:
        net.addLink(h, s1)

    net.start()
    time.sleep(2)  # let switches finish connecting to the controller
    return net


def ping_loss_percent(host, target_ip, count=3):
    out = host.cmd(f'ping -c {count} -W 1 {target_ip}')
    for line in out.splitlines():
        if 'packet loss' in line:
            pct = line.split('%')[0].split(',')[-1].strip()
            try:
                return int(pct)
            except ValueError:
                pass
    return None


def test_gap1_lateral_movement(net):
    pos1, pos2 = net.get('pos1'), net.get('pos2')
    loss = ping_loss_percent(pos1, pos2.IP())
    record(1, "pos1 -> pos2 lateral movement should be blocked", loss == 100,
           f"{loss}% packet loss" if loss is not None else "could not parse ping output")


def test_gap1_allowed_path(net):
    pos1, gateway = net.get('pos1'), net.get('gateway')
    loss = ping_loss_percent(pos1, gateway.IP())
    record(1, "pos1 -> gateway should still work", loss == 0,
           f"{loss}% packet loss" if loss is not None else "could not parse ping output")


def test_gap2_ram_scraper(net):
    pos1 = net.get('pos1')
    print("Launching fake RAM scraper against the POS backend...")
    pos1.cmd(f'{VENV_PYTHON} {FAKE_SCRAPER} > /tmp/fake_scraper.log 2>&1 &')

    time.sleep(6)  # give ram_monitor.py's 2s scan loop a few cycles to catch it

    still_running = 'fake_ram_scraper' in pos1.cmd('ps aux | grep fake_ram_scraper | grep -v grep')
    record(2, "fake RAM scraper should be detected and killed", not still_running,
           "still running — is ram_monitor.py running?" if still_running else "process no longer running")

    try:
        status = requests.get(f"{RYU_API}/status", timeout=3).json()
        quarantined = '10.0.0.1' in status.get('quarantined_hosts', [])
        record(2, "pos1 should be auto-quarantined by the closed loop", quarantined, str(status))
    except requests.exceptions.RequestException as e:
        record(2, "pos1 should be auto-quarantined by the closed loop", False,
               f"could not reach Ryu REST API ({e})")


def test_gap3_manual_quarantine(net):
    pos2, gateway = net.get('pos2'), net.get('gateway')
    try:
        resp = requests.post(f"{RYU_API}/quarantine/10.0.0.2", timeout=3)
        api_ok = resp.status_code == 200
    except requests.exceptions.RequestException as e:
        record(3, "manual quarantine API call", False, f"could not reach Ryu REST API ({e})")
        return

    time.sleep(1)
    loss = ping_loss_percent(pos2, gateway.IP())
    record(3, "pos2 should lose connectivity after manual quarantine", api_ok and loss == 100,
           f"{loss}% packet loss" if loss is not None else "could not parse ping output")


def test_gap15_dashboard_alert():
    try:
        requests.post("http://localhost:9000/api/alert", json={
            "message": "Simulated attack run", "severity": "critical", "source": "simulate_attacks"
        }, timeout=2)
        compliance = requests.get("http://localhost:9000/api/compliance", timeout=2).json()
        score = compliance.get('pci_score')
        record(15, "PCI score should drop after alerts", score is not None and score < 100, f"score={score}")
    except requests.exceptions.RequestException:
        record(15, "PCI score should drop after alerts", None, "dashboard not running yet")


def print_summary():
    print("\n" + "=" * 60)
    print("POSGuard Attack Simulation — Summary")
    print("=" * 60)
    for r in results:
        status = "SKIPPED" if r['passed'] is None else ("PASS" if r['passed'] else "FAIL")
        print(f"  Gap #{r['gap']:<3} [{status:8}] {r['test']}")
    p = sum(1 for r in results if r['passed'] is True)
    f = sum(1 for r in results if r['passed'] is False)
    s = sum(1 for r in results if r['passed'] is None)
    print(f"\n{p} passed, {f} failed, {s} skipped")


def main():
    setLogLevel('info')
    net = build_topology()
    try:
        test_gap1_lateral_movement(net)
        test_gap1_allowed_path(net)
        test_gap2_ram_scraper(net)
        test_gap3_manual_quarantine(net)
        test_gap15_dashboard_alert()
    finally:
        net.stop()
        print_summary()


if __name__ == '__main__':
    main()