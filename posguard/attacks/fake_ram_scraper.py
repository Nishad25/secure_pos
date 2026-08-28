#!/usr/bin/env python3
"""
Fake RAM-scraper for testing ram_monitor.py (Gap #2).
Finds the real POS backend process and opens its /proc/{pid}/mem file —
the exact technique real RAM-scraping malware uses. For detection testing only.
"""
import sys
import time
import psutil


def find_pos_process(port=8000):
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_LISTEN and conn.laddr.port == port and conn.pid:
            return conn.pid
    return None


def main():
    pos_pid = find_pos_process()
    if pos_pid is None:
        print("fake_ram_scraper: could not find POS backend process, exiting")
        sys.exit(1)

    mem_path = f"/proc/{pos_pid}/mem"
    print(f"fake_ram_scraper: attempting to open {mem_path} (PID {pos_pid})")
    try:
        f = open(mem_path, 'rb')
    except (PermissionError, OSError) as e:
        print(f"fake_ram_scraper: could not open memory file ({e})")
        sys.exit(1)

    print("fake_ram_scraper: memory file opened, holding for detection window...")
    try:
        time.sleep(15)  # give ram_monitor.py's scan loop time to catch it
    finally:
        f.close()
    print("fake_ram_scraper: finished (not detected/killed in time)")


if __name__ == '__main__':
    main()