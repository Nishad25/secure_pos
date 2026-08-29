#!/usr/bin/env python3
"""
POSGuard SDN environment preflight check.

This doesn't fix the underlying fragility of the Ryu/eventlet/setuptools
version chain — it turns the tribal knowledge from debugging that chain
once into an automated check, so a broken environment is caught here, in
a few seconds, instead of live during a demo.

Run with the sdn_env's own Python, before starting ryu-manager:
    sdn_env/bin/python3 scripts/verify_sdn_env.py
"""
import sys
from importlib import metadata

REQUIRED_PYTHON = (3, 8)

# These exact pins are load-bearing — see requirements-sdn.txt for why.
REQUIRED_PACKAGES = {
    "setuptools": "57.5.0",
    "eventlet": "0.30.2",
}

RECOMMENDED_PACKAGES = ["ryu", "webob", "requests", "psutil"]


def check_python_version():
    major, minor = sys.version_info[:2]
    if (major, minor) != REQUIRED_PYTHON:
        print(f"[FAIL] Python {major}.{minor} — this project needs exactly "
              f"Python {REQUIRED_PYTHON[0]}.{REQUIRED_PYTHON[1]} "
              f"(newer versions break eventlet's socket.timeout handling)")
        return False
    print(f"[PASS] Python {major}.{minor}")
    return True


def check_pinned_packages():
    ok = True
    for package, required_version in REQUIRED_PACKAGES.items():
        try:
            installed = metadata.version(package)
        except metadata.PackageNotFoundError:
            print(f"[FAIL] {package} is not installed (need exactly {required_version})")
            ok = False
            continue
        if installed != required_version:
            print(f"[FAIL] {package} {installed} installed — need exactly {required_version} "
                  f"(this pin came from a real compatibility break, see requirements-sdn.txt)")
            ok = False
        else:
            print(f"[PASS] {package} {installed}")
    return ok


def check_recommended_packages():
    for package in RECOMMENDED_PACKAGES:
        try:
            installed = metadata.version(package)
            print(f"[INFO] {package} {installed} installed")
        except metadata.PackageNotFoundError:
            print(f"[WARN] {package} not installed")


def main():
    print("POSGuard SDN environment check")
    print("=" * 40)
    results = [check_python_version(), check_pinned_packages()]
    check_recommended_packages()
    print("=" * 40)
    if all(results):
        print("Environment looks correct — safe to start ryu-manager.")
        sys.exit(0)
    print("Environment has issues — fix these BEFORE a live demo, not during one.")
    sys.exit(1)


if __name__ == "__main__":
    main()
