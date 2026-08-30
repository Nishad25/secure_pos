# POSGuard

A hybrid SDN and Python security framework built around a real, working restaurant point-of-sale application and payment gateway. POSGuard closes six security gaps typical of small and medium-sized retail POS deployments:

| Gap | What it closes |
|---|---|
| **#1** | Flat networks — SDN micro-segmentation blocks terminal-to-terminal traffic while still allowing terminal → gateway/server. Terminals are auto-discovered by IP range, not hardcoded. |
| **#2** | No memory monitoring — a host agent watches both the POS backend and the payment gateway for a process reading their memory, plus a Luhn-validated scan for card data already exposed in memory. |
| **#3** | Static firewalls — a reactive REST API lets a detection event rewrite firewall rules in real time. |
| **#4** | All-or-nothing response — low-confidence alerts get throttled (rate-limited) instead of a full block; the payment gateway/server are protected by a critical-infrastructure guard; quarantined hosts get flow-stats forensics instead of a silent drop. |
| **#15** | Snapshot compliance — a live incident score plus a real mapping against all 12 PCI DSS v4.0 requirements. |
| **#16** | No real monitoring — a health agent tracks the actual POS backend and payment-gateway processes (CPU, memory, uptime, restarts), with heartbeat-based tamper detection if either agent is killed. |

## Architecture

Four planes: **Data** (the real POS app + payment gateway — what's being protected), **Control** (Ryu SDN controller: micro-segmentation + graduated reactive firewall), **Analytics** (RAM-scrape monitor, POS health agent, compliance API), **Presentation** (Streamlit operator console, optionally Grafana).

The SDN layer (Mininet/Ryu) is an emulated network that stands in for "the network these terminals would sit on" — it does not carry the real POS app's actual localhost traffic. See `dashboard/app.py` and `agents/ram_monitor.py` for where the two halves connect (real-process health/detection reporting into the same compliance API the SDN layer reports to).

## Prerequisites

- **Node.js 18+** and **MongoDB**, for the POS application and payment gateway.
- **Python 3.8**, **Mininet**, and **Open vSwitch**, for the SDN half — **Linux only**. Mininet requires Linux kernel network-namespace support and does not run on Windows, including via a plain `pip install`.
- A second, unconstrained Python environment for the Streamlit console.

## Setup

**1. Payment gateway**
```bash
cd fake-payment-gateway
npm install
npm run start          # port 5100
```

**2. POS backend**
```bash
cd Restaurant_POS_System/pos-backend
npm install
cp .env.example .env   # set MONGODB_URI and JWT_SECRET
npm run dev             # port 8000
```

**3. POS frontend**
```bash
cd Restaurant_POS_System/pos-frontend
npm install
cp .env.example .env   # VITE_BACKEND_URL=http://localhost:8000  (no /api suffix — see Troubleshooting)
npm run dev             # port 5173
```

**4. SDN environment** (Linux only)
```bash
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update && sudo apt install python3.8 python3.8-venv mininet openvswitch-switch
python3.8 -m venv sdn_env
sdn_env/bin/pip install -r requirements-sdn.txt
sdn_env/bin/python3 scripts/verify_sdn_env.py    # every line should say [PASS]
```

**5. Streamlit environment**
```bash
python3 -m venv streamlit_env
streamlit_env/bin/pip install streamlit requests pandas
```

## Running it

Start each in its own terminal, in this order:

| # | Service | Command | Port |
|---|---|---|---|
| 1 | Payment gateway | `npm run start` (in `fake-payment-gateway`) | 5100 |
| 2 | POS backend | `npm run dev` (in `pos-backend`) | 8000 |
| 3 | POS frontend | `npm run dev` (in `pos-frontend`) | 5173 |
| 4 | SDN controller | `ryu-manager sdn_apps/microseg.py sdn_apps/dynamic_fw.py --verbose` (from `sdn_env`) | 6633 / 8080 |
| 5 | RAM-scrape monitor | `sudo sdn_env/bin/python3 agents/ram_monitor.py` | — |
| 6 | Compliance API | `python3 dashboard/app.py` (from `sdn_env`) | 9000 |
| 7 | POS health monitor | `sdn_env/bin/python3 agents/pos_health_monitor.py` | — |
| 8 | Operator console | `streamlit run dashboard/security_dashboard.py` (from `streamlit_env`) | 8501 |

Optionally, bring up the emulated store network and run the automated test suite:
```bash
sudo python3 topology/pos_network.py      # drops into the mininet> prompt
sudo python3 attacks/simulate_attacks.py  # from a separate terminal, after mn -c
```

### Controlling terminals directly

```bash
curl -X POST http://localhost:8080/posguard/quarantine/10.0.0.1
curl -X POST http://localhost:8080/posguard/throttle/10.0.0.3
curl -X POST http://localhost:8080/posguard/release/10.0.0.1
curl http://localhost:8080/posguard/status
```
Add `?force=true` to act on the gateway (`10.0.0.100`) or server (`10.0.0.200`), which otherwise refuse automatic action.

## Troubleshooting

Real issues hit building and deploying this project, in the order you're likely to hit them:

- **`ImportError: cannot import name 'ALREADY_HANDLED' from 'eventlet.wsgi'`** — the `sdn_env` was created without the pinned versions in `requirements-sdn.txt`. Reinstall from that file; `scripts/verify_sdn_env.py` catches this before it happens.
- **`ryu-manager: command not found`** — you're not inside the activated `sdn_env` (`source sdn_env/bin/activate` first), or Ryu was never installed into it.
- **`Unable to contact remote controller`** from Mininet — the SDN controller wasn't already running, or `sudo mn -c` was run *after* starting it rather than before (its own cleanup kills any running `ryu-manager`). Always: `mn -c` first, then start the controller.
- **A 404 on a path containing `/api/api/`** — `VITE_BACKEND_URL` has an `/api` suffix that duplicates the prefix already in every request path in `pos-frontend/src/https/index.js`. It should be the bare backend origin only.
- **`ModuleNotFoundError` for `fastapi`/`uvicorn`/`psutil`** — running a script with the system Python instead of `sdn_env`'s. Every Python service in this project except `pos_health_monitor.py`'s own health-only checks needs `sdn_env/bin/python3` specifically.
- **Compliance score sits at 0 immediately on startup** — the RAM-usage heuristic in `ram_monitor.py` flags every already-running process over its threshold once, the first time it scans a shared development machine. Not an ongoing attack; restart `dashboard/app.py` for a clean event log before a demo.
- **`"No switches connected yet"`** from any `/posguard/*` REST call — Mininet's topology isn't currently running. Start `topology/pos_network.py` and leave it at the `mininet>` prompt; don't type `exit` there or it tears the network down again.
- **A terminal (pos2/pos3) is missing from the dashboard** — the terminal list is discovered from live traffic, not hardcoded. It resets on every `ryu-manager` restart, and only registers a terminal once it's seen *sending* a packet. Run `pingall` from the `mininet>` prompt to register all of them.

## Known limitations

- The SDN and compliance REST APIs have no authentication.
- The compliance API's event history is in-memory and is lost on restart.
- Micro-segmentation and quarantine act only on the emulated Mininet network — they have no effect on the real POS app's own localhost traffic, by design.
- The eBPF-based detection upgrade discussed as a future direction was deliberately not implemented, to avoid destabilizing the pinned Ryu/Python 3.8 environment.
