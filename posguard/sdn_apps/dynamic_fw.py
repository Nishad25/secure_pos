import itertools
import ipaddress
import json
import os
import time
import urllib.error
import urllib.request
from webob import Response

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
from ryu.lib import hub
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

POSGUARD_INSTANCE = 'posguard_api_app'

# --- Gap #4: graduated response tuning ---
# Terminals never get a flat 10-minute block any more. First offense gets a
# short quarantine; each repeat offense within this controller's uptime
# doubles the timeout, capped at QUARANTINE_MAX_TIMEOUT.
QUARANTINE_BASE_TIMEOUT = 180        # seconds — first offense
QUARANTINE_MAX_TIMEOUT = 1800        # seconds — cap after repeated offenses
THROTTLE_HARD_TIMEOUT = 300          # seconds — lower-confidence alerts get rate-limited, not blocked
THROTTLE_RATE_KBPS = 64              # how hard a throttled host gets rate-limited

# Auto-classification, mirroring microseg.py's rule: anything in this /24
# with a last octet > TERMINAL_MAX_OCTET is treated as critical
# infrastructure (gateway, server, and any future server-range host) and
# refuses auto-quarantine/auto-throttle without an explicit human
# override (?force=true) — a false positive here is far more damaging
# than one on a single till.
POS_NETWORK = ipaddress.ip_network('10.0.0.0/24')
TERMINAL_MAX_OCTET = 99


def is_critical_infra(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return ip in POS_NETWORK and int(ip_str.split('.')[-1]) > TERMINAL_MAX_OCTET


QUARANTINE_PRIORITY = 100
THROTTLE_PRIORITY = 90

# --- forensic visibility instead of a silent drop ---
# A literal redirect to a separate "forensics VLAN" host would need a new
# topology host plus a cross-app MAC/port lookup shared with microseg.py —
# more moving parts than this testbed needs. Flow statistics give the same
# real value (what did a quarantined host keep trying to do?) using a
# core OpenFlow feature that's guaranteed to work on any switch, instead
# of an OpenFlow meter that might not be (see the throttle path above).
FORENSICS_POLL_INTERVAL = 10   # seconds
FORENSICS_ALERT_THRESHOLD = 50  # blocked packets before this escalates to an alert

# Gap: "single-host testbed" — override so the controller can report to a
# dashboard on a separate host: POSGUARD_DASHBOARD_HOST=http://10.0.0.60:9000
DASHBOARD_HOST = os.environ.get("POSGUARD_DASHBOARD_HOST", "http://localhost:9000")
DASHBOARD_ALERT_URL = DASHBOARD_HOST + "/api/alert"


class DynamicFirewall(app_manager.RyuApp):
    """
    Gap #3 defense (reactive rules) + Gap #4 (graduated response):
    Exposes a REST API so an external detection agent can either fully
    quarantine a terminal or just rate-limit it, in real time, without
    editing any code. Also polls OpenFlow flow statistics for quarantined
    hosts so a silent drop still leaves forensic evidence of what was
    attempted. Run alongside microseg.py.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(DynamicFirewall, self).__init__(*args, **kwargs)
        self.datapaths = {}          # {dpid: datapath}
        self.quarantined = {}        # {ip: expires_at_unix}
        self.throttled = {}          # {ip: expires_at_unix}
        self.offense_counts = {}     # {ip: int} — persists across releases, drives the timeout tier
        self.blocked_stats = {}      # {ip: {'packet_count': int, 'byte_count': int}} — forensic evidence
        self._alerted_thresholds = set()  # ips already escalated, avoid alert spam
        self._meter_ids = {}         # {(dpid, ip): meter_id}
        self._meter_id_counter = itertools.count(100)

        wsgi = kwargs['wsgi']
        wsgi.register(QuarantineController, {POSGUARD_INSTANCE: self})

        self._monitor_thread = hub.spawn(self._monitor_quarantined_flows)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("DynamicFirewall: tracking switch %s", datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def _error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.error(
            "OFPErrorMsg from switch %s: type=0x%02x code=0x%02x — "
            "if this followed a throttle request, this switch's OVS build "
            "likely doesn't support OpenFlow meters",
            msg.datapath.id, msg.type, msg.code
        )

    # ------------------------------------------------------------------
    # Gap #4 extension: forensic visibility on quarantined hosts
    # ------------------------------------------------------------------
    def _monitor_quarantined_flows(self):
        while True:
            hub.sleep(FORENSICS_POLL_INTERVAL)
            for datapath in list(self.datapaths.values()):
                parser = datapath.ofproto_parser
                datapath.send_msg(parser.OFPFlowStatsRequest(datapath))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        for stat in ev.msg.body:
            if stat.priority != QUARANTINE_PRIORITY:
                continue  # only the quarantine drop rules carry forensic value here
            ip = stat.match.get('ipv4_src') or stat.match.get('ipv4_dst')
            if not ip or ip not in self.quarantined:
                continue

            entry = self.blocked_stats.setdefault(ip, {'packet_count': 0, 'byte_count': 0})
            entry['packet_count'] += stat.packet_count
            entry['byte_count'] += stat.byte_count

            if entry['packet_count'] >= FORENSICS_ALERT_THRESHOLD and ip not in self._alerted_thresholds:
                self._alerted_thresholds.add(ip)
                self._send_forensics_alert(ip, entry['packet_count'])

    def _send_forensics_alert(self, ip_address, packet_count):
        # Deliberately stdlib urllib here, not `requests` — this method runs
        # inside ryu-manager's eventlet-monkey-patched process, and importing
        # `requests` (via urllib3's eager SSLContext construction) there
        # collides with eventlet's patched ssl.SSLContext and infinite-loops
        # in SSLContext.minimum_version. ram_monitor.py and pos_health_monitor.py
        # run as plain, unpatched processes and are unaffected — this is the
        # one file where that specific mix bites.
        payload = json.dumps({
            'message': f'{ip_address} attempted {packet_count}+ packets while quarantined '
                       f'— sustained activity, not a one-off',
            'severity': 'warning',
            'source': 'dynamic_fw_forensics',
        }).encode('utf-8')
        req = urllib.request.Request(
            DASHBOARD_ALERT_URL, data=payload,
            headers={'Content-Type': 'application/json'}, method='POST'
        )
        try:
            urllib.request.urlopen(req, timeout=2)
        except (urllib.error.URLError, OSError):
            pass  # dashboard may not be running — don't crash the controller over it

    def _clear_forensics(self, ip_address):
        self.blocked_stats.pop(ip_address, None)
        self._alerted_thresholds.discard(ip_address)

    # ------------------------------------------------------------------
    # low-level flow / meter helpers
    # ------------------------------------------------------------------
    def add_flow(self, datapath, priority, match, actions, hard_timeout=0, meter_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if meter_id is not None:
            inst.insert(0, parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER))
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                 match=match, instructions=inst,
                                 hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def _delete_flows(self, datapath, ip_address, priority):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        for match in (parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_address),
                      parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_address)):
            mod = parser.OFPFlowMod(
                datapath=datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                priority=priority, match=match
            )
            datapath.send_msg(mod)

    def _ensure_meter(self, datapath, ip_address, rate_kbps):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        key = (datapath.id, ip_address)
        meter_id = self._meter_ids.get(key)
        if meter_id is None:
            meter_id = next(self._meter_id_counter)
            self._meter_ids[key] = meter_id

        band = parser.OFPMeterBandDrop(rate=rate_kbps, burst_size=0)
        mod = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_ADD,
                                  flags=ofproto.OFPMF_KBPS, meter_id=meter_id, bands=[band])
        datapath.send_msg(mod)
        return meter_id

    def _delete_meter(self, datapath, ip_address):
        key = (datapath.id, ip_address)
        meter_id = self._meter_ids.pop(key, None)
        if meter_id is None:
            return
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPMeterMod(datapath=datapath, command=ofproto.OFPMC_DELETE,
                                  meter_id=meter_id)
        datapath.send_msg(mod)

    def _next_timeout_for(self, ip_address):
        """Tiered timeout: doubles per repeat offense, capped."""
        count = self.offense_counts.get(ip_address, 0)
        timeout = QUARANTINE_BASE_TIMEOUT * (2 ** count)
        return min(timeout, QUARANTINE_MAX_TIMEOUT)

    # ------------------------------------------------------------------
    # Gap #3 / #4 actions
    # ------------------------------------------------------------------
    def quarantine_host(self, ip_address, force=False):
        if not self.datapaths:
            return {'success': False, 'message': 'No switches connected yet'}
        if is_critical_infra(ip_address) and not force:
            return {
                'success': False,
                'message': f'{ip_address} is critical infrastructure — refusing to '
                            f'auto-quarantine. Retry with ?force=true if this is intentional.'
            }

        # a host being quarantined is no longer just throttled
        self._clear_throttle(ip_address)
        self._clear_forensics(ip_address)  # fresh evidence window for this offense

        timeout = self._next_timeout_for(ip_address)
        self.offense_counts[ip_address] = self.offense_counts.get(ip_address, 0) + 1

        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            for match in (parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_address),
                          parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_address)):
                self.add_flow(datapath, priority=QUARANTINE_PRIORITY, match=match,
                              actions=[], hard_timeout=timeout)
            self.logger.warning(
                "QUARANTINED %s on switch %s (offense #%d, auto-release in %ss)",
                ip_address, dpid, self.offense_counts[ip_address], timeout
            )

        self.quarantined[ip_address] = time.time() + timeout
        return {
            'success': True,
            'message': f'Host {ip_address} quarantined on {len(self.datapaths)} switch(es)',
            'offense_count': self.offense_counts[ip_address],
            'hard_timeout': timeout,
        }

    def throttle_host(self, ip_address, force=False):
        """Rate-limit a host instead of fully blocking it — for lower-confidence
        alerts where a full quarantine would be disruptive if it turns out
        to be a false positive."""
        if not self.datapaths:
            return {'success': False, 'message': 'No switches connected yet'}
        if is_critical_infra(ip_address) and not force:
            return {
                'success': False,
                'message': f'{ip_address} is critical infrastructure — refusing to '
                            f'auto-throttle. Retry with ?force=true if this is intentional.'
            }
        if ip_address in self.quarantined:
            return {'success': False, 'message': f'{ip_address} is already fully quarantined'}

        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            meter_id = self._ensure_meter(datapath, ip_address, THROTTLE_RATE_KBPS)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_address)
            actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)]
            self.add_flow(datapath, priority=THROTTLE_PRIORITY, match=match,
                          actions=actions, hard_timeout=THROTTLE_HARD_TIMEOUT, meter_id=meter_id)
            self.logger.warning(
                "THROTTLED %s to %d kbps on switch %s (auto-clear in %ss)",
                ip_address, THROTTLE_RATE_KBPS, dpid, THROTTLE_HARD_TIMEOUT
            )

        self.throttled[ip_address] = time.time() + THROTTLE_HARD_TIMEOUT
        return {
            'success': True,
            'message': f'Host {ip_address} throttled to {THROTTLE_RATE_KBPS} kbps on '
                       f'{len(self.datapaths)} switch(es)',
            'hard_timeout': THROTTLE_HARD_TIMEOUT,
        }

    def _clear_throttle(self, ip_address):
        if ip_address not in self.throttled:
            return
        for datapath in self.datapaths.values():
            self._delete_flows(datapath, ip_address, THROTTLE_PRIORITY)
            self._delete_meter(datapath, ip_address)
        self.throttled.pop(ip_address, None)

    def release_host(self, ip_address):
        """Manually release a host early — clears both quarantine and throttle state."""
        if not self.datapaths:
            return {'success': False, 'message': 'No switches connected yet'}

        for datapath in self.datapaths.values():
            self._delete_flows(datapath, ip_address, QUARANTINE_PRIORITY)
            self._delete_flows(datapath, ip_address, THROTTLE_PRIORITY)
            self._delete_meter(datapath, ip_address)

        self.quarantined.pop(ip_address, None)
        self.throttled.pop(ip_address, None)
        self._clear_forensics(ip_address)
        return {'success': True, 'message': f'Host {ip_address} released'}

    def reset_offense_history(self, ip_address):
        """Clears the offense counter so the next quarantine goes back to
        the base timeout — useful when re-running a demo/attack simulation
        repeatedly rather than accumulating an ever-longer timeout."""
        self.offense_counts.pop(ip_address, None)
        return {'success': True, 'message': f'Offense history cleared for {ip_address}'}


class QuarantineController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(QuarantineController, self).__init__(req, link, data, **config)
        self.app = data[POSGUARD_INSTANCE]

    @staticmethod
    def _json_response(result):
        body = json.dumps(result).encode('utf-8')
        return Response(content_type='application/json', body=body,
                         status=200 if result.get('success') else 503)

    @route('posguard', '/posguard/quarantine/{ip}', methods=['POST'])
    def quarantine(self, req, ip, **kwargs):
        force = req.GET.get('force', 'false').lower() == 'true'
        return self._json_response(self.app.quarantine_host(ip, force=force))

    @route('posguard', '/posguard/throttle/{ip}', methods=['POST'])
    def throttle(self, req, ip, **kwargs):
        force = req.GET.get('force', 'false').lower() == 'true'
        return self._json_response(self.app.throttle_host(ip, force=force))

    @route('posguard', '/posguard/release/{ip}', methods=['POST'])
    def release(self, req, ip, **kwargs):
        return self._json_response(self.app.release_host(ip))

    @route('posguard', '/posguard/reset/{ip}', methods=['POST'])
    def reset(self, req, ip, **kwargs):
        return self._json_response(self.app.reset_offense_history(ip))

    @route('posguard', '/posguard/status', methods=['GET'])
    def status(self, req, **kwargs):
        body = json.dumps({
            'quarantined_hosts': list(self.app.quarantined.keys()),
            'throttled_hosts': list(self.app.throttled.keys()),
            'offense_counts': self.app.offense_counts,
            'blocked_traffic': self.app.blocked_stats,
            'connected_switches': list(self.app.datapaths.keys()),
        }).encode('utf-8')
        return Response(content_type='application/json', body=body)
