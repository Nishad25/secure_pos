import json
from webob import Response

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import ether_types
from ryu.app.wsgi import ControllerBase, WSGIApplication, route

POSGUARD_INSTANCE = 'posguard_api_app'
QUARANTINE_HARD_TIMEOUT = 600  # seconds — 10 min auto-release


class DynamicFirewall(app_manager.RyuApp):
    """
    Gap #3 defense: reactive OpenFlow rule injection.
    Exposes POST /posguard/quarantine/{ip} so an external detection
    agent can block a terminal in real time, without editing any code.

    Run alongside microseg.py — this app doesn't do its own packet
    forwarding, it only tracks connected switches and pushes
    high-priority drop rules onto them on demand.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(DynamicFirewall, self).__init__(*args, **kwargs)
        self.datapaths = {}     # {dpid: datapath}
        self.quarantined = {}   # {ip: True} — just for the /status view

        wsgi = kwargs['wsgi']
        wsgi.register(QuarantineController, {POSGUARD_INSTANCE: self})

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            self.logger.info("DynamicFirewall: tracking switch %s", datapath.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    def add_flow(self, datapath, priority, match, actions, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                 match=match, instructions=inst,
                                 hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def quarantine_host(self, ip_address):
        """Install DROP rules for this IP, both directions, on every switch."""
        if not self.datapaths:
            return {'success': False, 'message': 'No switches connected yet'}

        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser

            # outbound: this host sending anything
            match_out = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                         ipv4_src=ip_address)
            self.add_flow(datapath, priority=100, match=match_out,
                          actions=[], hard_timeout=QUARANTINE_HARD_TIMEOUT)

            # inbound: anything sent to this host
            match_in = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_dst=ip_address)
            self.add_flow(datapath, priority=100, match=match_in,
                          actions=[], hard_timeout=QUARANTINE_HARD_TIMEOUT)

            self.logger.warning(
                "QUARANTINED %s on switch %s (auto-release in %ss)",
                ip_address, dpid, QUARANTINE_HARD_TIMEOUT
            )

        self.quarantined[ip_address] = True
        return {
            'success': True,
            'message': 'Host %s quarantined on %d switch(es)' % (ip_address, len(self.datapaths)),
            'hard_timeout': QUARANTINE_HARD_TIMEOUT
        }

    def release_host(self, ip_address):
        """Manually release a host early, before the timeout expires."""
        if not self.datapaths:
            return {'success': False, 'message': 'No switches connected yet'}

        for datapath in self.datapaths.values():
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            for match in (parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip_address),
                          parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_address)):
                mod = parser.OFPFlowMod(
                    datapath=datapath, command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                    priority=100, match=match
                )
                datapath.send_msg(mod)

        self.quarantined.pop(ip_address, None)
        return {'success': True, 'message': 'Host %s released' % ip_address}


class QuarantineController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(QuarantineController, self).__init__(req, link, data, **config)
        self.app = data[POSGUARD_INSTANCE]

    @route('posguard', '/posguard/quarantine/{ip}', methods=['POST'])
    def quarantine(self, req, ip, **kwargs):
        result = self.app.quarantine_host(ip)
        body = json.dumps(result).encode('utf-8')
        return Response(content_type='application/json', body=body,
                         status=200 if result['success'] else 503)

    @route('posguard', '/posguard/release/{ip}', methods=['POST'])
    def release(self, req, ip, **kwargs):
        result = self.app.release_host(ip)
        body = json.dumps(result).encode('utf-8')
        return Response(content_type='application/json', body=body,
                         status=200 if result['success'] else 503)

    @route('posguard', '/posguard/status', methods=['GET'])
    def status(self, req, **kwargs):
        body = json.dumps({
            'quarantined_hosts': list(self.app.quarantined.keys()),
            'connected_switches': list(self.app.datapaths.keys())
        }).encode('utf-8')
        return Response(content_type='application/json', body=body)