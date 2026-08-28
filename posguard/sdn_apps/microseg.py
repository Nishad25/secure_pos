from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4


class POSMicroseg(app_manager.RyuApp):
    """
    Gap #1 defense: SDN micro-segmentation.
    Blocks POS-terminal-to-POS-terminal traffic (lateral movement)
    while still allowing each terminal to reach the gateway/server.
    """
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    POS_TERMINALS = {'10.0.0.1', '10.0.0.2', '10.0.0.3'}
    ALLOWED_SERVERS = {'10.0.0.100', '10.0.0.200'}

    def __init__(self, *args, **kwargs):
        super(POSMicroseg, self).__init__(*args, **kwargs)
        self.mac_to_port = {}  # {dpid: {mac: port}}

    # --- boilerplate: when a switch connects, install the table-miss rule ---
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                           ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("POSMicroseg: switch %s connected", datapath.id)

    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                 match=match, instructions=inst,
                                 idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    def _is_lateral_pos_traffic(self, src_ip, dst_ip):
        """True when both endpoints are POS terminals talking to each other."""
        return src_ip in self.POS_TERMINALS and dst_ip in self.POS_TERMINALS

    # --- main packet handler ---
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # --- security check FIRST, before any forwarding decision ---
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip, dst_ip = ip_pkt.src, ip_pkt.dst
            if self._is_lateral_pos_traffic(src_ip, dst_ip):
                self.logger.warning(
                    "BLOCKED lateral movement attempt: %s -> %s (switch %s)",
                    src_ip, dst_ip, dpid
                )
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                         ipv4_src=src_ip, ipv4_dst=dst_ip)
                # empty actions list = drop. Installed so future packets on
                # this exact pair are dropped by the switch itself, without
                # asking the controller again, until it expires.
                self.add_flow(datapath, priority=10, match=match,
                              actions=[], idle_timeout=30)
                return  # drop this packet, nothing gets forwarded

        # --- normal MAC-learning switch behaviour for everything else ---
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, priority=1, match=match,
                          actions=actions, idle_timeout=60)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)