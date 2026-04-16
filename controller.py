from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
import datetime

# Map switch IDs to readable switch names
DPID_TO_NAME = {
    1: 's1',
    2: 's2',
    3: 's3'
}

# Add MAC pairs here if you want to block traffic
# Example:
# BLOCKED_FLOWS = {
#     ('3a:a0:37:00:06:8f', '7e:9c:58:0b:6c:5c')
# }
BLOCKED_FLOWS = set()


class PathTracer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PathTracer, self).__init__(*args, **kwargs)

        # dpid -> {mac -> port}
        self.mac_to_port = {}

        # flow_id -> [dpid list]
        self.packet_paths = {}

        # flow_id -> packet count
        self.flow_stats = {}

        self.logger.info("=== PathTracer SDN Controller Started ===")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        self.logger.info(
            f"[SETUP] Switch connected: {DPID_TO_NAME.get(dpid, dpid)}"
        )

        # Default rule: send unknown packets to controller
        match = parser.OFPMatch()

        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(
            datapath=datapath,
            priority=0,
            match=match,
            actions=actions,
            idle_timeout=0,
            hard_timeout=0
        )

    def add_flow(self, datapath, priority, match, actions,
                 idle_timeout=10, hard_timeout=30):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        instructions = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )

        datapath.send_msg(flow_mod)

    def drop_flow(self, datapath, priority, match):
        """Install a drop rule."""

        parser = datapath.ofproto_parser

        flow_mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=[],
            idle_timeout=30,
            hard_timeout=60
        )

        datapath.send_msg(flow_mod)

    def print_flow_stats(self):
        self.logger.info("===== FLOW STATISTICS =====")

        for flow_id, count in self.flow_stats.items():
            self.logger.info(f"{flow_id}: {count} packets")

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        switch_name = DPID_TO_NAME.get(dpid, str(dpid))

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP packets
        if eth.ethertype == 0x88cc:
            return

        dst = eth.dst
        src = eth.src

        flow_id = f"{src}->{dst}"
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

        # Blocked flow scenario
        if (src, dst) in BLOCKED_FLOWS:
            self.logger.warning(
                f"[BLOCKED] {timestamp} Flow {flow_id} "
                f"DROPPED at {switch_name}"
            )

            match = parser.OFPMatch(
                eth_src=src,
                eth_dst=dst
            )

            self.drop_flow(
                datapath=datapath,
                priority=10,
                match=match
            )
            return

        # Learn source MAC on this switch
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Decide output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Install flow if destination is known
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=src,
                eth_dst=dst
            )

            self.add_flow(
                datapath=datapath,
                priority=1,
                match=match,
                actions=actions
            )

        # Track path
        if flow_id not in self.packet_paths:
            self.packet_paths[flow_id] = []

        if dpid not in self.packet_paths[flow_id]:
            self.packet_paths[flow_id].append(dpid)

        # Count packets
        self.flow_stats[flow_id] = self.flow_stats.get(flow_id, 0) + 1

        # Convert switch IDs to readable names
        path_names = [
            DPID_TO_NAME.get(d, str(d))
            for d in self.packet_paths[flow_id]
        ]

        self.logger.info(
            f"[PATH] {timestamp} Flow {flow_id} | "
            f"Switch: {switch_name} | "
            f"Port in: {in_port} -> out: {out_port} | "
            f"Path so far: {' -> '.join(path_names)} | "
            f"Packet #: {self.flow_stats[flow_id]}"
        )

        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)

        # Print statistics every 10 packets
        if self.flow_stats[flow_id] % 10 == 0:
            self.print_flow_stats()
