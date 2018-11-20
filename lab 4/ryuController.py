from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet
import json
# packet

from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp

class shortest_path(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(shortest_path, self).__init__(*args, **kwargs)
        self.arp_table={}
        self.arp_table = {'10.0.0.1': '00:00:00:00:00:01',
                          '10.0.0.2': '00:00:00:00:00:02',
                          '10.0.0.3': '00:00:00:00:00:03',
                          '10.0.0.4': '00:00:00:00:00:04'}

    #Initial handshake between switchand controller proactive entries are added to switch here

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser #parser


        #this code does default match and sends flows that default packet should be send to controller
        match = ofp_parser.OFPMatch()
        action = ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER)])
        inst = [action]
        self.add_flow(dp=dp,match=match, inst=inst, table=0, priority=0)


        #Add here proactive icmp rules
        dpid = dp.id

        if (dpid == 1):  #Switch One
            self.flow_match_layer3(dp, '10.0.0.2', 2)
            self.flow_match_layer3(dp, '10.0.0.4', 3)
            self.flow_match_layer3(dp, '10.0.0.1', 1)
            self.flow_match_layer4(dp, '10.0.0.3', inet.IPPROTO_ICMP, 3)
            self.flow_match_layer4(dp, '10.0.0.3', inet.IPPROTO_TCP, 3)
            self.flow_match_layer4(dp, '10.0.0.3', inet.IPPROTO_UDP, 2)
            self.flow_match_drop(dp, '10.0.0.4', inet.IPPROTO_UDP, [])

        if (dpid == 2):  #Switch Two
            self.flow_match_layer3(dp, '10.0.0.1', 2)
            self.flow_match_layer3(dp, '10.0.0.2', 1)
            self.flow_match_layer3(dp, '10.0.0.3', 3)
            self.flow_match_layer4(dp, '10.0.0.4', inet.IPPROTO_ICMP, 2)
            self.flow_match_layer4(dp, '10.0.0.4', inet.IPPROTO_TCP, 2)
            self.flow_match_layer4(dp, '10.0.0.4', inet.IPPROTO_UDP, 3)
            self.flow_match_layer7(dp, '10.0.0.2','10.0.0.4', inet.IPPROTO_TCP, 80)


        if (dpid == 3):   #Switch Three
            self.flow_match_layer3(dp, '10.0.0.2', 2)
            self.flow_match_layer3(dp, '10.0.0.4', 3)
            self.flow_match_layer3(dp, '10.0.0.3', 1)
            self.flow_match_layer4(dp, '10.0.0.1', inet.IPPROTO_ICMP, 3)
            self.flow_match_layer4(dp, '10.0.0.1', inet.IPPROTO_TCP, 3)
            self.flow_match_layer4(dp, '10.0.0.1', inet.IPPROTO_UDP, 2)

        if (dpid == 4):   #Switch Four
            self.flow_match_layer3(dp, '10.0.0.4', 1)
            self.flow_match_layer3(dp, '10.0.0.1', 2)
            self.flow_match_layer3(dp, '10.0.0.3', 3)
            self.flow_match_layer4(dp, '10.0.0.2', inet.IPPROTO_ICMP, 2)
            self.flow_match_layer4(dp, '10.0.0.2', inet.IPPROTO_TCP, 2)
            self.flow_match_layer4(dp, '10.0.0.2', inet.IPPROTO_UDP, 3)
            self.flow_match_layer7(dp, '10.0.0.4','10.0.0.2', inet.IPPROTO_TCP, 80)
            self.flow_match_drop(dp, '10.0.0.1', inet.IPPROTO_UDP, [])

    #This defination creates a match, action and adds flow to switch
    def flow_match_layer7(self,dp,ipv4_src,ipv4_dst,ip_proto,tcp_dst):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=ipv4_src, ipv4_dst=ipv4_dst,ip_proto=ip_proto,tcp_dst=tcp_dst)
        action = ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  [ofp_parser.OFPActionOutput(ofp.OFPP_CONTROLLER)])
        inst = [action]
        self.add_flow(dp, match, inst, 0, 15)

    def flow_match_drop(self, dp, ipv4_dst, ip_proto,actions):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        actions = actions
        match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_dst=ipv4_dst, ip_proto=ip_proto)
        action = ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  actions)
        inst = [action]
        self.add_flow(dp, match, inst, 0, 11)

    def flow_match_layer3(self,dp,ipv4_dst,out_port):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,ipv4_dst=ipv4_dst)
        action = ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  [ofp_parser.OFPActionOutput(out_port)])
        inst = [action]
        self.add_flow(dp, match, inst, 0, 10)

    def flow_match_layer4(self,dp,ipv4_dst,proto,out_port):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        match = ofp_parser.OFPMatch(eth_type=ether.ETH_TYPE_IP,ipv4_dst=ipv4_dst,ip_proto=proto)
        action = ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                                                  [ofp_parser.OFPActionOutput(out_port)])
        inst = [action]
        self.add_flow(dp, match, inst, 0, 10)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        #self.logger.info(ev)
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        #get datapath ID to identify OpenFLow Switches
        dpid = dp.id
        #analyse the received packets using packet library to take appropriate action
        pkt = packet.Packet(msg.data)
        self.logger.info("This is packet in message!")
        self.logger.info(pkt)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ethertype = eth_pkt.ethertype
        eth_dst = eth_pkt.dst
        eth_src = eth_pkt.src

        in_port = msg.match['in_port']

        #self.logger.info("This is packet_in from switch id %s",dpid)
        #self.logger.info("packet in ether_type = %s dpid = %s, src =  %s, dst =  %s, in_port =  %s ",ethertype, dpid, eth_src, eth_dst, in_port)

        #If arp packet send to handle_arp
        if(ethertype == ether.ETH_TYPE_ARP):
            self.handle_arp(dp, in_port, pkt)

        #If packet is TCP sync from H2 and H4 then Send RST message
        if (ethertype == ether.ETH_TYPE_IP):
            self.handle_tcp(dp, in_port, pkt)



    # FlowMod for adding proactive flows in to switch

    def add_flow(self, dp, match, inst, table, priority):
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser

        buffer_id = ofp.OFP_NO_BUFFER

        mod = ofp_parser.OFPFlowMod(
            datapath=dp, table_id=table, priority=priority,
            match=match, instructions=inst
        )
        #self.logger.info("Here are flows")
        #self.logger.info(mod)
        dp.send_msg(mod)

    #PacketOut used to send packet from controller to switch

    def send_packet(self, dp, port, pkt):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        pkt.serialize()
        data = pkt.data
        action = [parser.OFPActionOutput(port=port)]

        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=action, data=data)
        dp.send_msg(out)


    #In our case arp table is hardcoded so arprequest is resolved by controller

    def handle_arp(self, dp, port, pkt):
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        
        #checking if it's arp packet return None if not arp packet
        if pkt_arp.opcode != arp.ARP_REQUEST:
            return

        #checking if the destination address exists in arp_table returns NONE otherwise
        if self.arp_table.get(pkt_arp.dst_ip) == None:
            return

        get_mac = self.arp_table[pkt_arp.dst_ip]

        pkt = packet.Packet()
        pkt.add_protocol(
            ethernet.ethernet(
                ethertype=ether.ETH_TYPE_ARP,
                dst=pkt_ethernet.src,
                src=get_mac
            )
        )

        pkt.add_protocol(
            arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=get_mac,
                src_ip=pkt_arp.dst_ip,
                dst_mac=pkt_arp.src_mac,
                dst_ip=pkt_arp.src_ip
            )
        )

        self.send_packet(dp, port, pkt)

    def handle_tcp(self, dp, port, pkt):
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        ip_src = ipv4_pkt.src
        ip_dst = ipv4_pkt.dst
        ip_proto = ipv4_pkt.proto

        tcp_pkt = pkt.get_protocol(tcp.tcp)
        dst_port = tcp_pkt.dst_port

        if ip_src == "10.0.0.2" and ip_dst == "10.0.0.4" and ip_proto == inet.IPPROTO_TCP and dst_port == 80:
            tcp_hd = tcp.tcp(ack=tcp_pkt.seq + 1, src_port=tcp_pkt.dst_port, dst_port=tcp_pkt.src_port, bits=20)
            ip_hd = ipv4.ipv4(dst=ipv4_pkt.src, src=ipv4_pkt.dst, proto=ipv4_pkt.proto)
            ether_hd = ethernet.ethernet(ethertype=ether.ETH_TYPE_IP, dst=eth_pkt.src, src=eth_pkt.dst)
            tcp_rst_ack = packet.Packet()
            tcp_rst_ack.add_protocol(ether_hd)
            tcp_rst_ack.add_protocol(ip_hd)
            tcp_rst_ack.add_protocol(tcp_hd)
            self.send_packet(dp, port, tcp_rst_ack)

        if ip_src == "10.0.0.4" and ip_dst == "10.0.0.2" and ip_proto == inet.IPPROTO_TCP and dst_port == 80:
            tcp_hd = tcp.tcp(ack=tcp_pkt.seq + 1, src_port=tcp_pkt.dst_port, dst_port=tcp_pkt.src_port, bits=20)
            ip_hd = ipv4.ipv4(dst=ipv4_pkt.src, src=ipv4_pkt.dst, proto=ipv4_pkt.proto)
            ether_hd = ethernet.ethernet(ethertype=ether.ETH_TYPE_IP, dst=eth_pkt.src, src=eth_pkt.dst)
            tcp_rst_ack = packet.Packet()
            tcp_rst_ack.add_protocol(ether_hd)
            tcp_rst_ack.add_protocol(ip_hd)
            tcp_rst_ack.add_protocol(tcp_hd)
            self.send_packet(dp, port, tcp_rst_ack)




