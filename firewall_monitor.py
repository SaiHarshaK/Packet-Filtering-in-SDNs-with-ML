## @package firewall_monitor
#  Documentation for this module.
#
#  An extension to the learning switch module
#  Allows "good" websites and blocks "bad" website based on the similarity to the filter set in checkSim.py.
#  Populates corresponding rules into the flow tables connected to the controller.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
import sys
from scapy.all import Ether
import ipaddress
import fcntl

import json

sys.path.insert(1, '/home/harsha')
import checkSim

## List of known dns servers
dns_servers = ['192.168.122.1']
## Allows ip in this subnet
allow_subnet = ["10.0.0.0/24"]
## Subnet to reject
reject_regex = ["192.168.122.56/29"]

## Docs on FirewallMonitor.
#
#  Creates the Ryu Application, specifies which versions of the OpenFlow protocol that the
#  application is compatible with, and initializes the internal MAC-to-Port table.
class FirewallMonitor(app_manager.RyuApp):
    ## OpenFlow Protocol supported
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    ## The constructor.
    def __init__(self, *args, **kwargs):
        super(FirewallMonitor, self).__init__(*args, **kwargs)
        ## @var mac_to_port
        #  dictionary for mac to port
        self.mac_to_port = {}

    ## Method.
    #  @param self  The object pointer.
    #  @param ev    events is the datastructure which has datapath, ofproto, parser, data, other base attributes as defined by ryu
    #
    #  The main purpose for this code is to have it run any time a switch is added to the controller and
    #  install a catch-all (or table-miss) flow entry in the switch, which allows the switch to send
    #  packets to the controller.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, False)

    ## Method.
    #  @param self  The object pointer.
    #  @param datapath associated datapath of packet
    #  @param priority Matching precedence of the entry
    #  @param match The match fields consist of ingress ports, packet header fields, and metadata from a previous flow table
    #  @param actions set of instructions that are executed
    #  @param timeout   boolean to decide if timeout has to be installed in flow entry
    #  @param buffer_id buffer id of packet
    #  @param drop  boolean to decide to drop packet or forward
    #
    #  a helper method is defined to construct and send the final flow entry.
    def add_flow(self, datapath, priority, match, actions, timeout, buffer_id=None, drop=False):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if drop == True:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        else:
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if timeout == True:
            if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        idle_timeout=60, hard_timeout=0, priority=priority, match=match,
                                        instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        idle_timeout=60, hard_timeout=0, match=match, instructions=inst)
        else:
            if buffer_id:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=priority, match=match,
                                        instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, instructions=inst)
        datapath.send_msg(mod)



    ## Method.
    #  @param self  The object pointer.
    #  @param ip  ip address as string.
    #  @param net  subnet as string.
    #  @return: boolean: true if ip inside subnet else false
    #
    #  a helper method is check if ip is contained in the subnet.
    def addressInNetwork(self, ip, net):
        return ipaddress.ip_address(ip) in ipaddress.ip_network(net)


    ## Method.
    #  @param self  The object pointer.
    #  @param pkt  packet as binary.
    #
    #  @return list: if dns reply, a list of hostname and ipaddresses from answer records, else returns [("","")]
    #
    #  a helper method is check if packet is a dns reply
    def get_hostname_ip_from_pkt(self, pkt):
        scapy_pkt = Ether(pkt)
        if(len(scapy_pkt.layers()) < 4 or type(scapy_pkt[3]) != scapy.layers.dns.DNS):
            # Not a DNS packet
            return [("", "")]
        else:
            src = scapy_pkt[1].src
            for dns in dns_servers:
                if dns == src:
                    # if ipv6 we ignore for now
                    if scapy_pkt[3][1].getfieldval('qtype') == 28:
                        return [("", "")]
                    # DNS packet
                    try:
                        dns_answers = scapy_pkt[3]
                        count = dns_answers.ancount
                        host_ip_pairs = []
                        if count == 0:
                            return [("", "")]
                        for index in range(0, count):
                            host_ip_pairs.append((scapy_pkt[3][1].getfieldval('qname').decode('ascii'),
                                dns_answers.an[index].rdata))
                        return host_ip_pairs
                    except:
                        return [("", "")] # invalid website.
            # else this is not dns reply
            return [("", "")]

    ## Method.
    #  @param fileName  The object pointer.
    #  @param data  string.
    #
    # a helper method which saves data to the given fileName.
    def save_to_file(self, fileName, data):
        processed = open(fileName, "a")
        fcntl.flock(processed, fcntl.LOCK_EX)
        processed.write(data)
        fcntl.flock(processed, fcntl.LOCK_UN)
        processed.close()

    ## Method.
    #  @param self  The object pointer.
    #  @param pkt  packet as binary.
    #
    # Calls get_hostname_ip_from_pkt() to retrieve hostname and ip address. Ignore if packet’s hostname is empty
    # Check if the hostname is already in the processed list. If so, associated rule already exists. Otherwise extract keywords and use ML model
    def get_checkNewEntry(self, pkt):
        host_ip_pairs = self.get_hostname_ip_from_pkt(pkt)
        # this means that either the packet isn't tls packet or not a dns reply
        host = host_ip_pairs[0][0]
        if host == "": # check if hostname is empty
            return
        # we have the name check if this was already processed before.
        try:
            processed = open("/home/harsha/processed.txt", "r")
            while True:
                line = processed.readline()
                tuple = line[:-1]
                tuple = tuple.split()
                if not line:
                    break
                if tuple[0] == host:
                    processed.close()
                    return
            processed.close()
        except IOError: # if file doesnt exist then nothing to blacklist
            pass
        # new entry so, try to get similarity. add this to processed
        sim = checkSim.similarity_check(host)
        if sim > 0.7: # bad site
            # print("host", host, " is bad")
            # add to processed - tuple (host, good/bad bool). good = 1, bad = 0
            to_write = host + " " + '0' + '\n'
            self.save_to_file("/home/harsha/processed.txt", to_write)
            # maintain a black list so that non dns replies are also blocked
            for host_ip in host_ip_pairs:
                to_write = str(host_ip[1]) + '\n'
                self.save_to_file("/home/harsha/blacklist.txt", to_write)
            return
        # should be good site.
        # add to processed - tuple (host, good/bad bool). good = 1, bad = 0
        to_write = host + " " + '1' + '\n'
        self.save_to_file("/home/harsha/processed.txt", to_write)
        return

    ## Method.
    #  @param self  The object pointer.
    #  @param src  source ip address.
    #  @param dst  destination ip address.
    #  @param raw_pkt  packet as binary.
    #
    #  @return boolean: if good site or bad site after checking rules/ function calls.
    #
    # calls checkNewEntry()  to update rules or check if already processed before.
    # Returns if good site or bad site after checking rules/ function calls.
    def isReliable(self, src, dst, raw_pkt):
        # lists. allow_subnet, blacklist, processed
        # check white list
        for subnet in allow_subnet:
            if self.addressInNetwork(dst, subnet) == True and self.addressInNetwork(src, subnet) == True:
                return True
        # black list. regex
        for subnet in reject_regex:
            if self.addressInNetwork(dst, subnet) == True or self.addressInNetwork(src, subnet) == True:
                return False
        # check black list. read from file
        try:
            blacklist = open("/home/harsha/blacklist.txt", "r")
            while True:
                line = blacklist.readline()
                blacked = line[:-1]
                if not line:
                    break
                if blacked == src or blacked == dst:
                    blacklist.close()
                    return False
            blacklist.close()
        except IOError: # if file doesnt exist then nothing to blacklist
            pass
        # else check if new entry. from this point on dns packets arer handled
        self.get_checkNewEntry(raw_pkt)
        return True # since, checkNewEntry part on code only runs on DNS. we wont be blocking dns.


    # any time the switch sends a packet to the controller, this function is called.
    # This only occurs if the switch doesn’t already know where to send the packet and the table-miss flow entry is matched.
    # The first part of the handler extracts vital information about the message and the packet sent to the controller.
    #
    # Extended from the base learning switch
    #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        # if ev.msg.msg_len < ev.msg.total_len:
        #     self.logger.debug("packet truncated: only %s of %s bytes",
        #                       ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD and eth.ethertype == ether_types.ETH_TYPE_IP:
            ip = pkt.get_protocol(ipv4.ipv4)
            # print("The packets source is: %s , Dest is: %s", ip, ip.src, ip.dst, msg.data)
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=ip.src, ipv4_dst=ip.dst)

            drop = False
            dns_packet = False
            for dns in dns_servers:
                if dns == ip.src:
                    dns_packet = True
                    break
            # check if the src and dst are good.
            if self.isReliable(ip.src, ip.dst, msg.data) == False:
                # drop these
                drop = True
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            if dns_packet == False:
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, True, msg.buffer_id, drop)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions, True, drop=drop)
                if drop == True:
                    return # no need to send packet_out.
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
