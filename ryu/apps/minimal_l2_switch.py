from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet
from ryu.app.wsgi import WSGIApplication
import logging

LOG = logging.getLogger(__name__)


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # create MAC address table: {dpid: {mac: port}}
        self.mac_to_port = {}

    #Installs catch all rule during switch setup phase.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) #ofp_event.EventOFPSwitchFeatures - fires when a switch first connects and completes open flow handshake,CONFIG_DISPATCHER - means only run during the configuration phase (before switch is full operational) 
    def switch_features_handler(self, ev):
        """Install a table-miss flow entry when a switch connects."""
        datapath = ev.msg.datapath #datapath is ryus representation of the connected switch, used for all communication with that switch. ev.msg is the openflow features reply message sent by the switch.
        ofproto = datapath.ofproto #ofproto contains all openflow protocol constants, like special port numbers e.g. OFPP_CONTROLLER (send to controller), OFPP_FLOOD (send out all ports) etc.
        parser = datapath.ofproto_parser #parser module contains classes for constructing openflow messages

        # Table-miss: send unmatched packets to the controller.
        match = parser.OFPMatch() #creates a match object with no fields specified, which essentially means match every packet regardlass of the header field
        actions = [parser.OFPActionOutput( #creates a list containing a single action, OFPActionOutput (sent the packet out a port). Arg1 = which port, Arg2 = controls max_len, max number of bytes to include in the packet-in.
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER #no buffer is a special value (65535) that tells ovs dont buffer the packet on the switch, send the entire packet data up to the controller (OVS doesn't keep it in memory at all).
        )] #The alternative would be to have OVS store the packet in a buffer and only send the header to the controller, then reference the buffer ID when sending the packet back out which has poerformance issues (buffer exhuastion).
        self._add_flow(datapath, 0 , match, actions) #install the rule. This calls the helper method that constructs and sends a Flow-Mod message (swich, priority, match, ations). 0 is lowest possible priority.
        LOG.info("Switch %s connected — table-miss rule installed.", datapath.id) #After this method completes, the switch has one rule in its flow table: "if nothing else matches, send the packet to Ryu." 
        #The switch transitions to MAIN_DISPATCHER phase, and from that point, any packet that arrives triggers a Packet-In, which fires packet_in_handler function, and the learning process begins.

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) #ofp_event.EventOFPPacketIn - fires when a packet comes in (meaning it hit the rule we installed in the setup phase), MAIN_DISPATCHER - phase after setup is complete (switch operational)
    def packet_in_handler(self, ev):
        """Handle packets sent to the controller (table miss)."""
        msg = ev.msg #openflow message sent by the switch
        datapath = msg.datapath #representation of connected switch
        ofproto = datapath.ofproto #openflow protocol constants
        parser = datapath.ofproto_parser #classes for constructing openflow messages
        in_port = msg.match['in_port'] #get switch port packet came in on
        #msg.data is the whole frame of data
        pkt = packet.Packet(msg.data) #The parser module peels back the preverbial onion to understand the layers. It reads the first 14 bytes from th frame (the Ethernet header: 6 bytes destination MAC, 6 bytes source MAC, 2 bytes EtherType) and creates an ethernet.ethernet protocol object.hen it looks at the EtherType field to determine what's encapsulated inside.
        #note. Packet is more like a frame than a packet. In RYU, packet referes to a container class ryu uses for parsing layered protocol data, it is not actually a packet as defined by OSI model.
        eth = pkt.get_protocol(ethernet.ethernet) #extracts the layer 2 headers object which has .src, .dst (the MAC addresses), and .ethertype.pkt. Could do get_protocol(ipv4.ipv4) to get the IP layer if there is one, or pkt.get_protocol(tcp.tcp) for TCP. If the frame doesn't contain that protocol, get_protocol returns None.

        if eth is None: #check its not empty
            return

        dst = eth.dst #destination mac address
        src = eth.src #source mac address
        dpid = datapath.id #switch id

        #-------------------------
        #This is the "learning" part. It records: "On switch X, MAC address Y is reachable through port Z."

        self.mac_to_port.setdefault(dpid, {}) #The first time a switch sends a packet in, self.mac_to_port is empty. This line says if the key dpid doesnt already exist in the dictionary self.mac_to_port, create it with an empty dictionary as its value.
        self.mac_to_port[dpid][src] = in_port # Learn the source MAC address to avoid flooding next time. (nested dictionary entry switch id, src mac as keys and in_port as value)
        #Flooding means "send out on every port except the one it came in on"
        # Look up the destination MAC
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            # Unknown destination — flood.
            out_port = ofproto.OFPP_FLOOD #sets out port to flood
        
        actions = [parser.OFPActionOutput(out_port)] #creates list of action messages, containing a single instruction (OFPActionOutput - send packet out a port)

        # If we know the destination, install a flow rule so future packets in this flow bypass the controller.
        

        if out_port != ofproto.OFPP_FLOOD: #if we are not flooding
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src) #create match object where it matches src mac, dst mac, port packet came in on
            self._add_flow(datapath, 1, match, actions, idle_timeout=300) #call helper function to add flow rule to OVS switch

        # Send this packet out.
        # OFP_NO_BUFFER = (0xFFFFFFFF)
        # if ovs did not buffer the packet (sent the entire frame to ryu inside msg.data) we need to send the whole frame back because ovs doesnt have a copy anymore
        # If OVS did buffer the packet (buffer_id is some actual ID): OVS kept the frame stored locally in a buffer on the switch and only sent the header up to Ryu, so we dont need to put anything in msg.data
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None 
        # OFPPacketOut is a one shot instruction "send this packet out with these actions" (actions are always wrapped in instructions)
        out = parser.OFPPacketOut( #construct openflow message
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data,
        )
        datapath.send_msg(out) #send the message to OVS


    #constructs and sends a flow-mod message.
    #table is not defined in mod message so defaults to table 0
    #cookie is not defined in mod message so defaults to 0
    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        """Helper to install a flow rule."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions( #create a list of messages. OFPInstructionActions is a flow instruction, this instruction writes/applies/clears the actions.
            ofproto.OFPIT_APPLY_ACTIONS, actions #accepts type, actions. Here type = OFPIT_APPLY_ACTIONS (execute the action immediately at this point in the pipeline, the actions are not saved).
        )] 
        #other types are:
        #OFPIT_WRITE_ACTIONS - adds the actions to the packets action set (which is like a to do list), these actions only get execute later when the packet has finished passing through all flow tables.
        #OFPIT_CLEAR_ACTIONS - wipes the action set clean.
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)
    #to send packets to a different table you would include a GoToTable instruction in a rules ations (actions = [parser.OFPInstructionGotoTable(1)])
    #a cookie is an opaque identifier that the controller attaches to a flow rule. OVS doesn't use it for matching or forwarding at all. It's purely for the controller's own bookkeeping.
    #for example if we had lots of flow rules we could catagorize them (e.g. micro-segmentation, device isolation) and apply specific cookie values to each category
    #then if we wanted to remove all rules in a specific category we can reference the cookie
