"""
IoT Security Gateway - SDN Policy Application
Phase 2: Micro-segmentation (POL-01) + Essential Services (POL-05)

This application replaces the learning switch with a security-focused
policy engine. It installs proactive OpenFlow rules that enforce:

  1. Default deny - all traffic is dropped unless explicitly allowed
  2. Micro-segmentation - IoT devices cannot communicate with each other
  3. Essential services - DHCP, DNS, and NTP are universally permitted
  4. General WAN access - devices can reach the internet via the gateway
     (this will be replaced by per-device allowlists in Phase 3)

The app discovers OVS port numbers dynamically so it does not depend
on hardcoded port numbers.

Flow Rule Priority Scheme:
    0   - Table-miss (send to controller, safety net)
    1   - Default deny (drop everything not explicitly allowed)
    50  - General WAN access (temporary, replaced in Phase 3)
    150 - Anti-lateral-movement (block IoT-to-IoT via gateway routing)
    200 - Essential services (DHCP, DNS, NTP, ARP)
    500 - Per-device allowlists (Phase 3, not yet implemented)
    65535 - Dynamic isolation (Phase 4, not yet implemented)
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
import json
import logging
from webob import Response
from datetime import datetime, timezone

LOG = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────
# Adjust these to match the network environment.

GATEWAY_IP = "192.168.50.1"
IOT_SUBNET = "192.168.50.0"
IOT_SUBNET_MASK = "255.255.255.0"

# The WiFi interface name on the OVS bridge. IoT devices connect
# through this interface. The app discovers the port number at
# runtime by matching this name in the port description reply.
WIFI_INTERFACE = "wlp3s0"

# ── Priority Levels ───────────────────────────────────────────
# Higher number = higher priority = matched first in OVS.

PRI_TABLE_MISS = 0          # Safety net: send unmatched to controller
PRI_DEFAULT_DENY = 1        # Drop everything not explicitly allowed
PRI_WAN_ACCESS = 50         # General internet access (Phase 2 only)
PRI_ANTI_LATERAL = 150      # Block IoT-to-IoT via gateway routing
PRI_ESSENTIAL = 200         # DHCP, DNS, NTP, ARP
PRI_DEVICE_ALLOW = 500      # Per-device allowlists (Phase 3)
PRI_ISOLATE = 65535         # Dynamic device isolation (Phase 4)


# ── REST API Configuration ────────────────────────────────────

POLICY_API_INSTANCE = "gateway_policy_app" #dictionary key for GatewayPolicy
BASE_URL = "/policy"

# GatewayPolicyController = REST API CLASS. Standard web controller that handles http requests.
# Exposes 4 endpoints: 
# GET /policy/status returns the current state of the engine (is the switch connected, how many rules, how many devices)
# GET /policy/devices returns every MAC address that's been seen on the WiFi port
# POST /policy/isolate takes a MAC address in a JSON body and installs drop rules to quarantine that device
# POST /policy/release removes the quarantine rules for a device

class GatewayPolicyController(ControllerBase):
    """REST API controller for the gateway policy app."""

    def __init__(self, req, link, data, **config): #Ryu's WGSI framework calls this constructor automatically each time an HTTP request comes in.
        super().__init__(req, link, data, **config) #A new instance of GatewayPolicyController is created for each request.
        ##req = http req object. 
        #link = ryus internals routing info that maps URLS to handler methods.
        #data = instance of the class GatewayPolicy
        self.app = data[POLICY_API_INSTANCE] #get an instance of the GatewayPolicy

    @route("policy", BASE_URL + "/status", methods=["GET"])
    def get_status(self, req, **kwargs):
        """Return the current policy engine status."""
        body = json.dumps(self.app.get_status(), indent=2)
        return Response(content_type="application/json", charset="utf-8", body=body)

    @route("policy", BASE_URL + "/devices", methods=["GET"])
    def get_devices(self, req, **kwargs):
        """Return the list of known devices (MACs seen on the WiFi port)."""
        body = json.dumps(self.app.get_known_devices(), indent=2)
        return Response(content_type="application/json", charset="utf-8", body=body)

    @route("policy", BASE_URL + "/isolate", methods=["POST"])
    def isolate_device(self, req, **kwargs):
        """Isolate a device by MAC address (Phase 4 implementation)."""
        try:
            body = json.loads(req.body)
            mac = body.get("mac", "").lower()
            reason = body.get("reason") or "API request (no reason provided)"
        except (ValueError, AttributeError):
            return Response(status=400, charset="utf-8", body="Invalid JSON")

        if not mac:
            return Response(status=400, charset="utf-8", body='Missing "mac" field')

        result = self.app.isolate_device(mac, reason)
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result, indent=2),
        )

    @route("policy", BASE_URL + "/release", methods=["POST"])
    def release_device(self, req, **kwargs):
        """Release a previously isolated device (Phase 4 implementation)."""
        try:
            body = json.loads(req.body)
            mac = body.get("mac", "").lower()
        except (ValueError, AttributeError):
            return Response(status=400, charset="utf-8", body="Invalid JSON")

        if not mac:
            return Response(status=400, charset="utf-8", body='Missing "mac" field')

        result = self.app.release_device(mac)
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result, indent=2),
        )


class GatewayPolicy(app_manager.RyuApp):
    """
    SDN policy engine for the IoT security gateway.

    On switch connection, this app installs proactive flow rules that
    implement micro-segmentation and essential service access. It does
    not use reactive (packet-in driven) rule installation for normal
    traffic, which keeps the controller out of the fast path.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION] #tells ryu what open flow protocol is used
    _CONTEXTS = {"wsgi": WSGIApplication} # tells ryu that this app needs the WGSI web server (ryu only creates one instace of it, and passes it to every app that needs it). Ryu injects it via kwargs["wsgi"] in the constructor, and the controller class is registered against it

    def __init__(self, *args, **kwargs): #gathers the positional arguments passed in into a tuple* and a dictionary**
        super().__init__(*args, **kwargs) #call the app_manager.RyuApp constructor which registers the app with Ryus event system, sets up the OpenFlow protocol handler, initialises the WSGI context, and wires up the event dispatcher that makes the @set_ev_cls decorators work.

        # Register the REST API.
        wsgi = kwargs["wsgi"]
        # wsgi.register(controller, data) integrates the customer rest api controller 'GatewayPolicyController' with ryus built in Web Server Gateway Interface (wsgi) 
        # controller = the rest api controler , data = a dictionary for putting important information in that the controller will need, in this case we use it to pass the policy app
        # {POLICY_API_INSTANCE: self} == {'gateway_policy_app': GatewayPolicy} - puts the gateway policy in the 'data' variable
        # ryu will pass 'data' into the controller constructor each time an api request is made
        wsgi.register(GatewayPolicyController, {POLICY_API_INSTANCE: self}) 

        # State tracking.
        self.datapath = None            # The connected OVS switch
        self.wifi_port = None           # Port number for the WiFi interface
        self.rules_installed = False    # Whether proactive rules are in place
        self.known_devices = {}         # {mac: {"first_seen": ts, "last_seen": ts}}
        self.isolated_devices = {}      # {mac: {"since": ts, "reason": str}}
        self.connect_time = None        # When the switch connected
        self.rule_count = 0             # Number of proactive rules installed

    # ── REST API data methods ─────────────────────────────────

    def get_status(self):
        return {
            "switch_connected": self.datapath is not None,
            "switch_dpid": self.datapath.id if self.datapath else None,
            "wifi_port": self.wifi_port,
            "wifi_interface": WIFI_INTERFACE,
            "rules_installed": self.rules_installed,
            "rule_count": self.rule_count,
            "known_devices": len(self.known_devices),
            "isolated_devices": len(self.isolated_devices),
            "connect_time": self.connect_time,
            "gateway_ip": GATEWAY_IP,
            "iot_subnet": f"{IOT_SUBNET}/{IOT_SUBNET_MASK}",
        }

    def get_known_devices(self):
        return {
            "devices": self.known_devices,
            "total": len(self.known_devices),
        }

    def isolate_device(self, mac, reason="API request (no reason provided)"):
        """Install a max-priority DROP rule for all traffic from this MAC."""
        if not self.datapath or not self.wifi_port:
            return {"success": False, "error": "Switch not connected"}

        if mac in self.isolated_devices:
            return {"success": False, "error": f"{mac} is already isolated"}

        dp = self.datapath
        parser = dp.ofproto_parser

        # Drop all traffic from this MAC address.
        match = parser.OFPMatch(in_port=self.wifi_port, eth_src=mac)
        self._add_flow(dp, PRI_ISOLATE, match, actions=[], tag="isolate")

        # Also drop all traffic TO this MAC address (responses).
        match_to = parser.OFPMatch(in_port=dp.ofproto.OFPP_LOCAL, eth_dst=mac)
        self._add_flow(dp, PRI_ISOLATE, match_to, actions=[], tag="isolate")

        ts = datetime.now(timezone.utc).isoformat()
        self.isolated_devices[mac] = {"since": ts, "reason": reason}
        LOG.warning("ISOLATED device %s at %s - reason: %s", mac, ts, reason)

        return {"success": True, "mac": mac, "isolated_at": ts}

    def release_device(self, mac):
        """Remove isolation rules for a device, restoring normal policy."""
        if not self.datapath:
            return {"success": False, "error": "Switch not connected"}

        if mac not in self.isolated_devices:
            return {"success": False, "error": f"{mac} is not isolated"}

        dp = self.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        # Delete the isolation rules by sending flow-delete for the specific matches at isolation priority.

        match_from = parser.OFPMatch(in_port=self.wifi_port, eth_src=mac) #release traffic from this MAC address
        self._delete_flow(dp, PRI_ISOLATE, match_from)

        match_to = parser.OFPMatch(in_port=ofproto.OFPP_LOCAL, eth_dst=mac) #release traffic to this MAC address
        self._delete_flow(dp, PRI_ISOLATE, match_to)

        del self.isolated_devices[mac]
        LOG.info("RELEASED device %s from isolation", mac)

        return {"success": True, "mac": mac}

    # ── OpenFlow Event Handlers ───────────────────────────────

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER) #Step 1 - Called when a switch connects
    def switch_features_handler(self, ev):
        """Called when a switch connects. Request port descriptions.""" 
        # Every time OVS restarts or ports are added/removed, port numbers can change so we must ask ovs "tell me about all your ports, their names and numbers")
        datapath = ev.msg.datapath
        self.datapath = datapath
        self.connect_time = datetime.now(timezone.utc).isoformat()
        LOG.info(
            "Switch %s connected. Requesting port descriptions...",
            datapath.id,
        )

        # Request port descriptions so port numbers can be discovered by interface name rather than hardcoding them.
        
        parser = datapath.ofproto_parser
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER) #Step 2 - Called when OVS responds with the port list
    def port_desc_reply_handler(self, ev):
        """
        Called when OVS responds with port descriptions. 
        Used to discover the port number for the Wi-Fi interface, 
        then install all the proactive security rules.
        """
        ports = {}
        for port in ev.msg.body:
            name = port.name
            if isinstance(name, bytes):
                name = name.decode("utf-8").rstrip("\x00")
            ports[name] = port.port_no
            LOG.info("Port discovered: %s = %d", name, port.port_no)

        if WIFI_INTERFACE not in ports:
            LOG.error(
                "WiFi interface '%s' not found on OVS bridge. "
                "Available ports: %s. Check WIFI_INTERFACE in the config.",
                WIFI_INTERFACE,
                list(ports.keys()),
            )
            return

        self.wifi_port = ports[WIFI_INTERFACE]
        LOG.info(
            "WiFi port resolved: %s = port %d", WIFI_INTERFACE, self.wifi_port
        )

        self._install_all_rules(ev.msg.datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER) #Called when a 'packet' hits the controller
    def packet_in_handler(self, ev):
        """
        Handle packets that reach the controller (table-miss).

        With proactive rules installed, the only packets that reach
        here are those not matching any rule (which should be dropped).
        This handler is used to track device MACs and log dropped traffic for debugging.
        """
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        src_mac = eth.src
        in_port = msg.match["in_port"] #note. this refers to the switch port

        # Track devices seen on the WiFi port.
        if in_port == self.wifi_port and src_mac != "ff:ff:ff:ff:ff:ff":
            now = datetime.now(timezone.utc).isoformat()
            if src_mac not in self.known_devices:
                self.known_devices[src_mac] = {
                    "first_seen": now,
                    "last_seen": now,
                }
                LOG.info("New device detected: %s on port %d", src_mac, in_port)
            else:
                self.known_devices[src_mac]["last_seen"] = now

        # Log what is being dropped (at DEBUG level to avoid noise).
        LOG.debug(
            "Packet-in (dropped by default deny): "
            "in_port=%d src=%s dst=%s type=0x%04x",
            in_port, eth.src, eth.dst, eth.ethertype,
        )

    # ── Rule Installation ─────────────────────────────────────

    def _install_all_rules(self, datapath):
        """
        Install the complete set of proactive flow rules.
        Called once when the switch connects and ports are discovered.
        """
        self.rule_count = 0
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        wifi = self.wifi_port
        local = ofproto.OFPP_LOCAL

        LOG.info("Installing security policy rules...")

        # ── 1. Table-miss: send to controller (priority 0) ────
        # Safety net. In practice, the default deny rule at priority 1
        # catches everything first. This only fires if there is no
        # other rule at all (e.g., during rule installation).
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, PRI_TABLE_MISS, match, actions, tag="table-miss")

        # ── 2. Default deny: drop everything (priority 1) ─────
        # POL-01: This is the micro-segmentation backbone. Any traffic
        # not explicitly permitted by a higher-priority rule is dropped.
        # Lateral movement between IoT devices is blocked because there
        # are no rules that forward traffic from the WiFi port back to
        # itself.
        match = parser.OFPMatch()
        self._add_flow(datapath, PRI_DEFAULT_DENY, match, actions=[], tag="default-deny")

        # ── 3. ARP: allow in both directions (priority 200) ───
        # ARP is required for basic L2 operation. Without it, devices
        # cannot resolve the gateway's MAC address and no IP traffic
        # works at all. Only ARP between devices and the gateway is
        # permitted (not device-to-device, since those frames would
        # need to go from WiFi port back to WiFi port, which no rule
        # allows).
        match = parser.OFPMatch(in_port=wifi, eth_type=0x0806) #eth_type=0x0806 = ARP frame
        actions = [parser.OFPActionOutput(local)] 
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="arp-to-gw")

        match = parser.OFPMatch(in_port=local, eth_type=0x0806)
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="arp-from-gw")

        # ── 4. DHCP: requests and responses (priority 200) ────
        # POL-05: DHCP is an essential service. Requests (UDP dst 67)
        # go from devices to the gateway where dnsmasq handles them.
        # Responses (UDP dst 68) go from the gateway back to devices.
        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800, #eth_type=0x0800 = IPv4
            ip_proto=17, udp_dst=67, #ip_proto=17 = UDP
        )
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dhcp-request")

        match = parser.OFPMatch(
            in_port=local, eth_type=0x0800,
            ip_proto=17, udp_dst=68,
        )
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dhcp-response")

        # ── 5. DNS: queries and responses (priority 200) ──────
        # POL-05: DNS is an essential service. Queries go to the
        # gateway IP (192.168.50.1) which maps to AdGuard Home via
        # Docker port mapping. Responses come back from the gateway.
        # Only DNS to the gateway is permitted; direct DNS to external
        # servers is blocked (and intercepted by nftables DNAT anyway).

        # DNS UDP query
        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800, #eth_type=0x0800 = IPv4
            ip_proto=17, udp_dst=53, ipv4_dst=GATEWAY_IP, #ip_proto=17 = UDP
        )
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dns-udp-query")

        # DNS TCP query
        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800,
            ip_proto=6, tcp_dst=53, ipv4_dst=GATEWAY_IP, #ip_proto=6 = TCP
        )
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dns-tcp-query")

        # DNS UDP response
        match = parser.OFPMatch(
            in_port=local, eth_type=0x0800,
            ip_proto=17, udp_src=53, ipv4_src=GATEWAY_IP,
        )
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dns-udp-response")

        # DNS TCP response
        match = parser.OFPMatch(
            in_port=local, eth_type=0x0800,
            ip_proto=6, tcp_src=53, ipv4_src=GATEWAY_IP,
        )
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dns-tcp-response")

        # ── 6. NTP: queries and responses (priority 200) ──────
        # POL-05: NTP is an essential service. IoT devices need
        # accurate time for TLS certificate validation, scheduled
        # operations, and logging. For now, UDP 123 to any destination
        # is allowed. This can be tightened to specific NTP server IPs
        # in a future hardening pass.
        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800,
            ip_proto=17, udp_dst=123,
        )
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="ntp-query")

        match = parser.OFPMatch(
            in_port=local, eth_type=0x0800,
            ip_proto=17, udp_src=123,
        )
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="ntp-response")

        # ── 7. Anti-lateral-movement (priority 150) ───────────
        # POL-01: Even though the default deny blocks direct
        # device-to-device frames (which would need WiFi->WiFi
        # forwarding), a device could try to route traffic to another
        # IoT device through the gateway. The gateway's IP stack would
        # see the destination is on the local subnet and forward it.
        #
        # This rule catches that case: any IPv4 traffic from the WiFi
        # port destined for the IoT subnet is dropped. This has lower
        # priority than the essential services rules, so DHCP/DNS/NTP
        # to the gateway (192.168.50.1) still works because those
        # rules match at priority 200 before this rule is evaluated.
        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800,
            ipv4_dst=(IOT_SUBNET, IOT_SUBNET_MASK),
        )
        self._add_flow(datapath, PRI_ANTI_LATERAL, match, actions=[], tag="anti-lateral")

        # ── 8. General WAN access (priority 50) ──────────────
        # This permits IoT devices to reach the internet via the
        # gateway. Traffic from devices goes to LOCAL (the host IP
        # stack), which NATs it out via enp2s0. Return traffic from
        # LOCAL goes back to the WiFi port.
        #
        # Phase 3 will replace these two rules with per-device
        # allowlists at priority 500 that restrict each device to
        # its approved external destinations. Until then, any device
        # can reach any external IP.
        match = parser.OFPMatch(in_port=wifi, eth_type=0x0800)
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_WAN_ACCESS, match, actions, tag="wan-outbound")

        match = parser.OFPMatch(in_port=local, eth_type=0x0800)
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_WAN_ACCESS, match, actions, tag="wan-inbound")

        # ── Log Rule Installs ──────────────────────────────────────────────

        self.rules_installed = True
        LOG.info(
            "Policy rules installed: %d rules. "
            "Micro-segmentation is ACTIVE. "
            "Essential services (DHCP, DNS, NTP) are PERMITTED. "
            "General WAN access is PERMITTED (Phase 3 will restrict this).",
            self.rule_count,
        )

    # ── Helpers ───────────────────────────────────────────────

    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0, tag=""):
        """Install a flow rule in OVS."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions
        )]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)
        self.rule_count += 1
        if tag:
            LOG.debug("  Rule [%s] installed at priority %d", tag, priority)

    def _delete_flow(self, datapath, priority, match):
        """Delete a specific flow rule from OVS."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE_STRICT,
            priority=priority,
            match=match,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            instructions=[],
        )
        datapath.send_msg(mod)
        LOG.debug("  Rule deleted at priority %d", priority)
