"""
IoT Security Gateway - SDN Policy Application
Phase 3: Per-Device Destination Allowlists (POL-02)

Builds on Phase 2 (micro-segmentation + essential services) by adding
per-device destination allowlists. Each IoT device can be assigned a
profile that restricts its WAN access to a set of approved IP ranges
and domain names.

The app operates in one of two modes:
  - "learning": General WAN access rules (priority 50) remain active
    for all devices. This is the baseline collection period where I
    use Zeek logs to profile device traffic and build allowlists. No
    traffic is blocked beyond what Phase 2 already blocks.
  - "enforcing": For devices that have an allowlist profile, the
    general WAN rules are bypassed. Only traffic to allowed
    destinations passes. Devices without profiles still get general
    WAN access (so I can add profiles incrementally without breaking
    un-profiled devices).

Device profiles are loaded from a JSON config file that is mounted
into the container. The config can be reloaded at runtime via the
REST API without restarting Ryu.

Flow Rule Priority Scheme (updated for Phase 3):
    0     - Table-miss (send to controller, safety net)
    1     - Default deny (drop everything not explicitly allowed)
    50    - General WAN access (active for un-profiled devices)
    100   - Per-device WAN intercept (send to controller for evaluation)
            and per-device inbound deny (block un-allowed return traffic)
    150   - Anti-lateral-movement (block IoT-to-IoT via gateway routing)
    200   - Essential services (DHCP, DNS, NTP, ARP)
    500   - Per-device allowlist entries (reactive, installed on first
            matching packet, with idle timeout)
    65535 - Dynamic isolation (Phase 4)
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
import os
import struct
import socket
import time
from webob import Response
from datetime import datetime, timezone

LOG = logging.getLogger(__name__)

# -- Configuration ----------------------------------------------------------
# Adjust these to match the network environment.

GATEWAY_IP = "192.168.50.1"
IOT_SUBNET = "192.168.50.0"
IOT_SUBNET_MASK = "255.255.255.0"

# The WiFi interface name on the OVS bridge. IoT devices connect
# through this interface. The app discovers the port number at
# runtime by matching this name in the port description reply.
WIFI_INTERFACE = "wlp3s0"

# Path to the device profiles config file inside the container.
# This is mounted from the host via docker-compose.
DEVICE_PROFILES_PATH = os.environ.get(
    "DEVICE_PROFILES_PATH",
    "/opt/ryu/config/device_profiles.json",
)

# -- Priority Levels --------------------------------------------------------
# Higher number = higher priority = matched first in OVS.

PRI_TABLE_MISS = 0          # Safety net: send unmatched to controller
PRI_DEFAULT_DENY = 1        # Drop everything not explicitly allowed
PRI_WAN_ACCESS = 50         # General internet access (un-profiled devices)
PRI_DEVICE_INTERCEPT = 100  # Per-device WAN intercept/deny (profiled devices)
PRI_ANTI_LATERAL = 150      # Block IoT-to-IoT via gateway routing
PRI_ESSENTIAL = 200         # DHCP, DNS, NTP, ARP
PRI_DEVICE_ALLOW = 500      # Per-device allowlist entries (reactive)
PRI_ISOLATE = 65535         # Dynamic device isolation (Phase 4)

# Default idle timeout for reactive allowlist flow rules (seconds).
# When no matching traffic flows for this duration, OVS removes the
# rule automatically. The next packet triggers a new controller
# evaluation. This keeps the flow table clean and allows the DNS
# cache to stay current.
DEFAULT_IDLE_TIMEOUT = 300

# -- REST API Configuration -------------------------------------------------

POLICY_API_INSTANCE = "gateway_policy_app"
BASE_URL = "/policy"


# -- Helper: CIDR matching --------------------------------------------------

def ip_to_int(ip_str):
    """Convert dotted-quad IP string to a 32-bit integer."""
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


def cidr_contains(cidr_str, ip_str):
    """Check whether ip_str falls within the CIDR range cidr_str."""
    if "/" in cidr_str:
        network, prefix_len = cidr_str.split("/")
        prefix_len = int(prefix_len)
    else:
        network = cidr_str
        prefix_len = 32

    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return (ip_to_int(network) & mask) == (ip_to_int(ip_str) & mask)


# -- REST API Controller ----------------------------------------------------
# Exposes endpoints for policy status, device management, allowlist
# management, and DNS cache updates.
#
# Phase 2 endpoints (unchanged):
#   GET  /policy/status        - engine state
#   GET  /policy/devices       - known MACs on the WiFi port
#   POST /policy/isolate       - quarantine a device by MAC
#   POST /policy/release       - remove quarantine
#
# Phase 3 endpoints (new):
#   GET  /policy/allowlists            - current device profiles and mode
#   POST /policy/allowlists/reload     - reload profiles from config file
#   POST /policy/allowlists/mode       - switch between learning/enforcing
#   POST /policy/dns-cache             - update domain-to-IP mappings
#   GET  /policy/dns-cache             - view current DNS cache
#   GET  /policy/denied-log            - recent denied connection attempts

class GatewayPolicyController(ControllerBase):
    """REST API controller for the gateway policy app."""

    def __init__(self, req, link, data, **config):
        super().__init__(req, link, data, **config)
        self.app = data[POLICY_API_INSTANCE]

    # -- Phase 2 endpoints (unchanged) --

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
        """Isolate a device by MAC address."""
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
        """Release a previously isolated device."""
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

    # -- Phase 3 endpoints (new) --

    @route("policy", BASE_URL + "/allowlists", methods=["GET"])
    def get_allowlists(self, req, **kwargs):
        """Return the current device profiles and enforcement mode."""
        body = json.dumps(self.app.get_allowlists(), indent=2)
        return Response(content_type="application/json", charset="utf-8", body=body)

    @route("policy", BASE_URL + "/allowlists/reload", methods=["POST"])
    def reload_allowlists(self, req, **kwargs):
        """Reload device profiles from the config file on disk."""
        result = self.app.reload_profiles()
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result, indent=2),
        )

    @route("policy", BASE_URL + "/allowlists/mode", methods=["POST"])
    def set_mode(self, req, **kwargs):
        """Switch between learning and enforcing mode."""
        try:
            body = json.loads(req.body)
            mode = body.get("mode", "").lower()
        except (ValueError, AttributeError):
            return Response(status=400, charset="utf-8", body="Invalid JSON")

        if mode not in ("learning", "enforcing"):
            return Response(
                status=400, charset="utf-8",
                body='Invalid mode. Must be "learning" or "enforcing".',
            )

        result = self.app.set_enforcement_mode(mode)
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result, indent=2),
        )

    @route("policy", BASE_URL + "/dns-cache", methods=["POST"])
    def update_dns_cache(self, req, **kwargs):
        """
        Update the DNS cache with domain-to-IP mappings.

        Expected JSON body:
        {
            "mappings": {
                "api.vendor.com": ["203.0.113.50", "203.0.113.51"],
                "cloud.vendor.com": ["198.51.100.10"]
            }
        }
        """
        try:
            body = json.loads(req.body)
            mappings = body.get("mappings", {})
        except (ValueError, AttributeError):
            return Response(status=400, charset="utf-8", body="Invalid JSON")

        if not mappings:
            return Response(
                status=400, charset="utf-8",
                body='Missing or empty "mappings" field',
            )

        result = self.app.update_dns_cache(mappings)
        return Response(
            content_type="application/json",
            charset="utf-8",
            body=json.dumps(result, indent=2),
        )

    @route("policy", BASE_URL + "/dns-cache", methods=["GET"])
    def get_dns_cache(self, req, **kwargs):
        """Return the current DNS cache contents."""
        body = json.dumps(self.app.get_dns_cache(), indent=2)
        return Response(content_type="application/json", charset="utf-8", body=body)

    @route("policy", BASE_URL + "/denied-log", methods=["GET"])
    def get_denied_log(self, req, **kwargs):
        """Return recent denied connection attempts from profiled devices."""
        body = json.dumps(self.app.get_denied_log(), indent=2)
        return Response(content_type="application/json", charset="utf-8", body=body)


class GatewayPolicy(app_manager.RyuApp):
    """
    SDN policy engine for the IoT security gateway.

    On switch connection, this app installs proactive flow rules that
    implement micro-segmentation and essential service access (Phase 2),
    plus per-device allowlist enforcement (Phase 3).
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Register the REST API.
        wsgi = kwargs["wsgi"]
        wsgi.register(GatewayPolicyController, {POLICY_API_INSTANCE: self})

        # -- State tracking (Phase 2, unchanged) --
        self.datapath = None
        self.wifi_port = None
        self.rules_installed = False
        self.known_devices = {}         # {mac: {"first_seen": ts, "last_seen": ts}}
        self.isolated_devices = {}      # {mac: {"since": ts, "reason": str}}
        self.connect_time = None
        self.rule_count = 0

        # -- Phase 3 state --
        self.device_profiles = {}       # {mac: {name, allowed_domains, allowed_cidrs}}
        self.enforcement_mode = "learning"
        self.idle_timeout = DEFAULT_IDLE_TIMEOUT
        self.dns_cache = {}             # {domain: {"ips": [...], "updated": ts}}
        self.denied_log = []            # List of recent denied attempts (capped)
        self.denied_log_max = 500       # Keep the last 500 entries
        self.active_allowlist_rules = {}  # {mac: set of dest IPs with active rules}

        # Load device profiles from config file on startup.
        self._load_profiles_from_file()

    # -- Profile loading ----------------------------------------------------

    def _load_profiles_from_file(self):
        """Load device profiles from the JSON config file."""
        if not os.path.exists(DEVICE_PROFILES_PATH):
            LOG.info(
                "No device profiles config found at %s. "
                "Starting with empty profiles (all devices get general WAN access).",
                DEVICE_PROFILES_PATH,
            )
            return

        try:
            with open(DEVICE_PROFILES_PATH, "r") as f:
                config = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            LOG.error("Failed to load device profiles from %s: %s", DEVICE_PROFILES_PATH, e)
            return

        # Parse the config.
        self.enforcement_mode = config.get("mode", "learning")
        self.idle_timeout = config.get("idle_timeout", DEFAULT_IDLE_TIMEOUT)

        devices = config.get("devices", {})
        self.device_profiles = {}
        for mac, profile in devices.items():
            mac = mac.lower()
            self.device_profiles[mac] = {
                "name": profile.get("name", "Unknown"),
                "manufacturer": profile.get("manufacturer", "Unknown"),
                "allowed_domains": [d.lower() for d in profile.get("allowed_domains", [])],
                "allowed_cidrs": profile.get("allowed_cidrs", []),
            }

        LOG.info(
            "Loaded %d device profiles from %s. Mode: %s. Idle timeout: %ds.",
            len(self.device_profiles),
            DEVICE_PROFILES_PATH,
            self.enforcement_mode,
            self.idle_timeout,
        )

    # -- REST API data methods (Phase 2, unchanged) -------------------------

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
            # Phase 3 additions to status.
            "enforcement_mode": self.enforcement_mode,
            "profiled_devices": len(self.device_profiles),
            "dns_cache_entries": len(self.dns_cache),
            "denied_log_size": len(self.denied_log),
        }

    def get_known_devices(self):
        # Augment the device list with profile status.
        devices = {}
        for mac, info in self.known_devices.items():
            entry = dict(info)
            entry["has_profile"] = mac in self.device_profiles
            if mac in self.device_profiles:
                entry["profile_name"] = self.device_profiles[mac]["name"]
            entry["is_isolated"] = mac in self.isolated_devices
            devices[mac] = entry
        return {
            "devices": devices,
            "total": len(devices),
        }

    def isolate_device(self, mac, reason="API request (no reason provided)"):
        """Install a max-priority DROP rule for all traffic from this MAC."""
        if not self.datapath or not self.wifi_port:
            return {"success": False, "error": "Switch not connected"}

        if mac in self.isolated_devices:
            return {"success": False, "error": f"{mac} is already isolated"}

        dp = self.datapath
        parser = dp.ofproto_parser

        match = parser.OFPMatch(in_port=self.wifi_port, eth_src=mac)
        self._add_flow(dp, PRI_ISOLATE, match, actions=[], tag="isolate")

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

        match_from = parser.OFPMatch(in_port=self.wifi_port, eth_src=mac)
        self._delete_flow(dp, PRI_ISOLATE, match_from)

        match_to = parser.OFPMatch(in_port=ofproto.OFPP_LOCAL, eth_dst=mac)
        self._delete_flow(dp, PRI_ISOLATE, match_to)

        del self.isolated_devices[mac]
        LOG.info("RELEASED device %s from isolation", mac)

        return {"success": True, "mac": mac}

    # -- REST API data methods (Phase 3, new) -------------------------------

    def get_allowlists(self):
        """Return the current device profiles and mode."""
        profiles_summary = {}
        for mac, profile in self.device_profiles.items():
            profiles_summary[mac] = {
                "name": profile["name"],
                "manufacturer": profile["manufacturer"],
                "allowed_domains": profile["allowed_domains"],
                "allowed_cidrs": profile["allowed_cidrs"],
                "active_rules": len(self.active_allowlist_rules.get(mac, set())),
            }
        return {
            "mode": self.enforcement_mode,
            "idle_timeout": self.idle_timeout,
            "profiles": profiles_summary,
            "total_profiles": len(self.device_profiles),
        }

    def reload_profiles(self):
        """Reload profiles from the config file and re-apply enforcement rules."""
        old_mode = self.enforcement_mode
        old_profiles = set(self.device_profiles.keys())

        self._load_profiles_from_file()

        new_profiles = set(self.device_profiles.keys())
        added = new_profiles - old_profiles
        removed = old_profiles - new_profiles

        # If the switch is connected, update the enforcement rules.
        if self.datapath and self.wifi_port:
            # Remove intercept rules for devices no longer profiled.
            for mac in removed:
                self._remove_device_intercept_rules(mac)

            # If mode changed or profiles changed, re-apply.
            if self.enforcement_mode == "enforcing":
                for mac in new_profiles:
                    self._install_device_intercept_rules(mac)
            elif old_mode == "enforcing":
                # Switched from enforcing to learning: remove all intercept rules.
                for mac in old_profiles:
                    self._remove_device_intercept_rules(mac)

        return {
            "success": True,
            "mode": self.enforcement_mode,
            "total_profiles": len(self.device_profiles),
            "added": list(added),
            "removed": list(removed),
        }

    def set_enforcement_mode(self, mode):
        """Switch between learning and enforcing mode."""
        if mode == self.enforcement_mode:
            return {"success": True, "mode": mode, "message": "Already in this mode"}

        old_mode = self.enforcement_mode
        self.enforcement_mode = mode

        if not self.datapath or not self.wifi_port:
            return {
                "success": True,
                "mode": mode,
                "message": "Mode set. Rules will be applied when the switch reconnects.",
            }

        if mode == "enforcing":
            # Install per-device intercept rules for all profiled devices.
            count = 0
            for mac in self.device_profiles:
                self._install_device_intercept_rules(mac)
                count += 1
            LOG.info(
                "Switched to ENFORCING mode. Installed intercept rules for %d devices.",
                count,
            )
            return {
                "success": True,
                "mode": mode,
                "message": f"Enforcing mode active. {count} devices have intercept rules.",
            }
        else:
            # Remove per-device intercept rules (back to learning mode).
            count = 0
            for mac in self.device_profiles:
                self._remove_device_intercept_rules(mac)
                count += 1
            # Also remove any reactive allowlist rules that were installed.
            self._flush_allowlist_rules()
            LOG.info(
                "Switched to LEARNING mode. Removed intercept rules for %d devices.",
                count,
            )
            return {
                "success": True,
                "mode": mode,
                "message": f"Learning mode active. {count} devices returned to general WAN access.",
            }

    def update_dns_cache(self, mappings):
        """
        Update the DNS cache with domain-to-IP mappings.

        Called by an external process (e.g., the dns_cache_updater script)
        that monitors AdGuard/Zeek DNS logs and pushes resolved IPs here.
        """
        ts = datetime.now(timezone.utc).isoformat()
        updated = 0
        for domain, ips in mappings.items():
            domain = domain.lower()
            self.dns_cache[domain] = {
                "ips": list(ips),
                "updated": ts,
            }
            updated += 1
        LOG.debug("DNS cache updated: %d domains refreshed", updated)
        return {"success": True, "domains_updated": updated}

    def get_dns_cache(self):
        """Return the current DNS cache."""
        return {
            "cache": self.dns_cache,
            "total_domains": len(self.dns_cache),
        }

    def get_denied_log(self):
        """Return recent denied connection attempts."""
        return {
            "entries": self.denied_log[-100:],  # Return last 100
            "total": len(self.denied_log),
        }

    # -- Allowlist evaluation -----------------------------------------------

    def _is_destination_allowed(self, mac, dst_ip):
        """
        Check whether a profiled device is allowed to reach dst_ip.

        Returns (allowed: bool, reason: str).
        """
        profile = self.device_profiles.get(mac)
        if not profile:
            return True, "no profile (general WAN access)"

        # Check static CIDR allowlist.
        for cidr in profile["allowed_cidrs"]:
            try:
                if cidr_contains(cidr, dst_ip):
                    return True, f"matched CIDR {cidr}"
            except (OSError, ValueError):
                LOG.warning("Invalid CIDR in profile for %s: %s", mac, cidr)
                continue

        # Check domain-based allowlist via the DNS cache.
        for domain in profile["allowed_domains"]:
            cache_entry = self.dns_cache.get(domain)
            if cache_entry and dst_ip in cache_entry["ips"]:
                return True, f"matched domain {domain} (resolved to {dst_ip})"

        return False, f"not in allowlist for {profile['name']}"

    # -- Per-device intercept rules -----------------------------------------

    def _install_device_intercept_rules(self, mac):
        """
        Install rules that intercept WAN traffic from a profiled device
        and send it to the controller for allowlist evaluation.

        Two rules per device:
          1. Outbound intercept (priority 100): IPv4 from this MAC on
             the WiFi port is sent to the controller. The controller
             evaluates it and either installs a priority 500 allow rule
             or drops the packet.
          2. Inbound deny (priority 100): IPv4 to this MAC from LOCAL
             is dropped unless a priority 500 allow rule exists. This
             prevents return traffic from un-allowed destinations.
        """
        if not self.datapath or not self.wifi_port:
            return

        dp = self.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        # Outbound: send this device's WAN traffic to the controller.
        match_out = parser.OFPMatch(
            in_port=self.wifi_port,
            eth_src=mac,
            eth_type=0x0800,
        )
        actions_out = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(
            dp, PRI_DEVICE_INTERCEPT, match_out, actions_out,
            tag=f"intercept-out-{mac[:8]}",
        )

        # Inbound: drop return traffic to this device by default.
        # Allowed return traffic will match at priority 500 instead.
        match_in = parser.OFPMatch(
            in_port=ofproto.OFPP_LOCAL,
            eth_dst=mac,
            eth_type=0x0800,
        )
        self._add_flow(
            dp, PRI_DEVICE_INTERCEPT, match_in, actions=[],
            tag=f"intercept-in-{mac[:8]}",
        )

        LOG.info("Installed intercept rules for profiled device %s", mac)

    def _remove_device_intercept_rules(self, mac):
        """Remove the intercept rules for a device."""
        if not self.datapath or not self.wifi_port:
            return

        dp = self.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        match_out = parser.OFPMatch(
            in_port=self.wifi_port,
            eth_src=mac,
            eth_type=0x0800,
        )
        self._delete_flow(dp, PRI_DEVICE_INTERCEPT, match_out)

        match_in = parser.OFPMatch(
            in_port=ofproto.OFPP_LOCAL,
            eth_dst=mac,
            eth_type=0x0800,
        )
        self._delete_flow(dp, PRI_DEVICE_INTERCEPT, match_in)

        # Also remove any reactive allowlist rules for this device.
        self._flush_device_allowlist_rules(mac)

        LOG.info("Removed intercept rules for device %s", mac)

    def _install_allowlist_flow(self, mac, dst_ip):
        """
        Install a bidirectional flow rule pair at priority 500 that
        allows traffic between this device and a specific destination IP.
        Rules have an idle timeout so they expire when the flow goes quiet.
        """
        if not self.datapath or not self.wifi_port:
            return

        dp = self.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        wifi = self.wifi_port
        local = ofproto.OFPP_LOCAL

        # Outbound: device -> destination via gateway.
        match_out = parser.OFPMatch(
            in_port=wifi,
            eth_src=mac,
            eth_type=0x0800,
            ipv4_dst=dst_ip,
        )
        actions_out = [parser.OFPActionOutput(local)]
        self._add_flow(
            dp, PRI_DEVICE_ALLOW, match_out, actions_out,
            idle_timeout=self.idle_timeout,
            tag=f"allow-out-{mac[:8]}->{dst_ip}",
        )

        # Inbound: destination -> device via gateway.
        match_in = parser.OFPMatch(
            in_port=local,
            eth_dst=mac,
            eth_type=0x0800,
            ipv4_src=dst_ip,
        )
        actions_in = [parser.OFPActionOutput(wifi)]
        self._add_flow(
            dp, PRI_DEVICE_ALLOW, match_in, actions_in,
            idle_timeout=self.idle_timeout,
            tag=f"allow-in-{dst_ip}->{mac[:8]}",
        )

        # Track active rules.
        if mac not in self.active_allowlist_rules:
            self.active_allowlist_rules[mac] = set()
        self.active_allowlist_rules[mac].add(dst_ip)

    def _flush_device_allowlist_rules(self, mac):
        """Remove all reactive allowlist rules for a specific device."""
        if not self.datapath:
            return

        dp = self.datapath
        parser = dp.ofproto_parser
        ofproto = dp.ofproto

        active_ips = self.active_allowlist_rules.pop(mac, set())
        for dst_ip in active_ips:
            # Delete outbound rule.
            match_out = parser.OFPMatch(
                in_port=self.wifi_port,
                eth_src=mac,
                eth_type=0x0800,
                ipv4_dst=dst_ip,
            )
            self._delete_flow(dp, PRI_DEVICE_ALLOW, match_out)

            # Delete inbound rule.
            match_in = parser.OFPMatch(
                in_port=ofproto.OFPP_LOCAL,
                eth_dst=mac,
                eth_type=0x0800,
                ipv4_src=dst_ip,
            )
            self._delete_flow(dp, PRI_DEVICE_ALLOW, match_in)

    def _flush_allowlist_rules(self):
        """Remove all reactive allowlist rules for all devices."""
        macs = list(self.active_allowlist_rules.keys())
        for mac in macs:
            self._flush_device_allowlist_rules(mac)

    # -- OpenFlow Event Handlers --------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Called when a switch connects. Request port descriptions."""
        datapath = ev.msg.datapath
        self.datapath = datapath
        self.connect_time = datetime.now(timezone.utc).isoformat()
        LOG.info(
            "Switch %s connected. Requesting port descriptions...",
            datapath.id,
        )

        parser = datapath.ofproto_parser
        req = parser.OFPPortDescStatsRequest(datapath, 0)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_reply_handler(self, ev):
        """
        Called when OVS responds with port descriptions.
        Discovers the WiFi port number, then installs all proactive rules.
        """
        ports = {}
        for port in ev.msg.body:
            name = port.name
            if isinstance(name, bytes):
                name = name.decode("utf-8").rstrip("\x00")
            ports[name] = port.port_no
            LOG.info("  Port discovered: %s = %d", name, port.port_no)

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

        # Reset tracking state on reconnect.
        self.active_allowlist_rules = {}
        self._install_all_rules(ev.msg.datapath)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """
        Handle packets that reach the controller.

        In Phase 2, packet-ins only came from the table-miss rule and
        were used for device tracking and debug logging. In Phase 3,
        packet-ins also come from the per-device intercept rules
        (priority 100) when a profiled device sends WAN traffic. The
        handler evaluates the traffic against the device's allowlist
        and either installs a forwarding rule or drops the packet.
        """
        msg = ev.msg
        dp = msg.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        src_mac = eth.src.lower()
        in_port = msg.match["in_port"]

        # Track devices seen on the WiFi port (Phase 2 behaviour).
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

        # Phase 3: evaluate allowlist for profiled devices.
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if (
            in_port == self.wifi_port
            and ip_pkt is not None
            and self.enforcement_mode == "enforcing"
            and src_mac in self.device_profiles
        ):
            dst_ip = ip_pkt.dst
            allowed, reason = self._is_destination_allowed(src_mac, dst_ip)

            if allowed:
                LOG.info(
                    "ALLOW %s -> %s (%s)",
                    src_mac, dst_ip, reason,
                )
                # Install a bidirectional flow rule for this device+destination.
                self._install_allowlist_flow(src_mac, dst_ip)

                # Forward the first packet that triggered this evaluation.
                actions = [parser.OFPActionOutput(ofproto.OFPP_LOCAL)]
                data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                out = parser.OFPPacketOut(
                    datapath=dp,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions,
                    data=data,
                )
                dp.send_msg(out)
            else:
                # Denied. Log it and let the packet be silently dropped
                # (we do not send a packet-out, so OVS discards it).
                LOG.info(
                    "DENY %s -> %s (%s)",
                    src_mac, dst_ip, reason,
                )
                self._record_denied(src_mac, dst_ip, reason)
            return

        # Default: log the dropped packet at debug level (Phase 2 behaviour).
        LOG.debug(
            "Packet-in (dropped by default deny): "
            "in_port=%d src=%s dst=%s type=0x%04x",
            in_port, eth.src, eth.dst, eth.ethertype,
        )

    def _record_denied(self, mac, dst_ip, reason):
        """Record a denied connection attempt in the denied log."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mac": mac,
            "dst_ip": dst_ip,
            "reason": reason,
        }
        # Include the device name if known.
        profile = self.device_profiles.get(mac)
        if profile:
            entry["device_name"] = profile["name"]

        self.denied_log.append(entry)
        # Cap the log size.
        if len(self.denied_log) > self.denied_log_max:
            self.denied_log = self.denied_log[-self.denied_log_max:]

    # -- Rule Installation --------------------------------------------------

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

        # -- 1. Table-miss: send to controller (priority 0) --
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, PRI_TABLE_MISS, match, actions, tag="table-miss")

        # -- 2. Default deny: drop everything (priority 1) --
        match = parser.OFPMatch()
        self._add_flow(datapath, PRI_DEFAULT_DENY, match, actions=[], tag="default-deny")

        # -- 3. ARP: allow in both directions (priority 200) --
        match = parser.OFPMatch(in_port=wifi, eth_type=0x0806)
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="arp-to-gw")

        match = parser.OFPMatch(in_port=local, eth_type=0x0806)
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="arp-from-gw")

        # -- 4. DHCP: requests and responses (priority 200) --
        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800,
            ip_proto=17, udp_dst=67,
        )
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dhcp-request")

        match = parser.OFPMatch(
            in_port=local, eth_type=0x0800,
            ip_proto=17, udp_dst=68,
        )
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dhcp-response")

        # -- 5. DNS: queries and responses (priority 200) --
        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800,
            ip_proto=17, udp_dst=53, ipv4_dst=GATEWAY_IP,
        )
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dns-udp-query")

        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800,
            ip_proto=6, tcp_dst=53, ipv4_dst=GATEWAY_IP,
        )
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dns-tcp-query")

        match = parser.OFPMatch(
            in_port=local, eth_type=0x0800,
            ip_proto=17, udp_src=53, ipv4_src=GATEWAY_IP,
        )
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dns-udp-response")

        match = parser.OFPMatch(
            in_port=local, eth_type=0x0800,
            ip_proto=6, tcp_src=53, ipv4_src=GATEWAY_IP,
        )
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_ESSENTIAL, match, actions, tag="dns-tcp-response")

        # -- 6. NTP: queries and responses (priority 200) --
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

        # -- 7. Anti-lateral-movement (priority 150) --
        match = parser.OFPMatch(
            in_port=wifi, eth_type=0x0800,
            ipv4_dst=(IOT_SUBNET, IOT_SUBNET_MASK),
        )
        self._add_flow(datapath, PRI_ANTI_LATERAL, match, actions=[], tag="anti-lateral")

        # -- 8. General WAN access (priority 50) --
        # These rules allow any device to reach the internet. In
        # enforcing mode, profiled devices are intercepted at priority
        # 100 before these rules are reached. Un-profiled devices
        # still hit these and get general WAN access.
        match = parser.OFPMatch(in_port=wifi, eth_type=0x0800)
        actions = [parser.OFPActionOutput(local)]
        self._add_flow(datapath, PRI_WAN_ACCESS, match, actions, tag="wan-outbound")

        match = parser.OFPMatch(in_port=local, eth_type=0x0800)
        actions = [parser.OFPActionOutput(wifi)]
        self._add_flow(datapath, PRI_WAN_ACCESS, match, actions, tag="wan-inbound")

        # -- 9. Phase 3: per-device intercept rules (enforcing mode) --
        # If we are in enforcing mode, install intercept rules for
        # each profiled device. These sit at priority 100, above the
        # general WAN rules at 50 but below essential services at 200.
        enforced_count = 0
        if self.enforcement_mode == "enforcing":
            for mac in self.device_profiles:
                self._install_device_intercept_rules(mac)
                enforced_count += 1

        # -- Log summary --
        self.rules_installed = True
        LOG.info(
            "Policy rules installed: %d rules. "
            "Micro-segmentation is ACTIVE. "
            "Essential services (DHCP, DNS, NTP) are PERMITTED. "
            "Mode: %s. Profiled devices: %d. Enforced: %d.",
            self.rule_count,
            self.enforcement_mode,
            len(self.device_profiles),
            enforced_count,
        )

    # -- Helpers ------------------------------------------------------------

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
