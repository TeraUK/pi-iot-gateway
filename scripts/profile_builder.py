#!/usr/bin/env python3
"""
IoT Security Gateway - Device Profile Builder

This script analyses Zeek conn.log and dns.log files and
generate per-device traffic profiles. The output is a device_profiles.json
file that Ryu's gateway policy app consumes.

The workflow:
  1. Collect Zeek logs with the gateway in learning mode
  2. Run this script against those logs to see what each device talks to
  3. Review the output and remove any destinations that look suspicious (can be automated later)
  4. Copy the approved profiles into device_profiles.json (can be automated later)
  5. Reload the profiles via the Ryu REST API (can be automated later)

Usage:
    # Analyse logs and print a summary to stdout:
    python3 profile_builder.py --zeek-dir /path/to/zeek-logs

    # Generate a draft profiles file:
    python3 profile_builder.py --zeek-dir /path/to/zeek-logs --output draft_profiles.json

    # Only analyse a specific device:
    python3 profile_builder.py --zeek-dir /path/to/zeek-logs --mac aa:bb:cc:dd:ee:ff

    # Use the DHCP lease file to map IPs to MACs:
    python3 profile_builder.py --zeek-dir /path/to/zeek-logs --leases /var/lib/misc/dnsmasq.leases
"""

import argparse
import json
import os
import sys
import gzip
from collections import defaultdict
from datetime import datetime, timezone


# The IoT subnet. Only devices in this range are profiled.
IOT_SUBNET_PREFIX = "192.168.50."

# The gateway IP. Traffic to this IP is essential services, not WAN.
GATEWAY_IP = "192.168.50.1"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Analyse Zeek logs and build per-device traffic profiles.",
    )
    parser.add_argument(
        "--zeek-dir", required=True,
        help="Path to the Zeek log directory (contains conn.log, dns.log, etc.)",
    )
    parser.add_argument(
        "--output", default=None,
        help="Write draft profiles to this JSON file.",
    )
    parser.add_argument(
        "--mac", default=None,
        help="Only analyse this specific MAC address.",
    )
    parser.add_argument(
        "--leases", default=None,
        help="Path to dnsmasq.leases file for IP-to-MAC mapping.",
    )
    parser.add_argument(
        "--min-connections", type=int, default=1,
        help="Minimum connection count to include a destination (default: 1).",
    )
    return parser.parse_args()


def load_dhcp_leases(leases_path):
    """
    Parse dnsmasq.leases to build an IP-to-MAC mapping.

    Each line: <expiry_epoch> <mac> <ip> <hostname> <client_id>
    """
    ip_to_mac = {}
    if not leases_path or not os.path.exists(leases_path):
        return ip_to_mac

    with open(leases_path, "r") as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) >= 3:
                mac = parts[1].lower()
                ip = parts[2]
                ip_to_mac[ip] = mac

    return ip_to_mac


def open_log_file(filepath):
    """Open a log file, handling gzip-compressed files transparently."""
    if filepath.endswith(".gz"):
        return gzip.open(filepath, "rt")
    return open(filepath, "r")


def find_log_files(zeek_dir, log_name):
    """
    Find all instances of a log file (current and rotated/archived).
    Searches the zeek_dir and a nested archive/ subdirectory.
    """
    files = []
    for root, dirs, filenames in os.walk(zeek_dir):
        for fn in filenames:
            # Match files like conn.log, conn.2025-03-01-12:00:00.log, conn.log.gz, etc.
            if fn.startswith(log_name.replace(".log", "")) and (fn.endswith(".log") or fn.endswith(".log.gz")):
                files.append(os.path.join(root, fn))
    return sorted(files)


def parse_json_log(filepath):
    """Parse a Zeek JSON log file, yielding one dict per line."""
    try:
        with open_log_file(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except (IOError, OSError) as e:
        print(f"  Warning: could not read {filepath}: {e}", file=sys.stderr)


def analyse_conn_logs(zeek_dir, ip_to_mac):
    """
    Parse all conn.log files and build a per-device connection profile.

    Returns:
        {mac: {dst_ip: {"count": N, "ports": set(), "protos": set(), "bytes": N}}}
    """
    device_connections = defaultdict(lambda: defaultdict(lambda: {
        "count": 0, "ports": set(), "protos": set(), "bytes_sent": 0, "bytes_recv": 0,
    }))

    conn_files = find_log_files(zeek_dir, "conn.log")
    if not conn_files:
        print("  Warning: no conn.log files found.", file=sys.stderr)
        return device_connections

    print(f"  Found {len(conn_files)} conn.log file(s)")

    for filepath in conn_files:
        for entry in parse_json_log(filepath):
            src_ip = entry.get("id.orig_h", "")
            dst_ip = entry.get("id.resp_h", "")
            dst_port = entry.get("id.resp_p")
            proto = entry.get("proto", "")
            orig_bytes = entry.get("orig_ip_bytes", 0) or 0
            resp_bytes = entry.get("resp_ip_bytes", 0) or 0

            # We only care about traffic originating from the IoT subnet.
            if not src_ip.startswith(IOT_SUBNET_PREFIX):
                continue

            # Skip traffic to the gateway itself (essential services).
            if dst_ip == GATEWAY_IP:
                continue

            # Skip traffic within the IoT subnet (lateral, already blocked).
            if dst_ip.startswith(IOT_SUBNET_PREFIX):
                continue

            # Resolve the source IP to a MAC address.
            mac = ip_to_mac.get(src_ip, src_ip)

            conn = device_connections[mac][dst_ip]
            conn["count"] += 1
            if dst_port is not None:
                conn["ports"].add(int(dst_port))
            conn["protos"].add(proto)
            conn["bytes_sent"] += int(orig_bytes)
            conn["bytes_recv"] += int(resp_bytes)

    return device_connections


def analyse_dns_logs(zeek_dir, ip_to_mac):
    """
    Parse all dns.log files and build a per-device DNS query profile.

    Returns:
        {mac: {domain: {"count": N, "resolved_ips": set()}}}
    """
    device_dns = defaultdict(lambda: defaultdict(lambda: {
        "count": 0, "resolved_ips": set(),
    }))

    dns_files = find_log_files(zeek_dir, "dns.log")
    if not dns_files:
        print("  Warning: no dns.log files found.", file=sys.stderr)
        return device_dns

    print(f"  Found {len(dns_files)} dns.log file(s)")

    for filepath in dns_files:
        for entry in parse_json_log(filepath):
            src_ip = entry.get("id.orig_h", "")
            query = entry.get("query", "").lower()
            answers = entry.get("answers", [])

            if not src_ip.startswith(IOT_SUBNET_PREFIX):
                continue

            if not query:
                continue

            mac = ip_to_mac.get(src_ip, src_ip)

            dns_entry = device_dns[mac][query]
            dns_entry["count"] += 1
            if answers:
                for ans in answers:
                    # Only capture IP addresses, not CNAMEs.
                    if ans and not ans.endswith(".") and "." in ans:
                        try:
                            parts = ans.split(".")
                            if all(0 <= int(p) <= 255 for p in parts) and len(parts) == 4:
                                dns_entry["resolved_ips"].add(ans)
                        except ValueError:
                            pass

    return device_dns


def build_profiles(device_connections, device_dns, min_connections, leases_info):
    """
    Combine connection and DNS data into draft device profiles.
    """
    all_macs = set(device_connections.keys()) | set(device_dns.keys())
    profiles = {}

    for mac in sorted(all_macs):
        # Try to determine a hostname from the lease file.
        name = "Unknown Device"
        for ip, lease_mac in leases_info.items():
            if lease_mac == mac:
                name = f"Device at {ip}"
                break

        connections = device_connections.get(mac, {})
        dns_queries = device_dns.get(mac, {})

        # Build the allowed_domains list from DNS queries.
        allowed_domains = []
        domain_to_ips = {}
        for domain, info in sorted(dns_queries.items(), key=lambda x: -x[1]["count"]):
            allowed_domains.append(domain)
            if info["resolved_ips"]:
                domain_to_ips[domain] = sorted(info["resolved_ips"])

        # Build the allowed_cidrs from connection destinations
        # that were not resolved via DNS.
        dns_resolved_ips = set()
        for info in dns_queries.values():
            dns_resolved_ips.update(info["resolved_ips"])

        allowed_cidrs = []
        for dst_ip, conn_info in sorted(connections.items(), key=lambda x: -x[1]["count"]):
            if conn_info["count"] < min_connections:
                continue
            if dst_ip not in dns_resolved_ips:
                # This IP was contacted directly, not via a DNS-resolved domain.
                # Add it as a /32 CIDR.
                allowed_cidrs.append(f"{dst_ip}/32")

        # Connection statistics for review.
        total_connections = sum(c["count"] for c in connections.values())
        unique_destinations = len(connections)
        unique_domains = len(dns_queries)

        profiles[mac] = {
            "name": name,
            "manufacturer": "Unknown",
            "allowed_domains": allowed_domains,
            "allowed_cidrs": allowed_cidrs,
            "_stats": {
                "total_connections": total_connections,
                "unique_destination_ips": unique_destinations,
                "unique_domains_queried": unique_domains,
                "domain_to_ips": domain_to_ips,
                "top_destinations": [
                    {
                        "ip": ip,
                        "count": info["count"],
                        "ports": sorted(info["ports"]),
                        "protos": sorted(info["protos"]),
                        "bytes_sent": info["bytes_sent"],
                        "bytes_recv": info["bytes_recv"],
                    }
                    for ip, info in sorted(
                        connections.items(), key=lambda x: -x[1]["count"]
                    )[:20]
                ],
            },
        }

    return profiles


def print_summary(profiles):
    """Print a human-readable summary of each device's traffic profile."""
    print("\n" + "=" * 70)
    print("  Device Traffic Profile Summary")
    print("=" * 70)

    for mac, profile in sorted(profiles.items()):
        stats = profile.get("_stats", {})
        print(f"\n{'─' * 70}")
        print(f"  Device: {mac}")
        print(f"  Name:   {profile['name']}")
        print(f"  Total connections: {stats.get('total_connections', 0)}")
        print(f"  Unique destination IPs: {stats.get('unique_destination_ips', 0)}")
        print(f"  Unique domains queried: {stats.get('unique_domains_queried', 0)}")

        if profile["allowed_domains"]:
            print(f"\n  DNS domains queried ({len(profile['allowed_domains'])}):")
            for domain in profile["allowed_domains"][:30]:
                ips = stats.get("domain_to_ips", {}).get(domain, [])
                ip_str = f" -> {', '.join(ips)}" if ips else ""
                print(f"    {domain}{ip_str}")
            if len(profile["allowed_domains"]) > 30:
                print(f"    ... and {len(profile['allowed_domains']) - 30} more")

        top_dests = stats.get("top_destinations", [])
        if top_dests:
            print(f"\n  Top destinations by connection count:")
            for dest in top_dests[:15]:
                ports_str = ", ".join(str(p) for p in dest["ports"][:5])
                print(
                    f"    {dest['ip']:18s}  "
                    f"conns={dest['count']:5d}  "
                    f"ports=[{ports_str}]  "
                    f"sent={dest['bytes_sent']}  recv={dest['bytes_recv']}"
                )

        if profile["allowed_cidrs"]:
            print(f"\n  Direct IPs (no DNS, will be added as CIDRs):")
            for cidr in profile["allowed_cidrs"][:20]:
                print(f"    {cidr}")

    print(f"\n{'=' * 70}")
    print(f"  Total devices profiled: {len(profiles)}")
    print("=" * 70)


def write_output(profiles, output_path):
    """
    Write a draft device_profiles.json file.

    The _stats fields are included as comments for my review but
    are ignored by the Ryu app (it only reads name, manufacturer,
    allowed_domains, allowed_cidrs).
    """
    output = {
        "mode": "learning",
        "idle_timeout": 300,
        "_generated": datetime.now(timezone.utc).isoformat(),
        "_note": (
            "This is a draft generated by profile_builder.py. "
            "Review each device's allowed_domains and allowed_cidrs, "
            "remove anything suspicious, set the correct device names "
            "and manufacturers, then change mode to 'enforcing' when ready. "
            "The _stats fields are for review only and are ignored by Ryu."
        ),
        "devices": profiles,
    }

    with open(output_path, "w") as f:
        json.dump(output, f, indent=4, default=str)

    print(f"\nDraft profiles written to: {output_path}")
    print(
        "Next steps:\n"
        "  1. Review the output and remove suspicious destinations\n"
        "  2. Set correct device names and manufacturers\n"
        "  3. Remove the _stats and _note fields (optional, Ryu ignores them)\n"
        "  4. Copy to ~/iot-gateway/ryu/config/device_profiles.json\n"
        "  5. Reload via: curl -X POST http://127.0.0.1:8080/policy/allowlists/reload\n"
    )


def main():
    args = parse_args()

    print("IoT Security Gateway - Device Profile Builder")
    print(f"Analysing Zeek logs in: {args.zeek_dir}")

    # Load DHCP leases for IP-to-MAC mapping.
    ip_to_mac = load_dhcp_leases(args.leases)
    if ip_to_mac:
        print(f"  Loaded {len(ip_to_mac)} DHCP lease entries")
    else:
        print(
            "  No DHCP leases loaded. Devices will be identified by IP, "
            "not MAC. Use --leases for better results."
        )

    # Analyse logs.
    print("\nAnalysing conn.log files...")
    device_connections = analyse_conn_logs(args.zeek_dir, ip_to_mac)

    print("\nAnalysing dns.log files...")
    device_dns = analyse_dns_logs(args.zeek_dir, ip_to_mac)

    # Build profiles.
    profiles = build_profiles(
        device_connections, device_dns, args.min_connections, ip_to_mac,
    )

    # Filter to a specific MAC if requested.
    if args.mac:
        mac = args.mac.lower()
        if mac in profiles:
            profiles = {mac: profiles[mac]}
        else:
            print(f"\nMAC {mac} not found in the logs.")
            sys.exit(1)

    if not profiles:
        print("\nNo device traffic found in the logs.")
        sys.exit(0)

    # Print the summary.
    print_summary(profiles)

    # Write output file if requested.
    if args.output:
        write_output(profiles, args.output)


if __name__ == "__main__":
    main()
