# IoT Security Gateway running on an Ubuntu mini PC. 

## Architecture Diagram

At this point in time the WAN uplink is managed automatically by systemd.networkd, as defined in netplan config. **The WAN interface will be moved into OVS in the future.**

![Diagram of High Level Architecture](http://www.plantuml.com/plantuml/proxy?cache=no&src=https://raw.githubusercontent.com/TeraUK/iot-gateway/refs/heads/main/Documentation/architecture-diagram.puml)

# IoT Security Gateway — Quick Reference

---

## Network Topology and Addressing

### Host Interfaces

| Interface | IP Address | Role |
|---|---|---|
| enp2s0 | DHCP from upstream router (e.g., 192.168.2.55) | WAN uplink to the internet |
| wlp3s0 | None (bridged into OVS) | WiFi radio, managed by hostapd |
| br0 (OVS internal port) | 192.168.50.1/24 | Default gateway for IoT devices, dnsmasq binds here |
| ovs-system | None | OVS kernel datapath (internal, not user-managed) |

### Docker Network (gateway-net)

| Interface / Entity | IP Address | Role |
|---|---|---|
| br-xxxxxx (Docker bridge) | 172.20.0.1 | Docker gateway for gateway-net |
| AdGuard Home | 172.20.0.53 (static) | DNS filtering for IoT clients |
| Ryu Controller | 172.20.0.x (DHCP) | SDN control plane |
| Zeek | 172.20.0.x (DHCP) | Passive traffic analysis |
| ML Pipeline | 172.20.0.x (DHCP) | Anomaly detection |

### IoT Subnet

| Entity | IP Address | How Assigned |
|---|---|---|
| IoT devices | 192.168.50.50 – 192.168.50.150 | DHCP from dnsmasq |
| Default gateway (advertised to clients) | 192.168.50.1 | DHCP option: router |
| DNS server (advertised to clients) | 192.168.50.1 | DHCP option: dns-server |

### Port Mappings (Host ← Container)

| Host Binding | Container Port | Service |
|---|---|---|
| 0.0.0.0:6653 | 6653/tcp | Ryu OpenFlow listener |
| 0.0.0.0:8080 | 8080/tcp | Ryu REST API |
| 192.168.50.1:53 | 53/tcp, 53/udp | AdGuard Home DNS |
| 0.0.0.0:3000 | 3000/tcp | AdGuard Home setup wizard |
| 0.0.0.0:8088 | 80/tcp | AdGuard Home admin panel |

### Mirror Infrastructure

| Interface | Location | Role |
|---|---|---|
| zeek-veth-h | Host (OVS port) | Host-side end of the mirror veth pair |
| zeek-eth1 | Zeek container | Container-side end; Zeek sniffs on this |

---

## Summary of Inter-Component Communication

| From | To | Method | Purpose |
|---|---|---|---|
| IoT device | hostapd (wlp3s0) | WiFi 802.11 (WPA2-PSK) | Network association and authentication |
| IoT device | dnsmasq (via br0) | DHCP broadcast (UDP 67/68) | IP address, gateway, and DNS server assignment |
| IoT device | AdGuard Home | DNS (UDP/TCP 53) via nftables DNAT to 172.20.0.53 | Domain name resolution and filtering |
| nftables | AdGuard Home | DNAT (prerouting chain) | Forces all DNS queries to AdGuard, even if a device hardcodes a different DNS server (e.g., 8.8.8.8) |
| IoT device | OVS (br0) | L2 frames via wlp3s0 | All traffic enters the OVS data plane |
| OVS | Ryu | OpenFlow 1.3 (TCP 6653) | Packet-In messages for unknown flows; Ryu responds with Flow-Mod to install rules |
| Ryu | OVS | OpenFlow 1.3 (TCP 6653) | Flow rule installation, modification, and deletion |
| OVS | Zeek | Mirrored traffic via veth pair (zeek-veth-h → zeek-eth1) | Passive one-way copy of all bridge traffic for inspection |
| OVS | nftables / enp2s0 | IP forwarding + NAT masquerade | WAN-bound traffic leaves the gateway via the host IP stack |
| Zeek | Shared volume (zeek-logs) | File I/O | Writes structured logs (conn.log, dns.log, http.log, ssl.log, etc.) |
| ML Pipeline | Shared volume (zeek-logs) | File I/O (read-only) | Reads and analyses Zeek logs for anomaly detection |
| Zeek | Ryu | REST API (HTTP POST to ryu:8080) | Real-time threat alerts triggering dynamic flow rule changes |
| ML Pipeline | Ryu | REST API (HTTP POST to ryu:8080) | Anomaly-triggered policy changes (e.g., device isolation) |
| zeek-mirror.service | Docker / OVS | docker events + ip/ovs-vsctl commands | Watches for Zeek container starts and re-attaches the mirror veth pair automatically |

---
