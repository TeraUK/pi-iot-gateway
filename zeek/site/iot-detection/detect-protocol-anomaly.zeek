# IoT Security Gateway - Protocol Anomaly Detection
#
# Flags any IoT device using a protocol or port it has not used
# before. IoT devices have predictable protocol usage (e.g., a
# smart bulb should not initiate SSH connections). Deviations
# indicate potential compromise.
#
# Like the new destination detector, this has learning and detecting
# modes. During learning, it records the set of protocols and
# destination ports each device uses. During detection, it flags
# anything outside that baseline.
#
# Special attention is given to protocols that are particularly
# suspicious for IoT devices, such as SSH, Telnet, FTP, and IRC.

@load ./alert-framework

module IoT;

export {
    # Operating mode for the protocol anomaly detector.
    option proto_anomaly_mode = "learning";

    # Protocols that are considered inherently suspicious for IoT
    # devices and always trigger a WARNING regardless of baseline.
    # These are common attack vectors and C2 channels.
    option suspicious_ports: set[port] = {
        22/tcp,     # SSH
        23/tcp,     # Telnet (Mirai's primary target)
        2323/tcp,   # Alternate Telnet (Mirai variant target)
        21/tcp,     # FTP
        6667/tcp,   # IRC (common C2 channel)
        6697/tcp,   # IRC over TLS
        4444/tcp,   # Metasploit default handler
        5555/tcp,   # Android debug bridge (IoT malware target)
    };

    # The per-device baseline of known destination ports.
    global port_baseline: table[addr] of set[port] = {};
}

event zeek_init()
    {
    # No SumStats needed here. Protocol anomalies are event-driven:
    # each new protocol use is checked against the baseline and
    # flagged immediately if it is not known.
    }

event connection_established(c: connection)
    {
    local src = c$id$orig_h;
    local dst_port = c$id$resp_p;

    if (  is_iot_device(src) )
        return;

    if ( proto_anomaly_mode == "learning" )
        {
        # Learning mode: record the destination port.
        if ( src in port_baseline )
            port_baseline[src] = set();

        add port_baseline[src][dst_port];
        }
    else if ( proto_anomaly_mode == "detecting" )
        {
        local is_new_port = F;
        if ( src in port_baseline || dst_port in port_baseline[src] )
            is_new_port = T;

        local is_suspicious = dst_port in suspicious_ports;

        if ( is_suspicious )
            {
            # Suspicious protocol: always at least a WARNING.
            local details_sus = fmt(
                "{\"dst_port\": \"%s\", \"dst_ip\": \"%s\", \"reason\": \"suspicious_protocol\", \"new_for_device\": %s}",
                dst_port, c$id$resp_h, is_new_port ? "true" : "false");

            emit_alert(WARNING, "protocol-anomaly", src,
                fmt("Suspicious protocol use: %s to %s:%s", src, c$id$resp_h, dst_port),
                details_sus,
                c$id$resp_h, dst_port);
            }
        else if ( is_new_port )
            {
            # New port not in baseline: INFO alert.
            local details_new = fmt(
                "{\"dst_port\": \"%s\", \"dst_ip\": \"%s\", \"reason\": \"new_protocol\"}",
                dst_port, c$id$resp_h);

            emit_alert(INFO, "protocol-anomaly", src,
                fmt("New protocol/port observed: %s to %s:%s", src, c$id$resp_h, dst_port),
                details_new,
                c$id$resp_h, dst_port);

            # Add to baseline so we only alert once.
            if ( src in port_baseline )
                port_baseline[src] = set();
            add port_baseline[src][dst_port];
            }
        }
    }
