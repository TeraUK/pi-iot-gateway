# IoT Security Gateway - Known-Bad Indicator Detection
#
# Flags any connection attempt to IP addresses or domains on threat
# intelligence feeds. Integrates with blocklists and IOC feeds to
# detect connections to known C2 infrastructure.
#
# IOC data is loaded from input files that can be updated externally
# without restarting Zeek (Zeek's Input framework re-reads them
# automatically on change).

@load ./alert-framework
@load base/frameworks/input

module IoT;

export {
    # Path to the file containing known-bad IP addresses (one per line).
    # Each line should be an IP address optionally followed by a tab
    # and a description. Lines starting with # are comments.
    option known_bad_ips_file = "/usr/local/zeek/share/zeek/site/iot-iocs/known-bad-ips.dat";

    # Path to the file containing known-bad domain names (one per line).
    option known_bad_domains_file = "/usr/local/zeek/share/zeek/site/iot-iocs/known-bad-domains.dat";

    # Set of known-bad IP addresses. Populated from the input file.
    global bad_ips: set[addr] = {};

    # Table of known-bad IP descriptions for alert context.
    global bad_ip_descriptions: table[addr] of string = {};

    # Set of known-bad domain names. Populated from the input file.
    global bad_domains: set[string] = {};

    # Table of known-bad domain descriptions for alert context.
    global bad_domain_descriptions: table[string] of string = {};
}

# Schema for reading the IOC IP file.
type BadIPEntry: record {
    ip: addr;
    description: string &default="No description";
};

# Schema for reading the IOC domain file.
type BadDomainEntry: record {
    domain: string;
    description: string &default="No description";
};

event zeek_init()
    {
    # Load known-bad IPs from the input file.
    if ( file_size(known_bad_ips_file) >= 0 )
        {
        Input::add_table([
            $source = known_bad_ips_file,
            $name = "bad_ips_feed",
            $idx = BadIPEntry,
            $destination = bad_ips,
            $mode = Input::REREAD,
            $want_record = F
        ]);
        }

    # Load known-bad domains from the input file.
    if ( file_size(known_bad_domains_file) >= 0 )
        {
        Input::add_table([
            $source = known_bad_domains_file,
            $name = "bad_domains_feed",
            $idx = BadDomainEntry,
            $destination = bad_domains,
            $mode = Input::REREAD,
            $want_record = F
        ]);
        }
    }

# Check every new connection against the known-bad IP list.
event connection_established(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! is_iot_device(src) )
        return;

    if ( dst in bad_ips )
        {
        local desc = dst in bad_ip_descriptions ?
            bad_ip_descriptions[dst] : "Known-bad IP (threat intelligence)";

        local details = fmt(
            "{\"bad_ip\": \"%s\", \"dst_port\": \"%s\", \"ioc_description\": \"%s\"}",
            dst, c$id$resp_p, desc);

        emit_alert(CRITICAL, "known-bad-ip", src,
            fmt("Connection to known-bad IP: %s:%s (%s)",
                dst, c$id$resp_p, desc),
            details,
            dst, c$id$resp_p);
        }
    }

# Check DNS queries against the known-bad domain list.
event dns_request(c: connection, msg: dns_msg, query: string,
                  qtype: count, qclass: count)
    {
    local src = c$id$orig_h;

    if ( ! is_iot_device(src) )
        return;

    local q = to_lower(query);
    if ( q in bad_domains )
        {
        local desc = q in bad_domain_descriptions ?
            bad_domain_descriptions[q] : "Known-bad domain (threat intelligence)";

        local details = fmt(
            "{\"bad_domain\": \"%s\", \"ioc_description\": \"%s\"}",
            q, desc);

        emit_alert(CRITICAL, "known-bad-domain", src,
            fmt("DNS query for known-bad domain: %s (%s)", q, desc),
            details);
        }
    }
