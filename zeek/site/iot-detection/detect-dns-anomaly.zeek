# IoT Security Gateway - DNS Query Rate Anomaly Detection
#
# Flags any IoT device whose DNS query rate exceeds a threshold
# within a time window. A sudden spike in DNS queries can indicate
# C2 beaconing, DNS tunnelling, or DNS-based data exfiltration.
#
# Also detects high-entropy domain names, which are characteristic
# of domain generation algorithms (DGAs) used by malware.
#
# Uses Zeek's SumStats framework for rate counting.

@load ./alert-framework
@load base/protocols/dns

module IoT;

export {
    # Time window for counting DNS queries per source.
    option dns_rate_epoch = 5 min;

    # DNS queries within the epoch that trigger a WARNING alert.
    option dns_rate_warning_threshold: double = 100.0;

    # DNS queries within the epoch that trigger a CRITICAL alert.
    option dns_rate_critical_threshold: double = 500.0;

    # Minimum character entropy (Shannon) of a queried domain name
    # for it to be flagged as a potential DGA domain. Legitimate
    # domain names typically have entropy below 3.5. Random-looking
    # DGA domains often exceed 4.0.
    option dga_entropy_threshold = 4.0;

    # Number of high-entropy DNS queries within the epoch that
    # triggers a WARNING alert.
    option dga_warning_threshold: double = 5.0;

    # Number of high-entropy DNS queries within the epoch that
    # triggers a CRITICAL alert.
    option dga_critical_threshold: double = 20.0;
}

# Calculate Shannon entropy of a string. Higher entropy means
# more randomness, which is characteristic of DGA domains.
function shannon_entropy(s: string): double
    {
    local counts: table[string] of count = {};
    local len = |s|;

    if ( len == 0 )
        return 0.0;

    local i = 0;
    while ( i < len )
        {
        local c = s[i];
        if ( c in counts )
            counts[c] = counts[c] + 1;
        else
            counts[c] = 1;
        ++i;
        }

    local entropy = 0.0;
    for ( ch, cnt in counts )
        {
        local freq = (cnt + 0.0) / (len + 0.0);
        if ( freq > 0.0 )
            entropy = entropy - freq * (ln(freq) / ln(2.0));
        }

    return entropy;
    }

# Extract the second-level domain from a FQDN for entropy calculation.
# E.g. "subdomain.example.com" -> "example"
function extract_sld(query: string): string
    {
    local parts = split_string(query, /\./);
    local n = |parts|;

    if ( n >= 2 )
        return parts[n - 2];
    return query;
    }

event zeek_init()
    {
    # -- DNS query rate counter --
    local r_rate = SumStats::Reducer(
        $stream = "iot.dns_rate.queries",
        $apply = set(SumStats::SUM)
    );

    SumStats::create([
        $name = "iot.dns_rate",
        $epoch = dns_rate_epoch,
        $reducers = set(r_rate),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["iot.dns_rate.queries"]$sum;
            },
        $threshold = dns_rate_warning_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local src = key$host;
            local query_count = result["iot.dns_rate.queries"]$sum;
            local details = fmt("{\"dns_queries\": %d, \"epoch_secs\": %d}",
                                double_to_count(query_count),
                                dns_rate_epoch / 1 sec);

            if ( query_count >= dns_rate_critical_threshold )
                {
                emit_alert(CRITICAL, "dns-rate", src,
                    fmt("Extreme DNS query rate: %d queries in %s",
                        double_to_count(query_count), dns_rate_epoch),
                    details);
                }
            else
                {
                emit_alert(WARNING, "dns-rate", src,
                    fmt("Elevated DNS query rate: %d queries in %s",
                        double_to_count(query_count), dns_rate_epoch),
                    details);
                }
            }
    ]);

    # -- DGA detection counter --
    local r_dga = SumStats::Reducer(
        $stream = "iot.dns_dga.high_entropy",
        $apply = set(SumStats::SUM)
    );

    SumStats::create([
        $name = "iot.dns_dga",
        $epoch = dns_rate_epoch,
        $reducers = set(r_dga),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["iot.dns_dga.high_entropy"]$sum;
            },
        $threshold = dga_warning_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local src = key$host;
            local dga_count = result["iot.dns_dga.high_entropy"]$sum;
            local details = fmt("{\"high_entropy_queries\": %d, \"entropy_threshold\": %.2f, \"epoch_secs\": %d}",
                                double_to_count(dga_count), dga_entropy_threshold,
                                dns_rate_epoch / 1 sec);

            if ( dga_count >= dga_critical_threshold )
                {
                emit_alert(CRITICAL, "dns-dga", src,
                    fmt("Possible DGA activity: %d high-entropy DNS queries in %s",
                        double_to_count(dga_count), dns_rate_epoch),
                    details);
                }
            else
                {
                emit_alert(WARNING, "dns-dga", src,
                    fmt("Elevated high-entropy DNS queries: %d in %s",
                        double_to_count(dga_count), dns_rate_epoch),
                    details);
                }
            }
    ]);
    }

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    local src = c$id$orig_h;

    if ( ! is_iot_device(src) )
        return;

    # Count the query for rate detection.
    SumStats::observe("iot.dns_rate.queries",
                      SumStats::Key($host = src),
                      SumStats::Observation($num = 1));

    # Check the query domain for high entropy (potential DGA).
    if ( |query| > 0 )
        {
        local sld = extract_sld(query);
        if ( |sld| >= 6 )
            {
            local ent = shannon_entropy(sld);
            if ( ent >= dga_entropy_threshold )
                {
                SumStats::observe("iot.dns_dga.high_entropy",
                                  SumStats::Key($host = src),
                                  SumStats::Observation($num = 1));
                }
            }
        }
    }
