# IoT Security Gateway - Port Scan Detection
#
# Flags any IoT device that attempts connections to multiple distinct
# destination IP:port combinations within a short window. This is the
# primary reconnaissance method used by botnet malware. Mirai
# specifically scans Telnet (port 23/2323) and other service ports
# to find vulnerable devices.
#
# Uses Zeek's SumStats framework to count unique destination
# IP:port pairs per source IP within a configurable epoch.

@load ./alert-framework

module IoT;

export {
    # Time window for counting unique destinations per source.
    option port_scan_epoch = 5 min;

    # Number of unique dst IP:port pairs within the epoch that
    # triggers a CRITICAL alert. This threshold indicates active
    # network scanning behaviour.
    option port_scan_critical_threshold: double = 15.0;

    # Lower threshold for a WARNING alert. Could indicate a
    # misconfigured device or the early stages of a scan.
    option port_scan_warning_threshold: double = 8.0;
}

event zeek_init()
    {
    local r1 = SumStats::Reducer(
        $stream = "iot.port_scan.targets",
        $apply = set(SumStats::UNIQUE)
    );

    SumStats::create([
        $name = "iot.port_scan",
        $epoch = port_scan_epoch,
        $reducers = set(r1),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["iot.port_scan.targets"]$unique + 0.0;
            },
        $threshold = port_scan_warning_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local src = key$host;
            local unique_count = result["iot.port_scan.targets"]$unique;
            local details = fmt("{\"unique_targets\": %d, \"epoch_secs\": %d}",
                                unique_count, port_scan_epoch / 1 sec);

            if ( unique_count >= port_scan_critical_threshold )
                {
                emit_alert(CRITICAL, "port-scan", src,
                    fmt("Port scanning detected: %d unique destination IP:port pairs in %s",
                        unique_count, port_scan_epoch),
                    details);
                }
            else
                {
                emit_alert(WARNING, "port-scan", src,
                    fmt("Elevated connection spread: %d unique destination IP:port pairs in %s",
                        unique_count, port_scan_epoch),
                    details);
                }
            }
    ]);
    }

# Observe each new connection attempt from an IoT device.
# combine the destination IP and port into a single string to
# count unique IP:port pairs (not just unique IPs or unique ports).
event new_connection(c: connection)
    {
    local src = c$id$orig_h;

    if (  is_iot_device(src) )
        return;

    local target = fmt("%s:%s", c$id$resp_h, c$id$resp_p);

    SumStats::observe("iot.port_scan.targets",
                      SumStats::Key($host = src),
                      SumStats::Observation($str = target));
    }
