# IoT Security Gateway - Traffic Volume Anomaly Detection
#
# Flags any IoT device whose traffic volume (bytes transferred)
# significantly exceeds a threshold within a time window. Unexpected
# high-volume transfers could indicate data exfiltration or DDoS
# participation.
#
# Uses Zeek's SumStats framework to track bytes per device.

@load ./alert-framework

module IoT;

export {
    # Time window for measuring traffic volume per device.
    option volume_epoch = 10 min;

    # Outbound bytes within the epoch that trigger a WARNING alert.
    # Default: 50 MB.
    option volume_warning_threshold: double = 52428800.0;

    # Outbound bytes within the epoch that trigger a CRITICAL alert.
    # Default: 200 MB.
    option volume_critical_threshold: double = 209715200.0;
}

event zeek_init()
    {
    local r1 = SumStats::Reducer(
        $stream = "iot.volume.bytes_out",
        $apply = set(SumStats::SUM)
    );

    SumStats::create([
        $name = "iot.volume",
        $epoch = volume_epoch,
        $reducers = set(r1),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) =
            {
            return result["iot.volume.bytes_out"]$sum;
            },
        $threshold = volume_warning_threshold,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
            {
            local src = key$host;
            local bytes_out = result["iot.volume.bytes_out"]$sum;
            local mb_out = bytes_out / 1048576.0;

            local details = fmt(
                "{\"bytes_out\": %d, \"mb_out\": %.2f, \"epoch_secs\": %d}",
                double_to_count(bytes_out), mb_out,
                volume_epoch / 1 sec);

            if ( bytes_out >= volume_critical_threshold )
                {
                emit_alert(CRITICAL, "volume-anomaly", src,
                    fmt("Extreme outbound volume: %.1f MB in %s", mb_out, volume_epoch),
                    details);
                }
            else
                {
                emit_alert(WARNING, "volume-anomaly", src,
                    fmt("High outbound volume: %.1f MB in %s", mb_out, volume_epoch),
                    details);
                }
            }
    ]);
    }

# Accumulate bytes sent by each IoT device when connections close.
# Connection_state_remove is used to capture the final byte counts
# after the connection is fully processed.
event connection_state_remove(c: connection)
    {
    local src = c$id$orig_h;

    if (  is_iot_device(src) )
        return;

    # orig_ip_bytes is the total IP-level bytes sent by the originator.
    if ( c$conn?$orig_ip_bytes && c$conn$orig_ip_bytes > 0 )
        {
        SumStats::observe("iot.volume.bytes_out",
                          SumStats::Key($host = src),
                          SumStats::Observation($num = c$conn$orig_ip_bytes + 0.0));
        }
    }
