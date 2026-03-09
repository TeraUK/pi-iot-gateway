# IoT Security Gateway - New Destination Detection
#
# Flags any IoT device that attempts to contact a destination IP
# not previously seen in its traffic history. After the baseline
# period, new destinations are suspicious and warrant investigation.
#
# The script has two modes:
#   - "learning": builds the baseline by recording every destination
#     each device contacts. Does not generate alerts.
#   - "detecting": compares new connections against the baseline and
#     flags new destinations.
#
# The baseline is built in-memory from observed traffic. It can also
# be seeded from an input file containing known-good device-to-IP
# pairs.

@load ./alert-framework

module IoT;

export {
    # Operating mode for the new destination detector.
    # Set to "detecting" once the baseline is established.
    option new_dest_mode = "learning";

    # Number of new (unseen) destinations from a single device within
    # the tracking epoch that triggers a WARNING alert.
    option new_dest_warning_threshold: double = 3.0;

    # Number of new destinations within the epoch that triggers a
    # CRITICAL alert.
    option new_dest_critical_threshold: double = 10.0;

    # Epoch for counting new destinations.
    option new_dest_epoch = 1 hr;

    # The per-device baseline of known destination IPs.
    # Populated during learning mode and consulted during detection.
    global dest_baseline: table[addr] of set[addr] = {};
}

event zeek_init()
    {
    if ( new_dest_mode == "detecting" )
        {
        local r1 = SumStats::Reducer(
            $stream = "iot.new_dest.count",
            $apply = set(SumStats::SUM)
        );

        SumStats::create([
            $name = "iot.new_dest",
            $epoch = new_dest_epoch,
            $reducers = set(r1),
            $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                {
                return result["iot.new_dest.count"]$sum;
                },
            $threshold = new_dest_warning_threshold,
            $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                {
                local src = key$host;
                local new_count = result["iot.new_dest.count"]$sum;
                local details = fmt("{\"new_destinations\": %d, \"epoch_secs\": %d}",
                                    double_to_count(new_count),
                                    new_dest_epoch / 1 sec);

                if ( new_count >= new_dest_critical_threshold )
                    {
                    emit_alert(CRITICAL, "new-destination", src,
                        fmt("Many new destinations: %d unseen IPs contacted in %s",
                            double_to_count(new_count), new_dest_epoch),
                        details);
                    }
                else
                    {
                    emit_alert(WARNING, "new-destination", src,
                        fmt("New destinations detected: %d unseen IPs contacted in %s",
                            double_to_count(new_count), new_dest_epoch),
                        details);
                    }
                }
        ]);
        }
    }

event connection_established(c: connection)
    {
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if ( ! is_iot_device(src) )
        return;

    # Skip traffic to the gateway and within the IoT subnet.
    if ( dst == gateway_ip )
        return;
    if ( dst in iot_subnet )
        return;

    if ( new_dest_mode == "learning" )
        {
        # Learning mode: record the destination in the baseline.
        if ( src !in dest_baseline )
            dest_baseline[src] = set();

        add dest_baseline[src][dst];
        }
    else if ( new_dest_mode == "detecting" )
        {
        # Detecting mode: check against the baseline.
        if ( src !in dest_baseline || dst !in dest_baseline[src] )
            {
            # This is a new destination for this device.
            # Add it to the baseline so we only alert once per destination.
            if ( src !in dest_baseline )
                dest_baseline[src] = set();
            add dest_baseline[src][dst];

            # Log an INFO alert for each individual new destination.
            local details = fmt("{\"new_dst_ip\": \"%s\", \"dst_port\": \"%s\"}",
                                dst, c$id$resp_p);
            emit_alert(INFO, "new-destination", src,
                fmt("New destination contacted: %s:%s", dst, c$id$resp_p),
                details,
                dst, c$id$resp_p);

            # Count towards the SumStats threshold for WARNING/CRITICAL.
            SumStats::observe("iot.new_dest.count",
                              SumStats::Key($host = src),
                              SumStats::Observation($num = 1));
            }
        }
    }
