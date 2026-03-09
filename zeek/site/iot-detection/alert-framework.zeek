# IoT Security Gateway - Alert Framework
#
# This is the core alerting infrastructure for the detection scripts.
# It provides:
#   - A custom log stream (iot_alerts.log) with structured JSON fields
#   - Severity levels: INFO, WARNING, CRITICAL
#   - IP-to-MAC resolution via DHCP observation
#   - Ryu REST API integration for automated device isolation
#   - A dry-run mode for testing detections without isolating devices
#
# All detection scripts use this framework to emit alerts. The output
# format is designed for easy ingestion by a future centralized
# logging/alerting system.

@load base/utils/active-http
@load base/protocols/dhcp

module IoT; # Tells zeek this script should be in the IoT namespace.

# Items defined in the export block are publically visible to the entire IoT namespace
export {
    # Severity levels for alerts.
    type Severity: enum {
        INFO,       #< Logged only. No automatic action.
        WARNING,    #< Logged with full context. No network action.
        CRITICAL,   #< Logged and triggers automatic device isolation.
    };

    # The IoT alert log stream. Writes to iot_alerts.log in JSON format.
    redef enum Log::ID += { ALERT_LOG };

    # Schema for iot_alerts.log entries.
    type AlertInfo: record {
        ts:            time            &log;  #< Timestamp of the alert.
        severity:      string          &log;  #< INFO, WARNING, or CRITICAL.
        detector:      string          &log;  #< Name of the detection script that fired.
        src_ip:        addr            &log;  #< Source IP of the flagged device.
        src_mac:       string          &log &default="unknown";  #< MAC address (resolved via DHCP).
        dst_ip:        addr            &log &optional;  #< Destination IP (if applicable).
        dst_port:      port            &log &optional;  #< Destination port (if applicable).
        description:   string          &log;  #< Human-readable summary of the detection.
        details:       string          &log &default="{}";  #< JSON-encoded detector-specific metadata.
        action_taken:  string          &log &default="logged";  #< What action was taken (logged, isolate_requested, dry_run).
    };

    # The Ryu REST API base URL. Zeek reaches Ryu via the Docker network hostname.
    option ryu_api_url = "http://ryu:8080";

    # When enabled, CRITICAL alerts will trigger automatic device
    # isolation via the Ryu REST API. When disabled, CRITICAL alerts
    # are still logged but no network action is taken (dry-run mode).
    # This should be enabled once the detections have been thoroughly tested.
    option auto_isolate = F;

    # The IoT subnet prefix. Only devices with source IPs matching
    # this prefix are monitored by the detection scripts.
    option iot_subnet: subnet = 192.168.50.0/24;

    # The gateway IP. Traffic to/from this IP is excluded from
    # detection (it is the gateway itself, not an IoT device).
    option gateway_ip = 192.168.50.1;

    # Emit an alert from a detection script.
    global emit_alert: function(severity: Severity, detector: string,
                                src_ip: addr, description: string,
                                details: string &default="{}",
                                dst_ip: addr &default=0.0.0.0,
                                dst_port: port &default=0/unknown);

    # Request isolation of a device via the Ryu REST API.
    # Only called internally when auto_isolate is enabled and severity is CRITICAL.
    global request_isolation: function(mac: string, ip: addr, reason: string);

    # Resolve an IP address to a MAC address using the DHCP table.
    global ip_to_mac: function(ip: addr): string;

    # Check whether an IP address is an IoT device (in the IoT subnet
    # and not the gateway).
    global is_iot_device: function(ip: addr): bool;

    # IP-to-MAC mapping table, populated from DHCP observations.
    global dhcp_table: table[addr] of string = {};
}

event zeek_init()
    {
    Log::create_stream(IoT::ALERT_LOG, [$columns=AlertInfo,
                                         $path="iot_alerts"]);

    Log::add_filter(IoT::ALERT_LOG, [$name="default",
                                      $path="iot_alerts"]);
    }

# Populate the IP-to-MAC table from DHCP acknowledgements.
# Every time dnsmasq hands out a lease, this event fires and records the mapping. 
# This is the most reliable way to resolve IoT device IPs to MACs inside Zeek.
event DHCP::log_dhcp(rec: DHCP::Info)
    {
    if ( rec?$mac && rec?$assigned_addr )
        {
        IoT::dhcp_table[rec$assigned_addr] = rec$mac;
        }
    }

function ip_to_mac(ip: addr): string
    {
    if ( ip in dhcp_table )
        return dhcp_table[ip];
    return "unknown";
    }

function is_iot_device(ip: addr): bool
    {
    return (ip in iot_subnet) && (ip != gateway_ip);
    }

function emit_alert(severity: Severity, detector: string,
                    src_ip: addr, description: string,
                    details: string &default="{}",
                    dst_ip: addr &default=0.0.0.0,
                    dst_port: port &default=0/unknown)
    {
    local mac = ip_to_mac(src_ip);
    local severity_str = "INFO";
    local action = "logged";

    if ( severity == WARNING )
        severity_str = "WARNING";
    else if ( severity == CRITICAL )
        severity_str = "CRITICAL";

    # For CRITICAL alerts, attempt isolation if enabled.
    if ( severity == CRITICAL )
        {
        if ( auto_isolate && mac != "unknown" )
            {
            request_isolation(mac, src_ip, fmt("%s: %s", detector, description));
            action = "isolate_requested";
            }
        else if ( auto_isolate && mac == "unknown" )
            {
            # I cannot isolate without a MAC address. Log the failure.
            action = "isolate_failed_no_mac";
            }
        else
            {
            action = "dry_run";
            }
        }

    local rec = AlertInfo(
        $ts = network_time(),
        $severity = severity_str,
        $detector = detector,
        $src_ip = src_ip,
        $src_mac = mac,
        $description = description,
        $details = details,
        $action_taken = action
    );

    if ( dst_ip != 0.0.0.0 )
        rec$dst_ip = dst_ip;
    if ( dst_port != 0/unknown )
        rec$dst_port = dst_port;

    Log::write(IoT::ALERT_LOG, rec);
    }

function request_isolation(mac: string, ip: addr, reason: string)
    {
    local payload = fmt("{\"mac\": \"%s\", \"reason\": \"Zeek: %s (src_ip=%s)\"}", mac, reason, ip);
    local url = fmt("%s/policy/isolate", ryu_api_url);

    local req = ActiveHTTP::Request(
        $url = url,
        $method = "POST",
        $client_data = payload,
        $addl_curl_args = fmt("-H 'Content-Type: application/json'")
    );

    when [req, mac, ip] ( local resp = ActiveHTTP::request(req) )
        {
        if ( resp$code == 200 )
            Reporter::info(fmt("IoT: Successfully requested isolation of %s (%s)", mac, ip));
        else
            Reporter::warning(fmt("IoT: Isolation request for %s (%s) returned HTTP %d: %s",
                                  mac, ip, resp$code, resp$body));
        }
    }
