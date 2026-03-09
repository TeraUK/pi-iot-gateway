#
# IoT Security Gateway - Zeek Local Policy
# 
# This file is loaded automatically by Zeek. It configures protocol
# analysers, logging, and loads the IoT detection scripts.
#

# ---- Standard Protocol Analysers ----
# These generate the structured logs that feed the ML pipeline.
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/dhcp

# NTP analysis - IoT devices use NTP heavily and anomalous NTP
# behaviour can indicate compromise or misconfiguration.
@load base/protocols/ntp

# SSH and FTP analysis - IoT devices should rarely use these protocols.
# If an SSH or FTP connection appears in the logs, it is a strong
# anomaly signal worth investigating (detection scripts will flag this).
@load base/protocols/ssh
@load base/protocols/ftp

# Connection content tracking - logs byte counts, packet counts,
# and connection duration. These become features for the ML pipeline.
@load base/protocols/conn/contents

# ---- Software Fingerprinting ----
# Extracts software version strings from traffic (HTTP User-Agent,
# SSH banners, DHCP vendor class, etc.). Useful for identifying
# device types on the network and detecting unexpected software.
@load base/frameworks/software
@load policy/protocols/http/software
@load policy/protocols/ssh/software
@load policy/protocols/dhcp/software

# ---- Notice Framework ----
# Detection scripts use this for internal notice generation.
@load base/frameworks/notice
@load policy/frameworks/notice/actions/drop

# ---- Logging Configuration ----
# Rotate logs hourly. Zeek creates timestamped archive files and
# starts fresh log files each rotation.
redef Log::default_rotation_interval = 1 hr;

# Use JSON output for all logs. JSON is easier for the ML pipeline
# to parse and for any future centralized logging system to ingest.
@load policy/tuning/json-logs

# Reduce noise: suppress the packet filter log and loaded-scripts log.
@load base/misc/version

# ---- SSL Certificate Validation ----
# Flags expired, self-signed, and otherwise invalid certificates.
# IoT devices often have poor certificate hygiene, so this may be
# noisy at first.
@load policy/protocols/ssl/validate-certs

# ---- DNS Query Case Preservation ----
# Preserves the original capitalisation of DNS query names in dns.log.
# Some malware encodes data in the case pattern of DNS labels (used
# in DNS tunnelling). Having the original case makes that detectable.
@load policy/protocols/dns/log-original-query-case

# ---- ActiveHTTP ----
# Required by the alert framework for POSTing isolation requests
# to the Ryu REST API.
@load base/utils/active-http

# ---- IoT Detection Scripts (Phase 4) ----
# This loads the alert framework and all six detection scripts.
@load ./iot-detection

# ---- Detection Configuration ----
# Override detection thresholds and modes here. These redef statements
# take effect after the scripts are loaded.
#
# Auto-isolation is DISABLED by default (dry-run mode). Should be enabled
# once the detections have been thoroughly tested, and it is confirmed they
# are not producing false positives.
#
# To enable auto-isolation:
# redef IoT::auto_isolate = T;
#
# To switch the baseline-dependent detectors to detection mode:
# redef IoT::new_dest_mode = "detecting";
# redef IoT::proto_anomaly_mode = "detecting";
#
# To adjust thresholds (examples):
# redef IoT::port_scan_critical_threshold = 20.0;
# redef IoT::dns_rate_warning_threshold = 150.0;
# redef IoT::volume_warning_threshold = 104857600.0;  # 100 MB
