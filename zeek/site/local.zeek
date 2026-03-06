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
# Detection scripts will use this to generate alerts.
# For now, notices just get logged.
@load base/frameworks/notice

# The drop action allows detection scripts to request that Zeek
# emit a notice with an action hint. This will be wired to Ryu.
@load policy/frameworks/notice/actions/drop

# ---- Logging Configuration ----
# Rotate logs hourly. Zeek will create timestamped archive files
# and start fresh log files each rotation.
redef Log::default_rotation_interval = 1 hr;

# Use JSON output instead of Zeek's tab-separated format.
# JSON is easier for the ML pipeline to parse and is more portable
# for any future log analysis tools.
@load policy/tuning/json-logs

# Reduce noise: suppress the packet filter log and loaded-scripts log.
@load base/misc/version

# ---- Ryu REST API Integration ----
# Load the ActiveHTTP utility so it is available when I add detection
# scripts. Those scripts will POST isolation requests to
# the Ryu REST API at http://ryu:8080/...
@load base/utils/active-http
