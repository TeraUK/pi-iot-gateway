#
# IoT Security Gateway — Zeek Local Policy
#
# This file is loaded automatically by Zeek. Add your custom
# detection logic, protocol analysers, and logging configuration here.
#

# Load standard analysis scripts.
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/dhcp

# Log all connections, DNS queries, HTTP transactions, and SSL certs.
# These logs are consumed by the ML pipeline via the shared volume.

# Reduce log noise: disable the packet filter log and the loaded-scripts log.
@load base/misc/version

# ---- Custom Detection Logic ----
# Add your own scripts here as the project develops.
# Examples:
#   @load ./detect-iot-scan.zeek
#   @load ./baseline-dns.zeek
#   @load ./alert-to-ryu.zeek

# ---- Ryu REST API Integration ----
# When we develop detection scripts that should trigger dynamic
# isolation, use Zeek's ActiveHTTP module or the Input framework
# to POST to the Ryu REST API at http://ryu:8080/...
