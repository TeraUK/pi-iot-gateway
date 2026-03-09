# IoT Security Gateway - Detection Script Loader
#
# Loads the alert framework and all detection scripts.
# The alert framework must be loaded first since all detectors depend on it.

@load ./alert-framework
@load ./detect-port-scan
@load ./detect-dns-anomaly
@load ./detect-new-destination
@load ./detect-protocol-anomaly
@load ./detect-volume-anomaly
@load ./detect-known-bad
