"""
IoT Security Gateway - ML Pipeline Feature Extraction

Computes a fixed-length numerical feature vector for a device from the
raw Zeek log entries in its rolling window. The same feature extraction
logic is used both here at inference time and in the offline training
script (train/train.py), so both the model and the runtime see identical
inputs.

Feature groups
--------------
conn.log features (11):
    conn_count          Total connection attempts in the window.
    unique_dst_ips      Unique destination IP addresses.
    unique_dst_ports    Unique destination ports across all connections.
    bytes_sent          Total originator bytes (orig_bytes).
    bytes_recv          Total responder bytes (resp_bytes).
    bytes_ratio         bytes_sent / (bytes_sent + bytes_recv). Indicates
                        data exfiltration direction. 0.5 = balanced.
    mean_duration       Mean connection duration in seconds.
    failed_conn_rate    Proportion of connections with state S0 or REJ.
                        High value = port scan or blocked C2 beaconing.
    tcp_ratio           Proportion of TCP connections.
    udp_ratio           Proportion of UDP connections.
    icmp_ratio          Proportion of ICMP connections.

dns.log features (4):
    dns_query_count     Total DNS queries in the window.
    dns_unique_domains  Unique domain names queried.
    dns_nxdomain_rate   Proportion of queries with NXDOMAIN response.
    dns_entropy_mean    Mean Shannon entropy of query names (bits per char).
                        Values above ~3.5 are indicative of DNS tunnelling
                        or algorithmically generated domain names (DGA).

All features default to 0.0 when no entries of that type exist in the
window, so the vector always has the same length regardless of traffic mix.
"""

import math
import logging
from collections import Counter

LOG = logging.getLogger(__name__)

# Ordered list of feature names. The order here defines the column order
# passed to scikit-learn. I must not change this order after training without
# retraining all models.
FEATURE_NAMES: list[str] = [
    # conn.log features
    "conn_count",
    "unique_dst_ips",
    "unique_dst_ports",
    "bytes_sent",
    "bytes_recv",
    "bytes_ratio",
    "mean_duration",
    "failed_conn_rate",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    # dns.log features
    "dns_query_count",
    "dns_unique_domains",
    "dns_nxdomain_rate",
    "dns_entropy_mean",
]


def extract(window_entries: list[dict]) -> dict[str, float]:
    """
    Compute the feature vector for a device from its rolling window entries.

    Each entry in window_entries is a Zeek JSON log line with an added
    'source' key indicating which log file it came from ('conn', 'dns', etc.).

    Returns a dict mapping feature name to float value. All features are
    present and default to 0.0 if the relevant log type has no entries.
    """
    conn_entries = [e for e in window_entries if e.get("source") == "conn"]
    dns_entries  = [e for e in window_entries if e.get("source") == "dns"]

    features: dict[str, float] = {}
    features.update(_conn_features(conn_entries))
    features.update(_dns_features(dns_entries))

    return features


def to_vector(features: dict[str, float]) -> list[float]:
    """
    Convert a features dict to an ordered list suitable for scikit-learn.

    The order follows FEATURE_NAMES. Missing features default to 0.0.
    """
    return [features.get(name, 0.0) for name in FEATURE_NAMES]


# ---------------------------------------------------------------------------
# Private: conn.log feature extraction
# ---------------------------------------------------------------------------

_FAILED_STATES = {"S0", "REJ", "RSTRH", "RSTOS0"}


def _conn_features(entries: list[dict]) -> dict[str, float]:
    """Extract connection-layer features from conn.log entries."""
    f: dict[str, float] = {
        "conn_count":       0.0,
        "unique_dst_ips":   0.0,
        "unique_dst_ports": 0.0,
        "bytes_sent":       0.0,
        "bytes_recv":       0.0,
        "bytes_ratio":      0.5,   # Neutral default: balanced traffic.
        "mean_duration":    0.0,
        "failed_conn_rate": 0.0,
        "tcp_ratio":        0.0,
        "udp_ratio":        0.0,
        "icmp_ratio":       0.0,
    }

    if not entries:
        return f

    n = len(entries)
    dst_ips:   set[str] = set()
    dst_ports: set[str] = set()
    total_bytes_sent = 0.0
    total_bytes_recv = 0.0
    total_duration   = 0.0
    failed_count     = 0
    proto_counts: Counter = Counter()

    for e in entries:
        dst_ips.add(e.get("id.resp_h", ""))
        dst_ports.add(str(e.get("id.resp_p", "")))

        # Zeek uses '-' for missing numeric fields in some configurations.
        orig = e.get("orig_bytes", 0) or 0
        resp = e.get("resp_bytes", 0) or 0
        try:
            total_bytes_sent += float(orig)
            total_bytes_recv += float(resp)
        except (TypeError, ValueError):
            pass

        dur = e.get("duration", 0) or 0
        try:
            total_duration += float(dur)
        except (TypeError, ValueError):
            pass

        state = e.get("conn_state", "")
        if state in _FAILED_STATES:
            failed_count += 1

        proto = (e.get("proto") or "").lower()
        proto_counts[proto] += 1

    total_bytes = total_bytes_sent + total_bytes_recv

    f["conn_count"]       = float(n)
    f["unique_dst_ips"]   = float(len(dst_ips))
    f["unique_dst_ports"] = float(len(dst_ports))
    f["bytes_sent"]       = total_bytes_sent
    f["bytes_recv"]       = total_bytes_recv
    f["bytes_ratio"]      = total_bytes_sent / total_bytes if total_bytes > 0 else 0.5
    f["mean_duration"]    = total_duration / n
    f["failed_conn_rate"] = failed_count / n
    f["tcp_ratio"]        = proto_counts.get("tcp", 0) / n
    f["udp_ratio"]        = proto_counts.get("udp", 0) / n
    f["icmp_ratio"]       = proto_counts.get("icmp", 0) / n

    return f


# ---------------------------------------------------------------------------
# Private: dns.log feature extraction
# ---------------------------------------------------------------------------

def _dns_features(entries: list[dict]) -> dict[str, float]:
    """Extract DNS-layer features from dns.log entries."""
    f: dict[str, float] = {
        "dns_query_count":    0.0,
        "dns_unique_domains": 0.0,
        "dns_nxdomain_rate":  0.0,
        "dns_entropy_mean":   0.0,
    }

    if not entries:
        return f

    n = len(entries)
    domains: set[str] = set()
    nxdomain_count = 0
    entropy_sum = 0.0

    for e in entries:
        query = (e.get("query") or "").strip()
        if query:
            domains.add(query.lower())
            entropy_sum += _shannon_entropy(query)

        # Zeek records the rcode_name field; NXDOMAIN = response code 3.
        rcode = (e.get("rcode_name") or "").upper()
        if rcode == "NXDOMAIN":
            nxdomain_count += 1

    f["dns_query_count"]    = float(n)
    f["dns_unique_domains"] = float(len(domains))
    f["dns_nxdomain_rate"]  = nxdomain_count / n
    f["dns_entropy_mean"]   = entropy_sum / n if n > 0 else 0.0

    return f


def _shannon_entropy(s: str) -> float:
    """
    Compute the Shannon entropy of a string in bits per character.

    A completely random string of lowercase hex characters has entropy ~4.0.
    Legitimate domain names typically score below 3.5. DGA domains and
    DNS-tunnelled payloads often score above 3.8.
    """
    if not s:
        return 0.0
    counts = Counter(s.lower())
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
