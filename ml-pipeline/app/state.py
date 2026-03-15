"""
IoT Security Gateway - ML Pipeline State

I keep all mutable runtime state here in a single module so every other
component can import it without circular dependencies.

What this module holds:
  - ip_to_mac: populated from dhcp.log, used to resolve device IPs to MACs
    across all log types (conn, dns, http, ssl all log by IP, not MAC).
  - device_windows: per-MAC rolling deque of raw log entries within the
    last WINDOW_SECONDS. Each entry is a dict with a 'source' key ('conn',
    'dns', etc.) plus the original Zeek JSON fields.
  - device_baselines: per-MAC running statistics (mean + std per feature)
    used to compute relative anomaly thresholds for WARNING classification.
    Updated incrementally each time a feature vector is scored.
  - recent_alerts: per-MAC set of recent alert fingerprints used to
    suppress duplicate alerts within DEDUP_SECONDS.
"""

import time
from collections import defaultdict, deque

# ---------------------------------------------------------------------------
# Configuration (overridden by pipeline.py on startup)
# ---------------------------------------------------------------------------

# How many seconds of log entries to retain per device.
# 5 minutes gives enough context without consuming excessive memory.
WINDOW_SECONDS: int = 300

# How long to suppress duplicate alerts for the same device and detector (seconds).
DEDUP_SECONDS: int = 120

# ---------------------------------------------------------------------------
# IP -> MAC mapping
# ---------------------------------------------------------------------------
# Populated by processing dhcp.log entries. The Zeek alert framework uses
# the same DHCP observation approach for MAC resolution.

ip_to_mac: dict[str, str] = {}


def update_dhcp(entry: dict) -> None:
    """
    Record an IP->MAC mapping from a dhcp.log entry.

    I look for both 'assigned_addr' (DHCP ACK) and 'client_addr' as
    fallbacks, since not every DHCP message contains all fields.
    """
    mac = entry.get("mac", "").lower().strip()
    if not mac:
        return

    for key in ("assigned_addr", "client_addr"):
        ip = entry.get(key, "").strip()
        if ip and ip != "0.0.0.0":
            ip_to_mac[ip] = mac
            break


def resolve_mac(ip: str) -> str:
    """Return the MAC address for a given IP, or 'unknown' if not seen in DHCP."""
    return ip_to_mac.get(ip, "unknown")


# ---------------------------------------------------------------------------
# Per-device rolling windows
# ---------------------------------------------------------------------------
# Each device (identified by MAC) has a deque of log entry dicts.
# Entries older than WINDOW_SECONDS are pruned on each update.

device_windows: dict[str, deque] = defaultdict(deque)


def add_entry(mac: str, entry: dict) -> None:
    """
    Add a log entry to a device's rolling window and prune stale entries.

    The 'ts' field in Zeek JSON logs is a UNIX epoch float. I use it
    for window expiry rather than wall-clock time so that replaying
    archived logs during training works correctly.
    """
    device_windows[mac].append(entry)
    _prune_window(mac, entry.get("ts", time.time()))


def _prune_window(mac: str, latest_ts: float) -> None:
    """Remove entries from the left of the window that are older than WINDOW_SECONDS."""
    cutoff = latest_ts - WINDOW_SECONDS
    dq = device_windows[mac]
    while dq and dq[0].get("ts", 0) < cutoff:
        dq.popleft()


def get_window(mac: str) -> list[dict]:
    """Return a snapshot of the current rolling window for a device."""
    return list(device_windows[mac])


def all_active_macs() -> list[str]:
    """Return MACs that have at least one entry in their current window."""
    return [mac for mac, dq in device_windows.items() if dq]


# ---------------------------------------------------------------------------
# Per-device feature baselines
# ---------------------------------------------------------------------------
# I track an exponentially-weighted running mean and variance for each
# feature per device. This lets me compute relative thresholds
# (e.g., "2x the device's normal DNS rate") in addition to the absolute
# Isolation Forest score.
#
# Algorithm: Welford's online algorithm for numerically stable mean/variance.

_EWM_ALPHA = 0.1  # Weight for new observations in exponential moving update.

# Structure: baselines[mac][feature_name] = {"mean": float, "var": float, "n": int}
device_baselines: dict[str, dict[str, dict]] = defaultdict(dict)


def update_baseline(mac: str, features: dict[str, float]) -> None:
    """
    Update the running mean and variance for each feature of a device.

    I use an exponentially-weighted approach so that the baseline adapts
    slowly over time, meaning gradual behavioural drift is eventually
    absorbed while sudden spikes remain anomalous.
    """
    for feature, value in features.items():
        if feature not in device_baselines[mac]:
            device_baselines[mac][feature] = {"mean": value, "var": 0.0, "n": 1}
        else:
            b = device_baselines[mac][feature]
            b["n"] += 1
            old_mean = b["mean"]
            b["mean"] = (1 - _EWM_ALPHA) * old_mean + _EWM_ALPHA * value
            b["var"] = (1 - _EWM_ALPHA) * (b["var"] + _EWM_ALPHA * (value - old_mean) ** 2)


def get_baseline(mac: str, feature: str) -> dict | None:
    """Return the baseline stats for a feature, or None if not yet established."""
    return device_baselines.get(mac, {}).get(feature)


def baseline_established(mac: str, min_observations: int = 50) -> bool:
    """
    Return True if this device has enough observations for reliable baselines.

    I require at least min_observations scoring cycles before trusting the
    baseline, to avoid triggering false positives on newly-connected devices.
    50 observations at a 60-second scoring interval = ~50 minutes of data.
    """
    b = device_baselines.get(mac, {})
    if not b:
        return False
    return all(v["n"] >= min_observations for v in b.values())


# ---------------------------------------------------------------------------
# Alert deduplication
# ---------------------------------------------------------------------------
# I track (mac, detector, severity) fingerprints with their last-fired
# timestamp so I don't emit floods of identical alerts for the same device.

_alert_last_fired: dict[tuple, float] = {}


def should_suppress(mac: str, detector: str, severity: str) -> bool:
    """
    Return True if an identical alert was already fired within DEDUP_SECONDS.
    """
    key = (mac, detector, severity)
    last = _alert_last_fired.get(key, 0.0)
    return (time.time() - last) < DEDUP_SECONDS


def record_alert(mac: str, detector: str, severity: str) -> None:
    """Record that an alert was fired so future duplicates can be suppressed."""
    _alert_last_fired[(mac, detector, severity)] = time.time()
