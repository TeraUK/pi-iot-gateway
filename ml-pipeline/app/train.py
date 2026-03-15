#!/usr/bin/env python3
"""
IoT Security Gateway - ML Pipeline Offline Training Script

Reads historical Zeek logs from the shared Docker volume, build feature
vectors in 5-minute windows per device, and train one Isolation Forest model
per device. I also train a global fleet model that serves as a fallback for
newly-connected devices.

Prerequisite
------------
Requires at least several weeks of Zeek logs collected with POL-01 through
POL-07 active (as required by POL-08). Running training on insufficient data
will produce excessive false positives. The recommended minimum is 2 weeks
of logs covering the device's typical usage patterns, including weekend
behaviour.

Usage
-----
Run this script on the gateway host (NOT inside the container) using docker
exec to access the Zeek log volume:

  # From the project root:
  python3 ml-pipeline/train/train.py \\
      --log-dir /path/to/zeek-logs \\
      --output-dir ./ml-pipeline/models \\
      --min-windows 576

After training, restart the ml-pipeline container so it picks up the new
model files:

  docker compose restart ml-pipeline

Training options
----------------
--log-dir       Path to the Zeek log directory (required).
--output-dir    Directory to save .joblib model files (default: ./models).
--min-windows   Minimum 5-minute windows required to train a per-device model.
                Default is 576 (= 48 hours at 5-min windows). Devices below
                this threshold are included only in the fleet model.
--contamination Expected proportion of anomalies in training data (0.0–0.5).
                Default is 0.05 (5%). Increase if the training data may
                contain attack traffic despite the POL-01/07 filters.
--n-estimators  Number of trees in the Isolation Forest (default: 200).
                More trees = better accuracy but slower training.
--dry-run       Print statistics without saving models.
"""

import argparse
import json
import logging
import math
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

# Add the app directory to the path so I can import the feature module.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "app"))

from features import FEATURE_NAMES, extract  # noqa: E402

logging.basicConfig(
    level  = logging.INFO,
    format = "%(asctime)s [Train] %(levelname)s: %(message)s",
)
LOG = logging.getLogger(__name__)

# Size of the feature aggregation window in seconds.
WINDOW_SECONDS = 300  # 5 minutes


# ---------------------------------------------------------------------------
# Log file discovery and parsing
# ---------------------------------------------------------------------------

LOG_FILES = {
    "conn": "conn",
    "dns":  "dns",
    "dhcp": "dhcp",
}


def find_log_files(log_dir: str, log_type: str) -> list[str]:
    """
    Find all log files of a given type (active and rotated) in log_dir.

    Zeek writes active logs as conn.log and rotated archives as
    conn.2026-03-12-12-00-00.log. I read both.
    """
    matches = []
    for filename in sorted(os.listdir(log_dir)):
        stem = filename.split(".")[0]
        if stem == log_type and filename.endswith(".log"):
            matches.append(os.path.join(log_dir, filename))
    return matches


def parse_log_file(path: str):
    """
    Generator: yield parsed JSON entries from a Zeek log file.

    Zeek JSON logs have one JSON object per line. Lines starting with '#'
    (legacy TSV header lines) and empty lines are skipped.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except OSError as exc:
        LOG.warning("Cannot read %s: %s", path, exc)


# ---------------------------------------------------------------------------
# IP -> MAC resolution from dhcp.log
# ---------------------------------------------------------------------------

def build_ip_mac_table(log_dir: str) -> dict[str, str]:
    """
    Parse all dhcp.log files and return an IP->MAC mapping.

    This is used to identify which device generated each conn/dns entry.
    """
    ip_to_mac: dict[str, str] = {}
    for path in find_log_files(log_dir, "dhcp"):
        for entry in parse_log_file(path):
            mac = entry.get("mac", "").lower().strip()
            if not mac:
                continue
            for key in ("assigned_addr", "client_addr"):
                ip = entry.get(key, "").strip()
                if ip and ip != "0.0.0.0":
                    ip_to_mac[ip] = mac
                    break
    LOG.info("DHCP table: %d IP->MAC mappings loaded.", len(ip_to_mac))
    return ip_to_mac


# ---------------------------------------------------------------------------
# Window aggregation
# ---------------------------------------------------------------------------

def build_windows(log_dir: str, ip_to_mac: dict[str, str]) -> dict[str, list[dict]]:
    """
    Read all conn.log and dns.log files and group entries into 5-minute windows
    per device.

    Returns a dict mapping MAC address to a list of feature dicts, one per
    5-minute window. Entries whose source IP is not in the DHCP table are
    assigned to a synthetic key "ip:<addr>" and excluded from per-device
    model training (but included in the fleet model).
    """
    # Accumulate raw entries per (mac, window_start) bucket.
    # window_start is the UNIX timestamp rounded down to the nearest 5 minutes.
    buckets: dict[tuple[str, int], list[dict]] = defaultdict(list)

    for log_type in ("conn", "dns"):
        for path in find_log_files(log_dir, log_type):
            LOG.info("Reading %s ...", path)
            for entry in parse_log_file(path):
                ts = entry.get("ts")
                if ts is None:
                    continue
                try:
                    ts_float = float(ts)
                except (TypeError, ValueError):
                    continue

                src_ip = entry.get("id.orig_h") or entry.get("orig_addr", "")
                if not src_ip:
                    continue

                mac = ip_to_mac.get(src_ip, f"ip:{src_ip}")
                entry["source"] = log_type

                window_start = int(ts_float // WINDOW_SECONDS) * WINDOW_SECONDS
                buckets[(mac, window_start)].append(entry)

    # Convert buckets into per-device lists of feature dicts.
    device_windows: dict[str, list[dict]] = defaultdict(list)
    for (mac, _window_start), entries in sorted(buckets.items(), key=lambda x: x[0][1]):
        features = extract(entries)
        features["_mac"] = mac
        device_windows[mac].append(features)

    LOG.info(
        "Window aggregation complete: %d devices, %d total windows.",
        len(device_windows),
        sum(len(v) for v in device_windows.values()),
    )
    return device_windows


# ---------------------------------------------------------------------------
# Model training
# ---------------------------------------------------------------------------

def train_model(
    feature_dicts: list[dict],
    contamination: float,
    n_estimators:  int,
) -> IsolationForest:
    """
    Train an Isolation Forest on a list of feature dicts.

    This strips the '_mac' metadata key before building the numpy array, and
    uses the canonical FEATURE_NAMES order so the model always sees the same
    column layout as the runtime pipeline.
    """
    matrix = np.array(
        [[fd.get(name, 0.0) for name in FEATURE_NAMES] for fd in feature_dicts],
        dtype=np.float64,
    )
    model = IsolationForest(
        n_estimators  = n_estimators,
        contamination = contamination,
        random_state  = 42,
        max_samples   = "auto",
        n_jobs        = -1,
    )
    model.fit(matrix)
    return model


def mac_to_filename(mac: str) -> str:
    """Convert aa:bb:cc:dd:ee:ff to aa_bb_cc_dd_ee_ff.joblib."""
    return mac.lower().replace(":", "_") + ".joblib"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Train Isolation Forest models from Zeek logs."
    )
    parser.add_argument(
        "--log-dir", required=True,
        help="Path to the Zeek log directory.",
    )
    parser.add_argument(
        "--output-dir", default="./models",
        help="Directory to save .joblib model files (default: ./models).",
    )
    parser.add_argument(
        "--min-windows", type=int, default=576,
        help=(
            "Minimum 5-minute windows required to train a per-device model. "
            "Default 576 = 48 hours."
        ),
    )
    parser.add_argument(
        "--contamination", type=float, default=0.05,
        help="Expected anomaly proportion in training data (default: 0.05).",
    )
    parser.add_argument(
        "--n-estimators", type=int, default=200,
        help="Number of trees in the Isolation Forest (default: 200).",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print statistics without saving any models.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not os.path.isdir(args.log_dir):
        LOG.error("Log directory does not exist: %s", args.log_dir)
        sys.exit(1)

    if not args.dry_run:
        os.makedirs(args.output_dir, exist_ok=True)

    LOG.info("=" * 60)
    LOG.info("Starting offline training.")
    LOG.info("  Log dir       : %s", args.log_dir)
    LOG.info("  Output dir    : %s", args.output_dir)
    LOG.info("  Min windows   : %d (%.1f hours)", args.min_windows, args.min_windows * 5 / 60)
    LOG.info("  Contamination : %.2f", args.contamination)
    LOG.info("  Estimators    : %d", args.n_estimators)
    LOG.info("  Dry run       : %s", args.dry_run)
    LOG.info("=" * 60)

    # Build IP->MAC table from DHCP logs.
    ip_to_mac = build_ip_mac_table(args.log_dir)

    # Aggregate all log entries into 5-minute windows per device.
    device_windows = build_windows(args.log_dir, ip_to_mac)

    if not device_windows:
        LOG.error("No usable windows found. Check that the log directory contains valid Zeek JSON logs.")
        sys.exit(1)

    # ---- Per-device models ----
    all_feature_dicts: list[dict] = []
    trained_devices: list[str] = []
    skipped_devices: list[str] = []

    for mac, feature_dicts in sorted(device_windows.items()):
        # Exclude synthetic ip: keys from per-device training.
        if mac.startswith("ip:"):
            all_feature_dicts.extend(feature_dicts)
            continue

        n_windows = len(feature_dicts)
        all_feature_dicts.extend(feature_dicts)

        if n_windows < args.min_windows:
            LOG.warning(
                "Skipping per-device model for %s: only %d windows "
                "(need %d, = %.1f hours).",
                mac, n_windows, args.min_windows, n_windows * 5 / 60,
            )
            skipped_devices.append(mac)
            continue

        LOG.info("Training model for %s (%d windows = %.1f hours) ...",
                 mac, n_windows, n_windows * 5 / 60)

        model = train_model(feature_dicts, args.contamination, args.n_estimators)

        if not args.dry_run:
            filename = mac_to_filename(mac)
            path = os.path.join(args.output_dir, filename)
            joblib.dump(model, path, compress=3)
            LOG.info("  Saved -> %s", path)

        trained_devices.append(mac)

    # ---- Fleet model ----
    # This trains the fleet model on all windows regardless of per-device
    # model eligibility, so that newly-connected devices have some coverage
    # from day one.
    if all_feature_dicts:
        n_fleet = len(all_feature_dicts)
        LOG.info("Training fleet model on %d total windows ...", n_fleet)
        fleet_model = train_model(all_feature_dicts, args.contamination, args.n_estimators)

        if not args.dry_run:
            fleet_path = os.path.join(args.output_dir, "_fleet.joblib")
            joblib.dump(fleet_model, fleet_path, compress=3)
            LOG.info("Saved fleet model -> %s", fleet_path)
    else:
        LOG.warning("No feature data available for fleet model.")

    # ---- Summary ----
    LOG.info("=" * 60)
    LOG.info("Training complete.")
    LOG.info("  Per-device models trained : %d", len(trained_devices))
    LOG.info("  Devices skipped (< %d windows): %d", args.min_windows, len(skipped_devices))
    if skipped_devices:
        for mac in skipped_devices:
            LOG.info("    - %s (%d windows)", mac, len(device_windows[mac]))
    LOG.info("  Fleet model windows       : %d", len(all_feature_dicts))
    if not args.dry_run:
        LOG.info("  Models saved to           : %s", args.output_dir)
        LOG.info("")
        LOG.info("Next steps:")
        LOG.info("  1. Review the models directory to confirm all expected devices have a model.")
        LOG.info("  2. docker compose restart ml-pipeline")
        LOG.info("  3. Monitor ml_alerts.log for false positives before enabling auto-isolation.")
    LOG.info("=" * 60)


if __name__ == "__main__":
    main()
