"""
IoT Security Gateway - ML Pipeline

This is the main entry point for the ML anomaly detection pipeline.
It orchestrates the four-stage processing loop defined in POL-08:

  Stage 1 - Ingest: read new JSON lines from Zeek's log files on the
            shared Docker volume (conn.log, dns.log, dhcp.log, etc.).

  Stage 2 - Enrich: resolve IP addresses to MAC addresses using the
            DHCP table, then update each device's rolling event window
            and feature baseline.

  Stage 3 - Score: every SCORE_INTERVAL seconds, extract feature vectors
            from each device's rolling window and run inference against
            the loaded Isolation Forest models.

  Stage 4 - Dispatch: classify scores against the thresholds in
            config/thresholds.yml and emit INFO / WARNING / CRITICAL
            alerts. CRITICAL alerts optionally trigger a POST to the
            Ryu REST API to isolate the device (controlled by the
            ML_AUTO_ISOLATE environment variable).

Environment variables (set in docker-compose.yml):
  RYU_API_URL      Ryu REST API base URL (default: http://ryu:8080)
  POLL_INTERVAL    Seconds between log ingestion polls (default: 10)
  ZEEK_LOG_DIR     Zeek log directory (default: /opt/zeek-logs)
  MODELS_DIR       Trained model directory (default: /opt/ml-pipeline/models)
  CONFIG_PATH      Path to thresholds.yml (default: /opt/ml-pipeline/config/thresholds.yml)
  ML_AUTO_ISOLATE  Set to "true" to enable automatic device isolation (default: false)
  ML_ALERT_LOG     Path for the ML alert log (default: /opt/zeek-logs/ml_alerts.log)
"""

import logging
import os
import sys
import time

import yaml

import state
import features as feat_mod
from ingestor  import LogIngestor
from detector  import Detector
from alerter   import Alerter

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level    = logging.INFO,
    format   = "%(asctime)s [ML-Pipeline] %(levelname)s %(name)s: %(message)s",
    datefmt  = "%Y-%m-%dT%H:%M:%S",
    stream   = sys.stdout,
)
LOG = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

ZEEK_LOG_DIR  = os.environ.get("ZEEK_LOG_DIR",  "/opt/zeek-logs")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "10"))
CONFIG_PATH   = os.environ.get("CONFIG_PATH",    "/opt/ml-pipeline/config/thresholds.yml")


def load_config(path: str) -> dict:
    """Load and return the thresholds YAML config."""
    try:
        with open(path, "r") as fh:
            cfg = yaml.safe_load(fh)
        LOG.info("Loaded config from %s.", path)
        return cfg
    except FileNotFoundError:
        LOG.warning("Config file not found at %s. Using built-in defaults.", path)
        return {}
    except yaml.YAMLError as exc:
        LOG.error("Failed to parse config %s: %s. Using built-in defaults.", path, exc)
        return {}


# ---------------------------------------------------------------------------
# Severity classification
# ---------------------------------------------------------------------------

def classify(
    mac:      str,
    features: dict[str, float],
    score:    float | None,
    cfg:      dict,
) -> tuple[str | None, str, dict]:
    """
    Classify a device's current state into INFO / WARNING / CRITICAL / None.

    Rule-based checks are applied first (these are deterministic and do not
    require a trained model), then fall back to the Isolation Forest score.
    Classification returns a tuple of:
      (severity, description, details_dict)
    where severity is None if no alert should be emitted.
    """
    rules   = cfg.get("rules",     {})
    scoring = cfg.get("scoring",   {})
    thresholds = cfg.get("thresholds", {})

    severity = None
    description = ""
    details: dict = {"anomaly_score": score}

    # ---- Rule-based checks ----

    # 1. Port scan: many unique destination ports.
    unique_ports = features.get("unique_dst_ports", 0)
    port_crit    = rules.get("port_scan_critical_unique_ports", 30)
    if unique_ports >= port_crit:
        severity    = "CRITICAL"
        description = (
            f"Possible port scan: {int(unique_ports)} unique destination ports "
            f"in the scoring window (threshold: {port_crit})."
        )
        details.update({"trigger": "port_scan", "unique_dst_ports": unique_ports})
        return severity, description, details

    # 2. High failed connection rate (scanning or blocked C2).
    failed_rate = features.get("failed_conn_rate", 0)
    if failed_rate >= rules.get("failed_conn_critical_rate", 0.80):
        severity    = "CRITICAL"
        description = (
            f"High failed connection rate: {failed_rate:.0%} of connections "
            f"in state S0/REJ (threshold: {rules.get('failed_conn_critical_rate', 0.80):.0%})."
        )
        details.update({"trigger": "failed_conn_rate", "failed_conn_rate": failed_rate})
        return severity, description, details

    if failed_rate >= rules.get("failed_conn_warning_rate", 0.50):
        severity    = "WARNING"
        description = (
            f"Elevated failed connection rate: {failed_rate:.0%} of connections "
            f"failed (threshold: {rules.get('failed_conn_warning_rate', 0.50):.0%})."
        )
        details.update({"trigger": "failed_conn_rate", "failed_conn_rate": failed_rate})

    # 3. DNS rate anomaly relative to baseline (requires established baseline).
    min_obs = scoring.get("min_baseline_observations", 50)
    if state.baseline_established(mac, min_obs):
        baseline = state.get_baseline(mac, "dns_query_count")
        if baseline and baseline["mean"] > 0:
            dns_count    = features.get("dns_query_count", 0)
            multiplier   = dns_count / baseline["mean"]
            crit_mult    = rules.get("dns_rate_critical_multiplier", 10.0)
            warn_mult    = rules.get("dns_rate_warning_multiplier",  2.0)
            if multiplier >= crit_mult:
                severity    = "CRITICAL"
                description = (
                    f"DNS query rate {multiplier:.1f}x above device baseline "
                    f"({int(dns_count)} queries vs mean {baseline['mean']:.1f}). "
                    f"Possible C2 beaconing or DNS tunnelling."
                )
                details.update({
                    "trigger": "dns_rate",
                    "dns_query_count": dns_count,
                    "baseline_mean": baseline["mean"],
                    "multiplier": multiplier,
                })
                return severity, description, details

            elif multiplier >= warn_mult and severity is None:
                severity    = "WARNING"
                description = (
                    f"DNS query rate {multiplier:.1f}x above device baseline "
                    f"({int(dns_count)} queries vs mean {baseline['mean']:.1f})."
                )
                details.update({
                    "trigger": "dns_rate",
                    "dns_query_count": dns_count,
                    "baseline_mean": baseline["mean"],
                    "multiplier": multiplier,
                })

    # 4. DNS query entropy anomaly (possible DGA or tunnelling).
    entropy = features.get("dns_entropy_mean", 0)
    if entropy >= rules.get("dns_entropy_critical", 3.80):
        severity    = "CRITICAL"
        description = (
            f"High DNS query name entropy: {entropy:.2f} bits/char "
            f"(threshold: {rules.get('dns_entropy_critical', 3.80):.2f}). "
            f"Possible DGA activity or DNS tunnelling."
        )
        details.update({"trigger": "dns_entropy", "dns_entropy_mean": entropy})
        return severity, description, details

    if entropy >= rules.get("dns_entropy_warning", 3.50) and severity is None:
        severity    = "WARNING"
        description = (
            f"Elevated DNS query name entropy: {entropy:.2f} bits/char "
            f"(threshold: {rules.get('dns_entropy_warning', 3.50):.2f}). "
            f"Possible DGA or tunnelling activity."
        )
        details.update({"trigger": "dns_entropy", "dns_entropy_mean": entropy})

    # 5. Traffic volume anomaly relative to baseline.
    if state.baseline_established(mac, min_obs):
        total_bytes  = features.get("bytes_sent", 0) + features.get("bytes_recv", 0)
        baseline_vol = state.get_baseline(mac, "bytes_sent")
        if baseline_vol and baseline_vol["mean"] > 0:
            base_total = baseline_vol["mean"] + (state.get_baseline(mac, "bytes_recv") or {}).get("mean", 0)
            if base_total > 0:
                vol_mult = total_bytes / base_total
                vol_crit = rules.get("volume_critical_multiplier", 10.0)
                vol_warn = rules.get("volume_warning_multiplier", 3.0)
                if vol_mult >= vol_crit:
                    severity    = "CRITICAL"
                    description = (
                        f"Traffic volume {vol_mult:.1f}x above device baseline "
                        f"({total_bytes/1024:.1f} KB vs mean {base_total/1024:.1f} KB). "
                        f"Possible DDoS participation or data exfiltration."
                    )
                    details.update({
                        "trigger": "volume",
                        "total_bytes": total_bytes,
                        "baseline_bytes": base_total,
                        "multiplier": vol_mult,
                    })
                    return severity, description, details

                elif vol_mult >= vol_warn and severity is None:
                    severity    = "WARNING"
                    description = (
                        f"Traffic volume {vol_mult:.1f}x above device baseline "
                        f"({total_bytes/1024:.1f} KB vs mean {base_total/1024:.1f} KB)."
                    )
                    details.update({
                        "trigger": "volume",
                        "total_bytes": total_bytes,
                        "baseline_bytes": base_total,
                        "multiplier": vol_mult,
                    })

    # ---- Isolation Forest score classification ----
    # Only applied when no higher-priority rule already set a severity.
    if score is not None:
        info_thr = thresholds.get("info_threshold",     0.05)
        warn_thr = thresholds.get("warning_threshold",  0.15)
        crit_thr = thresholds.get("critical_threshold", 0.30)

        if score >= crit_thr and severity not in ("CRITICAL",):
            severity    = "CRITICAL"
            description = (
                f"Isolation Forest anomaly score {score:.3f} exceeds CRITICAL "
                f"threshold {crit_thr:.3f}. Behaviour deviates significantly from baseline."
            )
            details.update({"trigger": "isolation_forest"})

        elif score >= warn_thr and severity is None:
            severity    = "WARNING"
            description = (
                f"Isolation Forest anomaly score {score:.3f} exceeds WARNING "
                f"threshold {warn_thr:.3f}. Behaviour is moderately anomalous."
            )
            details.update({"trigger": "isolation_forest"})

        elif score >= info_thr and severity is None:
            severity    = "INFO"
            description = (
                f"Isolation Forest anomaly score {score:.3f} exceeds INFO "
                f"threshold {info_thr:.3f}. Minor deviation from baseline."
            )
            details.update({"trigger": "isolation_forest"})

    # Enrich details with the most anomalous feature (useful for triage).
    if severity is not None:
        details["features"] = {
            k: round(v, 4)
            for k, v in features.items()
            if isinstance(v, (int, float))
        }

    return severity, description, details


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    LOG.info("=" * 60)
    LOG.info("IoT Security Gateway - ML Pipeline starting.")
    LOG.info("  Zeek log dir : %s", ZEEK_LOG_DIR)
    LOG.info("  Poll interval: %ds", POLL_INTERVAL)
    LOG.info("  Config       : %s", CONFIG_PATH)
    LOG.info("=" * 60)

    cfg      = load_config(CONFIG_PATH)
    scoring  = cfg.get("scoring", {})

    # Apply config values to the state module.
    state.WINDOW_SECONDS = scoring.get("window_seconds",   300)
    state.DEDUP_SECONDS  = scoring.get("dedup_seconds",    120)

    score_interval  = scoring.get("score_interval",            60)
    min_conn_entries = scoring.get("min_conn_entries",           3)

    ingestor = LogIngestor(ZEEK_LOG_DIR)
    detector = Detector()
    alerter  = Alerter()

    # Determine how many poll cycles to run before scoring.
    polls_per_score = max(1, score_interval // POLL_INTERVAL)

    poll_count = 0
    LOG.info(
        "Pipeline ready. Scoring every %ds (%d poll cycles). "
        "Auto-isolate: %s.",
        score_interval, polls_per_score,
        os.environ.get("ML_AUTO_ISOLATE", "false"),
    )

    while True:
        # ----------------------------------------------------------------
        # Stage 1: Ingest new log entries from Zeek's files.
        # ----------------------------------------------------------------
        new_entries = ingestor.poll()

        # ----------------------------------------------------------------
        # Stage 2: Enrich entries with source tag, resolve IPs to MACs,
        #          and push into per-device rolling windows.
        # ----------------------------------------------------------------
        for log_type, entries in new_entries.items():
            for entry in entries:
                entry["source"] = log_type

                # DHCP entries update the IP->MAC table only.
                if log_type == "dhcp":
                    state.update_dhcp(entry)
                    continue

                # For all other log types, resolve src IP to MAC and add
                # to the device's rolling window.
                src_ip = entry.get("id.orig_h") or entry.get("orig_addr", "")
                if not src_ip:
                    continue

                mac = state.resolve_mac(src_ip)
                if mac == "unknown":
                    # Device not yet seen in DHCP. Store the entry keyed on IP
                    # so we can still score it if the DHCP table is populated
                    # before the next scoring cycle.
                    mac = f"ip:{src_ip}"

                entry["_src_ip"] = src_ip
                entry["_src_mac"] = mac
                state.add_entry(mac, entry)

        # ----------------------------------------------------------------
        # Stage 3: Score every active device (every polls_per_score polls).
        # ----------------------------------------------------------------
        poll_count += 1
        if poll_count % polls_per_score != 0:
            time.sleep(POLL_INTERVAL)
            continue

        active_macs = state.all_active_macs()
        if not active_macs:
            LOG.debug("No devices in scoring windows. Waiting for traffic.")
            time.sleep(POLL_INTERVAL)
            continue

        LOG.debug("Scoring %d active device(s).", len(active_macs))

        for mac in active_macs:
            window = state.get_window(mac)

            # Require a minimum number of conn entries to avoid noisy scores
            # on devices with very little traffic in the window.
            conn_entries = [e for e in window if e.get("source") == "conn"]
            if len(conn_entries) < min_conn_entries:
                continue

            # Extract the feature vector.
            features = feat_mod.extract(window)

            # Run Isolation Forest inference.
            score = detector.score(mac, features)

            # Update the baseline for this device with the new feature vector.
            state.update_baseline(mac, features)

            # ----------------------------------------------------------------
            # Stage 4: Classify and dispatch alerts.
            # ----------------------------------------------------------------
            severity, description, details = classify(mac, features, score, cfg)

            if severity is None:
                continue

            # Resolve the display IP (use the first src IP seen in the window).
            src_ip = next(
                (e.get("_src_ip", "") for e in window if e.get("_src_ip")),
                "",
            )
            # Normalise the MAC back to colon-separated form if we stored it
            # as ip:<addr> before a DHCP entry arrived.
            display_mac = mac if not mac.startswith("ip:") else "unknown"

            # Suppress duplicate alerts.
            if state.should_suppress(display_mac, "ml-isolation-forest", severity):
                continue

            details["model_type"] = detector.model_type(display_mac)

            alerter.dispatch(severity, src_ip, display_mac, description, details)
            state.record_alert(display_mac, "ml-isolation-forest", severity)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
