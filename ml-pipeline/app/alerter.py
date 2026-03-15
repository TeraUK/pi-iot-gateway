"""
IoT Security Gateway - ML Pipeline Alert Dispatcher

Writes alert events to ml_alerts.log and, for CRITICAL severity alerts,
POST a device isolation request to the Ryu REST API.

The alert log format deliberately mirrors the schema used by Zeek's
alert-framework.zeek so that both sources can be parsed by the same tooling:

  {
    "ts":          ISO-8601 timestamp string,
    "severity":    "INFO" | "WARNING" | "CRITICAL",
    "detector":    "ml-isolation-forest",
    "src_ip":      source IP of the flagged device,
    "src_mac":     MAC address (resolved from dhcp.log, or "unknown"),
    "description": human-readable summary,
    "details":     JSON-encoded dict of anomaly metadata,
    "action_taken": "logged" | "isolate_requested" | "dry_run" | "isolate_failed"
  }

Ryu integration
---------------
POST /policy/isolate with body {"mac": "<mac>", "reason": "<reason>"}.
On failure it retries with exponential backoff up to MAX_RETRIES times before
giving up and logging a warning. The isolation is still logged even if the
Ryu call fails.

Auto-isolation mode
-------------------
When AUTO_ISOLATE is False (the default, matching Zeek's auto_isolate = F),
CRITICAL alerts are logged with action_taken = "dry_run" and no Ryu call is
made. Set the ML_AUTO_ISOLATE environment variable to "true" to enable.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

import requests

LOG = logging.getLogger(__name__)

# Path to the alert log file on the shared Zeek logs volume.
ALERT_LOG_PATH = os.environ.get(
    "ML_ALERT_LOG", "/opt/zeek-logs/ml_alerts.log"
)

# Ryu REST API base URL.
RYU_API_URL = os.environ.get("RYU_API_URL", "http://ryu:8080")

# When True, CRITICAL alerts trigger a POST to Ryu's /policy/isolate.
# Keep False until detections have been validated against real traffic.
AUTO_ISOLATE = os.environ.get("ML_AUTO_ISOLATE", "false").lower() == "true"

# Retry settings for Ryu API calls.
MAX_RETRIES    = 3
RETRY_BASE_SEC = 2.0   # Exponential backoff base (doubles each attempt).

# The detector identifier written to every alert log entry.
DETECTOR_NAME = "ml-isolation-forest"


class Alerter:
    """Writes alert log entries and optionally calls Ryu to isolate devices."""

    def __init__(self) -> None:
        self._log_fh = None
        self._open_log()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dispatch(
        self,
        severity:    str,
        src_ip:      str,
        src_mac:     str,
        description: str,
        details:     dict,
    ) -> None:
        """
        Emit an alert.

        For CRITICAL alerts, also call Ryu to isolate the device
        (when AUTO_ISOLATE is enabled).
        """
        action = self._determine_action(severity, src_mac)
        entry  = self._build_entry(severity, src_ip, src_mac, description, details, action)
        self._write_log(entry)

        if action == "isolate_requested":
            success = self._call_ryu_isolate(src_mac, description)
            if not success:
                # Update the logged action to reflect the failure.
                entry["action_taken"] = "isolate_failed"
                LOG.warning(
                    "Ryu isolation call failed for %s (%s). "
                    "The device has NOT been isolated. Manual action required.",
                    src_mac, src_ip,
                )

        LOG.info(
            "[%s] %s | %s | %s | action=%s",
            severity, src_mac, src_ip, description[:80], entry["action_taken"],
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _determine_action(self, severity: str, src_mac: str) -> str:
        """Decide what action to log based on severity and AUTO_ISOLATE flag."""
        if severity != "CRITICAL":
            return "logged"
        if not AUTO_ISOLATE:
            return "dry_run"
        if src_mac == "unknown":
            # Cannot isolate without a MAC address.
            return "isolate_failed"
        return "isolate_requested"

    @staticmethod
    def _build_entry(
        severity:    str,
        src_ip:      str,
        src_mac:     str,
        description: str,
        details:     dict,
        action:      str,
    ) -> dict:
        """Build the alert log entry dict."""
        return {
            "ts":           datetime.now(timezone.utc).isoformat(),
            "severity":     severity,
            "detector":     DETECTOR_NAME,
            "src_ip":       src_ip,
            "src_mac":      src_mac,
            "description":  description,
            "details":      json.dumps(details),
            "action_taken": action,
        }

    def _write_log(self, entry: dict) -> None:
        """Append the alert entry to ml_alerts.log as a JSON line."""
        try:
            self._open_log()
            line = json.dumps(entry, ensure_ascii=False)
            self._log_fh.write(line + "\n")
            self._log_fh.flush()
        except OSError as exc:
            LOG.error("Failed to write alert log: %s", exc)

    def _open_log(self) -> None:
        """Open (or reopen) the alert log file in append mode."""
        if self._log_fh is not None and not self._log_fh.closed:
            return
        try:
            os.makedirs(os.path.dirname(ALERT_LOG_PATH), exist_ok=True)
            self._log_fh = open(ALERT_LOG_PATH, "a", encoding="utf-8")
        except OSError as exc:
            LOG.error("Cannot open alert log at %s: %s", ALERT_LOG_PATH, exc)
            self._log_fh = None

    def _call_ryu_isolate(self, mac: str, reason: str) -> bool:
        """
        POST an isolation request to the Ryu REST API.

        Retries up to MAX_RETRIES times with exponential backoff.
        Returns True if the request succeeded, False otherwise.
        """
        url     = f"{RYU_API_URL}/policy/isolate"
        payload = {
            "mac":    mac,
            "reason": f"ML pipeline (auto-isolation): {reason}",
        }

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                resp = requests.post(url, json=payload, timeout=5)
                if resp.status_code == 200:
                    LOG.info("Ryu isolation ACK for %s: %s", mac, resp.text[:120])
                    return True
                LOG.warning(
                    "Ryu returned HTTP %d for isolate %s (attempt %d/%d): %s",
                    resp.status_code, mac, attempt, MAX_RETRIES, resp.text[:120],
                )
            except requests.exceptions.ConnectionError:
                LOG.warning(
                    "Cannot reach Ryu at %s (attempt %d/%d).",
                    RYU_API_URL, attempt, MAX_RETRIES,
                )
            except requests.exceptions.Timeout:
                LOG.warning(
                    "Ryu API timed out for isolate %s (attempt %d/%d).",
                    mac, attempt, MAX_RETRIES,
                )
            except Exception as exc:
                LOG.error("Unexpected error calling Ryu: %s", exc)
                return False

            if attempt < MAX_RETRIES:
                backoff = RETRY_BASE_SEC * (2 ** (attempt - 1))
                LOG.debug("Retrying Ryu call in %.1fs.", backoff)
                time.sleep(backoff)

        return False
