"""
IoT Security Gateway — ML Pipeline (Placeholder)

This script watches for Zeek log files on the shared volume and
demonstrates the log-consumption and Ryu-integration pattern.

Currently a placeholder analysis script that needs replacing.

Just demonstrates how log ingestion and alerting would work.
"""

import os
import time
import json
import requests
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ML-Pipeline] %(levelname)s: %(message)s",
)
LOG = logging.getLogger(__name__)

# Paths
ZEEK_LOG_DIR = "/opt/zeek-logs"
RYU_API_URL = os.environ.get("RYU_API_URL", "http://ryu:8080")

# How often to check for new log data (seconds)
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "10"))


def process_conn_log(filepath: str):
    """
    Placeholder: Read Zeek's conn.log and perform analysis.

    In a real implementation, this would:
    - Parse the TSV log into a DataFrame
    - Run feature extraction
    - Perform inference with a trained model
    - Return a list of suspicious flows/devices
    """
    LOG.info("Processing %s", filepath)
    # TODO: Replace with actual model inference
    return []


def alert_ryu(action: dict):
    """
    Send a dynamic policy request to the Ryu controller's REST API.

    Example action:
    {
        "action": "isolate",
        "mac": "aa:bb:cc:dd:ee:ff",
        "reason": "anomalous DNS volume"
    }
    """
    try:
        resp = requests.post(
            f"{RYU_API_URL}/api/policy",
            json=action,
            timeout=5,
        )
        LOG.info("Ryu response: %s %s", resp.status_code, resp.text)
    except requests.exceptions.ConnectionError:
        LOG.warning("Cannot reach Ryu at %s — is it running?", RYU_API_URL)
    except Exception as e:
        LOG.error("Error contacting Ryu: %s", e)


def main():
    LOG.info("ML Pipeline started. Watching %s", ZEEK_LOG_DIR)
    LOG.info("Ryu API endpoint: %s", RYU_API_URL)

    while True:
        conn_log = os.path.join(ZEEK_LOG_DIR, "current", "conn.log")

        if os.path.exists(conn_log):
            suspicious = process_conn_log(conn_log)
            for finding in suspicious:
                alert_ryu(finding)
        else:
            LOG.debug("No conn.log found yet at %s", conn_log)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
