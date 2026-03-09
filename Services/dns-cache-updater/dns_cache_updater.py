#!/usr/bin/env python3
"""
IoT Security Gateway - DNS Cache Updater

This script runs on the gateway host as a systemd service. It watches
Zeek's dns.log for new entries, extracts domain-to-IP mappings, and
pushes them to the Ryu REST API. This keeps Ryu's DNS cache current so
that domain-based allowlists resolve to the correct IPs.

The script only pushes mappings for domains that appear in at least one
device profile's allowed_domains list. This avoids polluting the cache
with irrelevant domains.

Usage:
    # Run directly (for testing):
    python3 dns_cache_updater.py

    # As a systemd service:
    sudo cp dns-cache-updater.service /etc/systemd/system/
    sudo systemctl enable dns-cache-updater
    sudo systemctl start dns-cache-updater

Environment variables:
    ZEEK_DNS_LOG    Path to Zeek's current dns.log (default: see below)
    RYU_API_URL     Ryu REST API base URL (default: http://127.0.0.1:8080)
    POLL_INTERVAL   Seconds between log checks (default: 10)
"""

import json
import logging
import os
import sys
import time
from collections import defaultdict

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DNS-Cache-Updater] %(levelname)s: %(message)s",
)
LOG = logging.getLogger(__name__)

# -- Configuration --

# Path to Zeek's current dns.log file inside the container.
# The script runs on the host and uses docker exec to read it.
ZEEK_CONTAINER = os.environ.get("ZEEK_CONTAINER", "zeek")
ZEEK_DNS_LOG = os.environ.get("ZEEK_DNS_LOG", "/opt/zeek-logs/current/dns.log")

# Ryu REST API.
RYU_API_URL = os.environ.get("RYU_API_URL", "http://127.0.0.1:8080")

# How often to check for new log entries.
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "10"))

# How often to do a full refresh of all domain mappings (seconds).
FULL_REFRESH_INTERVAL = int(os.environ.get("FULL_REFRESH_INTERVAL", "300"))


def get_allowed_domains():
    """
    Fetch the list of allowed domains from all device profiles via
    the Ryu REST API.
    """
    try:
        resp = requests.get(f"{RYU_API_URL}/policy/allowlists", timeout=5)
        if resp.status_code != 200:
            LOG.warning("Failed to fetch allowlists: HTTP %d", resp.status_code)
            return set()

        data = resp.json()
        domains = set()
        for mac, profile in data.get("profiles", {}).items():
            for domain in profile.get("allowed_domains", []):
                domains.add(domain.lower())
        return domains
    except requests.exceptions.ConnectionError:
        LOG.warning("Cannot reach Ryu at %s", RYU_API_URL)
        return set()
    except Exception as e:
        LOG.error("Error fetching allowlists: %s", e)
        return set()


def read_dns_log_tail(last_position):
    """
    Read new entries from Zeek's dns.log via docker exec.

    Returns (entries, new_position).
    """
    import subprocess

    # Docker exec is used to read the log file inside the Zeek container.
    # This avoids needing to know the Docker volume mount path on the host.
    try:
        result = subprocess.run(
            ["docker", "exec", ZEEK_CONTAINER, "cat", ZEEK_DNS_LOG],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return [], last_position

        content = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return [], last_position

    # Only process lines we have not seen before.
    lines = content.split("\n")
    new_entries = []

    for i, line in enumerate(lines):
        if i < last_position:
            continue
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            entry = json.loads(line)
            new_entries.append(entry)
        except json.JSONDecodeError:
            continue

    return new_entries, len(lines)


def extract_mappings(entries, allowed_domains):
    """
    Extract domain-to-IP mappings from DNS log entries.

    Only returns mappings for domains in the allowed_domains set.
    """
    mappings = defaultdict(set)

    for entry in entries:
        query = entry.get("query", "").lower()
        answers = entry.get("answers", [])

        if not query or not answers:
            continue

        # Only track domains that are in a device profile.
        if query not in allowed_domains:
            continue

        for answer in answers:
            if not answer:
                continue
            # Check if the answer looks like an IPv4 address.
            parts = answer.split(".")
            try:
                if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                    mappings[query].add(answer)
            except ValueError:
                continue

    return mappings


def push_to_ryu(mappings):
    """Post domain-to-IP mappings to the Ryu REST API."""
    if not mappings:
        return

    # Convert sets to lists for JSON serialisation.
    payload = {
        "mappings": {domain: sorted(ips) for domain, ips in mappings.items()}
    }

    try:
        resp = requests.post(
            f"{RYU_API_URL}/policy/dns-cache",
            json=payload,
            timeout=5,
        )
        if resp.status_code == 200:
            LOG.info(
                "Pushed %d domain mappings to Ryu (%d total IPs)",
                len(mappings),
                sum(len(ips) for ips in mappings.values()),
            )
        else:
            LOG.warning("Ryu returned HTTP %d: %s", resp.status_code, resp.text)
    except requests.exceptions.ConnectionError:
        LOG.warning("Cannot reach Ryu at %s", RYU_API_URL)
    except Exception as e:
        LOG.error("Error pushing to Ryu: %s", e)


def main():
    LOG.info("DNS Cache Updater started")
    LOG.info("  Zeek container: %s", ZEEK_CONTAINER)
    LOG.info("  DNS log path: %s", ZEEK_DNS_LOG)
    LOG.info("  Ryu API: %s", RYU_API_URL)
    LOG.info("  Poll interval: %ds", POLL_INTERVAL)
    LOG.info("  Full refresh interval: %ds", FULL_REFRESH_INTERVAL)

    last_position = 0
    allowed_domains = set()
    last_domain_refresh = 0
    all_mappings = defaultdict(set)  # Cumulative mappings for full refresh.

    while True:
        now = time.time()

        # Periodically refresh the allowed domains list from Ryu.
        if now - last_domain_refresh > FULL_REFRESH_INTERVAL:
            allowed_domains = get_allowed_domains()
            if allowed_domains:
                LOG.info("Tracking %d allowed domains from device profiles", len(allowed_domains))
            last_domain_refresh = now

            # On a full refresh, push all accumulated mappings.
            if all_mappings:
                push_to_ryu(all_mappings)

        # Read new DNS log entries.
        entries, last_position = read_dns_log_tail(last_position)

        if entries and allowed_domains:
            mappings = extract_mappings(entries, allowed_domains)
            if mappings:
                # Accumulate mappings.
                for domain, ips in mappings.items():
                    all_mappings[domain].update(ips)
                push_to_ryu(mappings)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
