# DNS Cache Updater Service

## Overview

This service bridges the gap between domain-based device allowlists and
OVS's IP-only matching capability. OVS flow rules can only match on IP
addresses, but device profiles define allowed destinations by domain
name (e.g. `api.vendor.com`). The DNS cache updater solves this by
monitoring Zeek's DNS logs for resolution results and pushing the
domain-to-IP mappings to Ryu's in-memory cache. When Ryu evaluates a
packet from a profiled device, it checks the destination IP against these
cached mappings to determine whether the traffic matches a domain-based
allowlist entry.

## How It Works

1. On startup, the service queries Ryu's REST API at
   `GET /policy/allowlists` to fetch the list of domains that appear
   in any device profile's `allowed_domains` field. Only these domains
   are tracked.

2. Every `POLL_INTERVAL` seconds (default 10), it reads new entries from
   Zeek's `dns.log` inside the Zeek container via `docker exec`.

3. For each DNS response where the queried domain is in the tracked set,
   it extracts the resolved IPv4 addresses from the answer records.

4. It posts the domain-to-IP mappings to Ryu via
   `POST /policy/dns-cache`.

5. Every `FULL_REFRESH_INTERVAL` seconds (default 300), it re-fetches
   the allowed domains list from Ryu (in case profiles were reloaded)
   and pushes all accumulated mappings as a batch.

## Dependencies

The service requires the following to be running:

- **Ryu container** (`ryu-controller`): provides the REST API that the
  updater reads from and writes to.
- **Zeek container** (`zeek`): provides the dns.log that the updater
  reads via `docker exec`.
- **Docker**: the service uses `docker exec` to read log files from
  inside the Zeek container without needing to know the volume mount
  path on the host.
- **Python 3** with the `requests` library.

## Installation

```bash
# Copy the script.
sudo cp scripts/dns_cache_updater.py /usr/local/bin/dns_cache_updater.py
sudo chmod +x /usr/local/bin/dns_cache_updater.py

# Ensure the requests library is available.
sudo pip3 install requests --break-system-packages

# Copy the systemd unit file.
sudo cp systemd/dns-cache-updater.service /etc/systemd/system/

# Reload systemd, enable, and start.
sudo systemctl daemon-reload
sudo systemctl enable dns-cache-updater
sudo systemctl start dns-cache-updater
```

## Configuration

All configuration is done through environment variables, set in the
systemd unit file under the `[Service]` section.

| Variable              | Default                          | Description                                                         |
|-----------------------|----------------------------------|---------------------------------------------------------------------|
| `ZEEK_CONTAINER`      | `zeek`                           | Name of the Docker container running Zeek.                          |
| `ZEEK_DNS_LOG`        | `/opt/zeek-logs/current/dns.log` | Path to dns.log inside the Zeek container.                          |
| `RYU_API_URL`         | `http://127.0.0.1:8080`         | Base URL for the Ryu REST API.                                      |
| `POLL_INTERVAL`       | `10`                             | Seconds between checks for new dns.log entries.                     |
| `FULL_REFRESH_INTERVAL`| `300`                           | Seconds between full re-fetches of the allowed domains list and batch pushes of all accumulated mappings. |

To change a value, edit the service file:

```bash
sudo systemctl edit dns-cache-updater
```

This creates an override file where the admin can add or replace 
environment variables without modifying the original unit file:

```ini
[Service]
Environment=POLL_INTERVAL=5
Environment=FULL_REFRESH_INTERVAL=120
```

Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl restart dns-cache-updater
```

## Managing the Service

```bash
# Check status.
sudo systemctl status dns-cache-updater

# View recent logs.
sudo journalctl -u dns-cache-updater --since "10 minutes ago"

# Follow logs in real time.
sudo journalctl -u dns-cache-updater -f

# Stop the service.
sudo systemctl stop dns-cache-updater

# Disable (prevent starting on boot).
sudo systemctl disable dns-cache-updater
```

## Verifying It Works

After starting the service, the user can confirm it is populating the DNS cache
by querying Ryu:

```bash
curl -s http://127.0.0.1:8080/policy/dns-cache | python3 -m json.tool
```

If profiles are loaded with `allowed_domains` entries and IoT devices are
generating DNS traffic, you should see domain-to-IP mappings with recent
timestamps. If the cache is empty, check:

- The service is running: `sudo systemctl status dns-cache-updater`
- The Zeek container is running and producing dns.log entries:
  `docker exec zeek ls -la /opt/zeek-logs/current/dns.log`
- Device profiles have `allowed_domains` entries:
  `curl -s http://127.0.0.1:8080/policy/allowlists | python3 -m json.tool`
- The service logs for errors:
  `sudo journalctl -u dns-cache-updater --since "5 minutes ago"`

## Behaviour on Failure

The service is configured with `Restart=on-failure` and `RestartSec=10`
in the systemd unit file. If the script crashes (e.g. due to an unhandled
exception), systemd will restart it after 10 seconds.

If the Ryu container is not running, the service logs a warning and
continues polling. It does not crash. Once Ryu comes back, the next poll
cycle will successfully push mappings.

If the Zeek container is not running, `docker exec` returns a non-zero
exit code and the service skips that poll cycle. Again, it does not crash.

## Known Limitations

- The DNS cache is stored in Ryu's process memory. If Ryu restarts, the
  cache is lost and the updater needs a few poll cycles to repopulate it.
  During that window, domain-based allowlist entries will not resolve and
  profiled devices may be temporarily denied access to domain-only
  destinations. Static CIDR entries in the profile are not affected.

- The script reads the entire dns.log file on each poll and tracks its
  position by line count. If Zeek rotates the log file between polls,
  the script resets to position 0 and reprocesses from the start of the
  new file. This is harmless (duplicate pushes are idempotent) but
  means there may be a brief gap where entries from the tail of the
  old file are missed. In practice, the full refresh cycle catches
  these within `FULL_REFRESH_INTERVAL` seconds.

- Reading the entire dns.log file may become resource intensive as it gets 
  bigger. It may be a better idea so index the logs and record the
  last seen index value. Aggregating the logs into a database is planned, 
  at which point this service will be reviewed.

- Only IPv4 addresses are extracted from DNS answer records. IPv6 (AAAA)
  records are ignored, which is consistent with the gateway's IPv4-only
  flow rules.
