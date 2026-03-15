"""
IoT Security Gateway - ML Pipeline Log Ingestor

I tail Zeek's JSON log files on the shared volume, reading only new lines
since the last poll. On each call to poll(), the ingestor returns a dict of
log type -> list of parsed JSON entries.

Log types I consume:
  conn  - connection summary log (features: bytes, duration, ports, states)
  dns   - DNS query/response log (features: query rate, NXDOMAIN, entropy)
  dhcp  - DHCP lease log (used for IP->MAC resolution, not scoring)
  http  - HTTP transaction log (future features: user-agent, status codes)
  ssl   - TLS connection log (future features: invalid cert rate)

I detect Zeek's hourly log rotation by tracking each file's inode. When the
inode changes (the old file was renamed and a new one created), I reset the
read position to 0.

Zeek writes logs to the working directory set in docker-compose.yml:
  /opt/zeek-logs/conn.log, /opt/zeek-logs/dns.log, etc.
"""

import json
import logging
import os

LOG = logging.getLogger(__name__)

# Log types to consume and the file names they correspond to.
LOG_FILES: dict[str, str] = {
    "conn": "conn.log",
    "dns":  "dns.log",
    "dhcp": "dhcp.log",
    "http": "http.log",
    "ssl":  "ssl.log",
}


class LogIngestor:
    """
    Tails a set of Zeek log files, returning new JSON entries on each poll.

    I maintain the byte offset and inode for each file so I can resume
    reading after a restart and detect log rotation correctly.
    """

    def __init__(self, log_dir: str) -> None:
        self.log_dir = log_dir

        # Byte offset for each log type.
        self._positions: dict[str, int] = {lt: 0 for lt in LOG_FILES}

        # Inode of each log file as last seen.
        self._inodes: dict[str, int] = {lt: -1 for lt in LOG_FILES}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def poll(self) -> dict[str, list[dict]]:
        """
        Read any new lines from every tracked log file.

        Returns a dict mapping log type to a list of parsed JSON entries.
        Unparseable lines are skipped with a debug-level warning.
        """
        results: dict[str, list[dict]] = {lt: [] for lt in LOG_FILES}

        for log_type, filename in LOG_FILES.items():
            path = os.path.join(self.log_dir, filename)
            entries = self._read_new_lines(log_type, path)
            results[log_type] = entries

        return results

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _read_new_lines(self, log_type: str, path: str) -> list[dict]:
        """
        Open the file at the stored position, read new lines, update position.

        I detect rotation by comparing the current file's inode to the stored
        one. If they differ, the file has been rotated and I reset to position 0.
        """
        if not os.path.exists(path):
            return []

        try:
            stat = os.stat(path)
        except OSError:
            return []

        current_inode = stat.st_ino
        stored_inode = self._inodes.get(log_type, -1)

        # Detect rotation: inode changed means a new file was created.
        if current_inode != stored_inode:
            LOG.info("Log rotation detected for %s (inode %d -> %d), resetting offset.",
                     log_type, stored_inode, current_inode)
            self._positions[log_type] = 0
            self._inodes[log_type] = current_inode

        position = self._positions.get(log_type, 0)

        # If the file is smaller than our stored position, it was truncated.
        # This should not happen under normal operation but handle it defensively.
        if stat.st_size < position:
            LOG.warning("File %s shrank unexpectedly (was %d, now %d). Resetting.",
                        path, position, stat.st_size)
            position = 0

        if stat.st_size == position:
            # No new data.
            return []

        entries: list[dict] = []

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(position)
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    try:
                        entry = json.loads(line)
                        entries.append(entry)
                    except json.JSONDecodeError:
                        LOG.debug("Skipping non-JSON line in %s: %.80s", log_type, line)

                # Store the position after all the lines we read.
                self._positions[log_type] = fh.tell()

        except OSError as exc:
            LOG.warning("Could not read %s: %s", path, exc)

        if entries:
            LOG.debug("Ingested %d new entries from %s.", len(entries), log_type)

        return entries
