#!/usr/bin/env python3
"""systemd OnFailure= handler: make a failed maintenance/backup run visible.

Started by systemd when a monitored unit fails, with that unit's name as the
single argument. It always logs the failure to the journal (so `systemctl` /
`journalctl` show it), and — if a webhook is configured — posts a short report
so the failure reaches you off-box instead of sitting silently on the Pi.

Environment (from /etc/pihole-alerting/env):
  NOTIFY_WEBHOOK_URL  where to POST the report (e.g. an ntfy topic). Empty =>
                      journal only, no webhook.
"""
import socket
import subprocess
import sys
import urllib.request

TITLE = "Pi-hole alert"


def build_message(unit, host, journal_text):
    """Human-readable failure report naming the unit, host, and recent logs."""
    tail = journal_text.strip() or "(no recent journal output)"
    return f"{host}: unit {unit} FAILED\n\n{tail}"


def build_request(url, message, title):
    """POST request carrying the report as its body (ntfy-compatible Title)."""
    return urllib.request.Request(
        url, data=message.encode("utf-8"), method="POST",
        headers={"Title": title, "Content-Type": "text/plain; charset=utf-8"})


def should_notify(url):
    """Only reach out over the network when a webhook URL is actually set."""
    return bool(url)


def journal_tail(unit, lines=20):
    """Last few journal lines for the failed unit; '' if journalctl is unavailable."""
    try:
        return subprocess.run(
            ["journalctl", "-u", unit, "-n", str(lines), "--no-pager"],
            capture_output=True, text=True, timeout=15).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def main(argv, env):
    unit = argv[1] if len(argv) > 1 else "unknown.unit"
    host = socket.gethostname()
    message = build_message(unit, host, journal_tail(unit))

    # Always record it locally, regardless of webhook config.
    subprocess.run(["logger", "-t", "pihole-alert", "-p", "user.err",
                    f"{unit} failed"], check=False)

    url = env.get("NOTIFY_WEBHOOK_URL", "")
    if should_notify(url):
        try:
            urllib.request.urlopen(build_request(url, message, TITLE), timeout=15)
        except OSError as e:
            # A down webhook must not mask the original failure; log and move on.
            subprocess.run(["logger", "-t", "pihole-alert", "-p", "user.err",
                            f"failed to post alert: {e}"], check=False)


if __name__ == "__main__":
    import os
    main(sys.argv, os.environ)
