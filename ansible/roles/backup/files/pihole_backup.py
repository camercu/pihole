#!/usr/bin/env python3
"""Weekly Pi-hole backup: export a Teleporter bundle via the FTL API and store
it in a restic repository (encrypted, deduplicated, incremental).

Reads everything from the environment (see /etc/pihole-backup/env):
  RESTIC_REPOSITORY, RESTIC_PASSWORD   restic target + repo password (used by
                                       restic directly)
  PIHOLE_PASSWORD    admin/API password ('' => API needs no auth)
  PIHOLE_API         API base (default http://localhost/api)
  RESTIC_KEEP_WEEKLY snapshots to retain (default 8)
"""
import json
import os
import subprocess
import urllib.request

API = os.environ.get("PIHOLE_API", "http://localhost/api")
PW = os.environ.get("PIHOLE_PASSWORD", "")
KEEP = os.environ.get("RESTIC_KEEP_WEEKLY", "8")
# Stable path so every snapshot shares one restic path/group (retention relies
# on grouping; a random temp path would make every run its own group).
STAGING = os.environ.get("BACKUP_STAGING", "/var/backups/pihole")


def login():
    if not PW:
        return ""  # no password set => API accepts unauthenticated calls
    req = urllib.request.Request(
        API + "/auth",
        data=json.dumps({"password": PW}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)["session"]["sid"]


def export_teleporter(sid, dest):
    url = API + "/teleporter" + (f"?sid={sid}" if sid else "")
    with urllib.request.urlopen(url, timeout=30) as r, open(dest, "wb") as f:
        f.write(r.read())


def main():
    sid = login()
    os.makedirs(STAGING, exist_ok=True)
    bundle = os.path.join(STAGING, "pihole-teleporter.zip")
    try:
        export_teleporter(sid, bundle)
        # restic reads RESTIC_REPOSITORY / RESTIC_PASSWORD from the environment.
        subprocess.run(["restic", "backup", "--tag", "pihole", bundle], check=True)
        subprocess.run(
            ["restic", "forget", "--tag", "pihole", "--group-by", "host,tags",
             "--keep-weekly", KEEP, "--prune"],
            check=True,
        )
    finally:
        if os.path.exists(bundle):
            os.remove(bundle)
    print("backup OK")


if __name__ == "__main__":
    main()
