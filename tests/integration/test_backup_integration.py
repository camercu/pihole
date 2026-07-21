"""End-to-end test: the backup script exports and restic can restore it.

Proves the whole chain works against real tools — Teleporter export over the FTL
API, restic backup with our tags/retention, and a restore that yields the exact
bundle back. An untested backup is not a backup.
"""
import json
import os
import subprocess
import zipfile

import pytest

pytestmark = pytest.mark.integration


def _restic(repo_env, *args):
    return subprocess.run(["restic", *args], env=repo_env, text=True,
                          capture_output=True, check=True)


def test_backup_export_and_restore_round_trip(pihole, tmp_path):
    repo = tmp_path / "repo"
    staging = tmp_path / "staging"
    restore = tmp_path / "restore"
    restic_env = {
        "RESTIC_REPOSITORY": str(repo),
        "RESTIC_PASSWORD": "test-restic-pw",
        "BACKUP_STAGING": str(staging),
        "RESTIC_KEEP_WEEKLY": "2",
    }
    repo_env = {**os.environ, **restic_env}
    _restic(repo_env, "init")

    r = pihole.run_backup(restic_env)
    assert r.returncode == 0, r.stderr
    assert "backup OK" in r.stdout

    snaps = json.loads(_restic(repo_env, "snapshots", "--json").stdout)
    assert len(snaps) == 1
    assert "pihole" in snaps[0]["tags"]

    _restic(repo_env, "restore", "latest", "--target", str(restore))
    bundles = list(restore.rglob("pihole-teleporter.zip"))
    assert bundles, "restored snapshot has no teleporter bundle"
    with zipfile.ZipFile(bundles[0]) as z:
        assert "etc/pihole/pihole.toml" in z.namelist()  # a real Pi-hole config

    # The staging bundle is removed after the run (finally-clause cleanup).
    assert not (staging / "pihole-teleporter.zip").exists()
