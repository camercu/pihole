"""Unit tests for the pure argv builders in pihole_backup.py."""
import pihole_backup as b


def test_backup_argv_tags_the_snapshot_and_backs_up_the_bundle():
    assert b.backup_argv("/var/backups/pihole/x.zip") == [
        "restic", "backup", "--tag", "pihole", "/var/backups/pihole/x.zip"]


def test_forget_argv_groups_by_host_and_tags_and_prunes():
    assert b.forget_argv("8") == [
        "restic", "forget", "--tag", "pihole",
        "--group-by", "host,tags", "--keep-weekly", "8", "--prune"]


def test_forget_argv_passes_the_keep_count_through():
    assert "3" in b.forget_argv("3")
