"""Unit tests for the pure argv builders in pihole_backup.py."""
import pihole_backup as b


class TestBackupArgv:
    def test_tags_the_snapshot_and_backs_up_the_bundle(self):
        assert b.backup_argv("/var/backups/pihole/x.zip") == [
            "restic", "backup", "--tag", "pihole", "/var/backups/pihole/x.zip"]


class TestForgetArgv:
    def test_retention_groups_by_host_and_tags_and_prunes(self):
        assert b.forget_argv("8") == [
            "restic", "forget", "--tag", "pihole",
            "--group-by", "host,tags", "--keep-weekly", "8", "--prune"]

    def test_keep_count_is_passed_through(self):
        assert "3" in b.forget_argv("3")
