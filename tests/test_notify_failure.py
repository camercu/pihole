"""Unit tests for the pure core of notify_failure.py."""
import notify_failure as n


class TestBuildMessage:
    def test_names_the_failed_unit_and_host(self):
        msg = n.build_message("maint-pihole-gravity.service", "pi-dns",
                              "line1\nline2\n")
        assert "maint-pihole-gravity.service" in msg
        assert "pi-dns" in msg
        assert "line1" in msg and "line2" in msg

    def test_tolerates_empty_journal(self):
        msg = n.build_message("pihole-backup.service", "pi-dns", "")
        assert "pihole-backup.service" in msg


class TestBuildRequest:
    def test_posts_message_body_with_title_header(self):
        req = n.build_request("https://ntfy.sh/mytopic", "boom", "Pi-hole alert")
        assert req.full_url == "https://ntfy.sh/mytopic"
        assert req.get_method() == "POST"
        assert req.data == b"boom"
        assert req.headers["Title"] == "Pi-hole alert"


class TestShouldNotify:
    def test_no_url_means_no_webhook(self):
        assert n.should_notify("") is False
        assert n.should_notify(None) is False

    def test_url_present_means_webhook(self):
        assert n.should_notify("https://ntfy.sh/x") is True
