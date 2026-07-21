"""Unit tests for the pure core of notify_failure.py."""
import notify_failure as n


def test_build_message_names_the_failed_unit_and_host():
    msg = n.build_message("maint-pihole-gravity.service", "pi-dns", "line1\nline2\n")
    assert "maint-pihole-gravity.service" in msg
    assert "pi-dns" in msg
    assert "line1" in msg and "line2" in msg


def test_build_message_tolerates_empty_journal():
    msg = n.build_message("pihole-backup.service", "pi-dns", "")
    assert "pihole-backup.service" in msg


def test_build_request_posts_message_body_with_title_header():
    req = n.build_request("https://ntfy.sh/mytopic", "boom", "Pi-hole alert")
    assert req.full_url == "https://ntfy.sh/mytopic"
    assert req.get_method() == "POST"
    assert req.data == b"boom"
    assert req.headers["Title"] == "Pi-hole alert"


def test_should_notify_is_false_without_a_url():
    assert n.should_notify("") is False
    assert n.should_notify(None) is False


def test_should_notify_is_true_with_a_url():
    assert n.should_notify("https://ntfy.sh/x") is True
