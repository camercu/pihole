"""Unit tests for the pure core of notify_failure.py."""
import types

import notify_failure as n


def _record_subprocess(monkeypatch, stdout=""):
    """Replace subprocess.run with a recorder; return the list of argv it saw."""
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return types.SimpleNamespace(stdout=stdout)

    monkeypatch.setattr(n.subprocess, "run", fake_run)
    return calls


def test_main_tails_the_journal_for_the_exact_unit_that_failed(monkeypatch):
    # The report's whole value is the failed unit's recent logs. main() must
    # query journalctl for the unit name it was handed, verbatim — no mangling
    # (guards the @.service template's %i-vs-%I choice from the script side).
    calls = _record_subprocess(monkeypatch, stdout="recent log line\n")

    n.main(["notify_failure.py", "pihole-backup.service"], {})  # no webhook

    journalctl = next(c for c in calls if c[0] == "journalctl")
    assert "pihole-backup.service" in journalctl
    assert "pihole/backup.service" not in journalctl


def test_main_survives_a_malformed_webhook_url(monkeypatch):
    # A misconfigured webhook (e.g. no scheme) makes urlopen raise ValueError,
    # not OSError. The notifier must log and move on, never crash — a broken
    # webhook must not mask the original unit failure it was told to report.
    calls = _record_subprocess(monkeypatch)

    n.main(["notify_failure.py", "pihole-backup.service"],
           {"NOTIFY_WEBHOOK_URL": "ntfy.sh/topic"})  # scheme-less on purpose

    joined = [" ".join(map(str, c)) for c in calls]
    # The original unit failure was still recorded (not masked by the bad webhook)...
    assert any("pihole-backup.service failed" in c for c in joined)
    # ...and the post failure fell back to a log line rather than raising.
    assert any("failed to post alert" in c for c in joined)


def test_main_without_a_webhook_makes_no_network_call(monkeypatch):
    _record_subprocess(monkeypatch)

    def fail_if_called(*a, **k):
        raise AssertionError("urlopen must not run when no webhook is configured")

    monkeypatch.setattr(n.urllib.request, "urlopen", fail_if_called)
    n.main(["notify_failure.py", "pihole-backup.service"], {})


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
