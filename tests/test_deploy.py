"""Unit tests for the pure decision logic in pihole_deploy.py."""
import pihole_deploy as deploy
import pytest


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class _FakeResponse:
    """Stands in for the object urllib.request.urlopen returns."""

    def __init__(self, text):
        self._body = text.encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_clean_lines_strips_comments_blanks_and_whitespace():
    text = "a.com\n  b.com  \n# comment\n\nc.com # trailing\n"
    assert deploy.clean_lines(text) == ["a.com", "b.com", "c.com"]


def test_clean_lines_empty_input():
    assert deploy.clean_lines("") == []


def test_clean_lines_only_comments():
    assert deploy.clean_lines("# one\n   # two\n") == []


def test_plain_domains_are_not_regex():
    for d in ["www.facebook.com", "example.co.uk", "a-b.example.com"]:
        assert not deploy.is_regex(d)


def test_real_regex_pattern_detected():
    # from the actual allow.list
    assert deploy.is_regex(r"(\.|^)twimg\.com$")


def test_regex_metacharacters_detected():
    for pat in ["a|b", "x*", "^host", "end$", "grp(x)", "[abc]"]:
        assert deploy.is_regex(pat)


def test_split_allow_partitions_exact_and_regex():
    exact, regex = deploy.split_allow(["a.com", r"(\.|^)twimg\.com$", "b.com"])
    assert exact == ["a.com", "b.com"]
    assert regex == [r"(\.|^)twimg\.com$"]


def test_split_allow_empty():
    assert deploy.split_allow([]) == ([], [])


def test_host_domain_plain_domain():
    assert deploy.host_domain("example.com") == "example.com"


def test_host_domain_hosts_format_prefix_stripped():
    assert deploy.host_domain("0.0.0.0 example.com") == "example.com"
    assert deploy.host_domain("127.0.0.1\texample.com") == "example.com"


def test_fetch_domains_reports_its_own_success(monkeypatch):
    monkeypatch.setattr(
        deploy.urllib.request, "urlopen",
        lambda url, timeout=30: _FakeResponse("a.example\nb.example\n"))

    domains, ok = deploy.fetch_domains("http://list.example/a.txt")

    assert domains == ["a.example", "b.example"]
    assert ok is True


def test_fetch_domains_reports_failure_without_raising(monkeypatch, capsys):
    def boom(url, timeout=30):
        raise deploy.urllib.error.URLError("connection refused")
    monkeypatch.setattr(deploy.urllib.request, "urlopen", boom)

    domains, ok = deploy.fetch_domains("http://dead.example/a.txt")

    assert domains == []
    assert ok is False
    assert "could not fetch" in capsys.readouterr().err


def _owned(*gids):
    """What a config file listing an entry asserts about it: these groups, on."""
    return deploy.Owned(frozenset(gids), True)


def test_plan_membership_add_update_remove():
    desired = {"a": _owned(1), "b": _owned(1, 2), "c": _owned(2)}
    current = {"b": _owned(1), "c": _owned(2), "d": _owned(1)}
    add, update, remove = deploy.plan_membership(desired, current)
    assert add == {"a": _owned(1)}          # only in desired
    assert update == {"b": _owned(1, 2)}    # in both, group set differs
    assert remove == ["d"]                  # only in current


def test_plan_membership_noop_when_identical():
    m = {"a": _owned(1), "b": _owned(0, 3)}
    assert deploy.plan_membership(m, dict(m)) == ({}, {}, [])


def test_plan_membership_remove_is_sorted():
    _, _, remove = deploy.plan_membership({}, {"c": _owned(1), "a": _owned(1),
                                          "b": _owned(1)})
    assert remove == ["a", "b", "c"]


def test_plan_membership_all_new():
    add, update, remove = deploy.plan_membership({"a": _owned(1)}, {})
    assert add == {"a": _owned(1)}
    assert update == {} and remove == []


def test_managed_entry_switched_off_by_hand_is_planned_for_re_enabling():
    # A config file listing an entry says it is on, so a managed row toggled off
    # in the admin UI is drift the reconcile has to correct. Nothing else would:
    # mirroring skips rows the reconciler owns, so the block would stay off
    # through every site.yml run and every rebuild.
    desired = deploy.assemble_desired([], [(2, [], ["bad.example"], [])])["deny_exact"]
    current = {"bad.example": deploy.Owned(frozenset({2}), False)}
    _, update, _ = deploy.plan_membership(desired, current)
    assert update == desired


def test_network_wide_entries_are_owned_by_the_default_group_and_enabled():
    # Allowlists name no group, so the files say default group and nothing else.
    # Saying it as membership is what puts them on the one reconcile path.
    assert deploy.network_wide(["a.example"]) == {"a.example": _owned(0)}


def test_network_wide_dedupes_what_remote_lists_repeat():
    # allow.list and a fetched allowlist can name the same domain; the desired
    # map has one row per entry, as Pi-hole does.
    assert deploy.network_wide(["a.example", "a.example"]) == {"a.example": _owned(0)}


def test_ftl_already_present_400_is_collision():
    body = {"error": {"key": "database_error",
                      "message": "The item is already present"}}
    assert deploy.is_collision(400, body)


def test_other_400_is_not_collision():
    assert not deploy.is_collision(400, {"error": {"message": "bad regex"}})


def test_success_is_not_collision():
    assert not deploy.is_collision(201, {})


def test_collision_text_body_tolerated():
    assert deploy.is_collision(409, "duplicate: item already present")
    assert not deploy.is_collision(500, "internal error")


def test_ftl_database_locked_is_transient():
    # Gravity swaps the database as it rebuilds. A write that lands mid-swap is
    # refused with this and succeeds moments later, so it is not the run's fault.
    body = {"error": {"key": "database_error",
                      "message": "Could not add to gravity database",
                      "hint": "database is locked"}}
    assert deploy.is_transient(400, body)


def test_ftl_readonly_database_is_transient():
    # The other half of the swap window: the new file is in place but still
    # read-only. Same cause, different SQLite wording.
    assert deploy.is_transient(400, {"error": {"hint": "attempt to write a "
                                               "readonly database"}})


def test_a_real_database_error_is_not_transient():
    # A bad regex answers the same way however long you wait, so retrying it
    # would turn a clear failure into a slow one.
    assert not deploy.is_transient(400, {"error": {"message": "bad regex"}})


def test_a_collision_is_not_transient():
    # Collisions have their own handling; retrying one would never clear.
    body = {"error": {"message": "The item is already present"}}
    assert not deploy.is_transient(400, body)
    assert deploy.is_collision(400, body)


def test_success_is_not_transient():
    assert not deploy.is_transient(201, {})


_LOCKED = (400, {"error": {"key": "database_error", "hint": "database is locked"}})


def test_a_transient_database_answer_is_retried_until_it_clears():
    answers = [_LOCKED, _LOCKED, (201, {})]
    slept = []
    call = lambda: answers.pop(0)  # noqa: E731
    assert deploy.retry_transient(call, sleep=slept.append) == (201, {})
    assert len(slept) == 2


def test_a_database_that_never_unlocks_gives_back_ftls_own_answer():
    # Bounded, so a genuinely stuck database stops the run instead of hanging
    # it — and stops it with the message FTL gave, not one this script invented.
    assert deploy.retry_transient(lambda: _LOCKED, sleep=lambda _: None) == _LOCKED


def test_a_locked_write_is_retried_by_the_call_that_makes_it(monkeypatch):
    # The predicate and the policy are both tested above, and neither of them is
    # the fix: api() routing through them is. Without this the wiring can be
    # dropped and the whole suite stays green.
    answers = [_LOCKED, _LOCKED, (201, {})]
    monkeypatch.setattr(deploy, "_request", lambda req: answers.pop(0))
    monkeypatch.setattr(deploy.time, "sleep", lambda _: None)

    assert deploy.api("POST", "/groups", body={}) == (201, {})
    assert answers == []


def test_a_dropped_connection_is_retried_until_it_reconnects():
    # FTL closes sockets while gravity restarts DNS -- same "try again" window
    # as a locked database, just signalled by an exception instead of a body.
    answers = [ConnectionResetError("reset"), (201, {})]

    def call():
        item = answers.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    slept = []
    assert deploy.retry_transient(call, sleep=slept.append) == (201, {})
    assert len(slept) == 1


def test_a_connection_that_never_recovers_raises():
    # A permanently dead API is a real fault; the run should stop loud on
    # FTL's own exception, not hang or silently report success.
    def call():
        raise deploy.urllib.error.URLError("connection refused")

    with pytest.raises(deploy.urllib.error.URLError):
        deploy.retry_transient(call, sleep=lambda _: None)


def test_a_timeout_is_not_retried():
    # A timeout means FTL is there but slow, not that its socket dropped.
    # Retrying it would turn one bounded 30s wait into several.
    slept = []

    def call():
        raise TimeoutError("timed out")

    with pytest.raises(TimeoutError):
        deploy.retry_transient(call, sleep=slept.append)
    assert slept == []


def test_a_urlerror_wrapping_a_timeout_is_not_retried():
    # urllib wraps a connect/send-phase timeout in URLError, not a bare
    # TimeoutError -- an OSError subtype that, without checking .reason,
    # falls into the generic dropped-connection branch and gets retried like
    # a socket reset instead of propagating as the slow-FTL signal it is.
    slept = []

    def call():
        raise deploy.urllib.error.URLError(TimeoutError("timed out"))

    with pytest.raises(deploy.urllib.error.URLError):
        deploy.retry_transient(call, sleep=slept.append)
    assert slept == []


def test_wiring_that_makes_the_call_picks_up_the_real_default_sleep(monkeypatch):
    # retry_transient's sleep default used to bind time.sleep at def time, so
    # patching deploy.time.sleep never reached it -- api() callers slept for
    # real on every retry. Locking in the fix: a monkeypatched module sleep is
    # what api() actually uses when no sleep is passed explicitly.
    answers = [_LOCKED, (201, {})]
    monkeypatch.setattr(deploy, "_request", lambda req: answers.pop(0))
    slept = []
    monkeypatch.setattr(deploy.time, "sleep", slept.append)

    assert deploy.api("POST", "/groups", body={}) == (201, {})
    assert slept == [deploy._DB_RETRY_WAITS[0]]


def test_a_dropped_connection_is_not_retried_when_the_caller_opts_out():
    slept = []

    def call():
        raise ConnectionResetError("reset")

    with pytest.raises(ConnectionResetError):
        deploy.retry_transient(call, sleep=slept.append, retry_dropped=False)
    assert slept == []


def test_gravity_trigger_fails_hard_on_a_dropped_connection(monkeypatch):
    # Re-triggering gravity while an earlier, "failed" call actually started
    # it would overlap two rebuilds against the same database swap. A dropped
    # connection here should stop the run, not retry blind.
    monkeypatch.setattr(deploy, "changed", {**deploy.changed, "adlists": True})

    def fake_api(method, path, sid=None, body=None, retry_dropped=True):
        raise ConnectionResetError("reset")

    monkeypatch.setattr(deploy, "api", fake_api)

    with pytest.raises(SystemExit):
        deploy.apply_changes(None)


def test_gravity_trigger_reports_a_timeout_as_a_timeout_not_a_dropped_connection(
        monkeypatch, capsys):
    monkeypatch.setattr(deploy, "changed", {**deploy.changed, "adlists": True})

    def fake_api(method, path, sid=None, body=None, retry_dropped=True):
        raise TimeoutError("timed out")

    monkeypatch.setattr(deploy, "api", fake_api)

    with pytest.raises(SystemExit):
        deploy.apply_changes(None)
    err = capsys.readouterr().err
    assert "timed out" in err.lower()
    assert "dropped" not in err.lower()


def test_gravity_retry_dropped_false_is_wired_into_the_action_call(monkeypatch):
    seen = {}

    def fake_api(method, path, sid=None, body=None, retry_dropped=True):
        seen["retry_dropped"] = retry_dropped
        return 200, {}

    monkeypatch.setattr(deploy, "changed", {**deploy.changed, "adlists": True})
    monkeypatch.setattr(deploy, "api", fake_api)

    deploy.apply_changes(None)

    assert seen["retry_dropped"] is False


def test_a_missing_config_root_is_not_an_empty_one(tmp_path):
    # Pointing PIHOLE_DIR at a path that is not there deleted every managed
    # entry and reported success, because absent read as empty everywhere.
    assert deploy.config_root_missing(str(tmp_path / "nope"))
    assert not deploy.config_root_missing(str(tmp_path))


def test_a_config_file_that_is_not_there_is_named_not_assumed_empty(tmp_path):
    # A file renamed away, half a checkout, a bad deploy: the entries it would
    # have listed are unknown, not deleted.
    (tmp_path / "adlists.txt").write_text("https://a.example/l.txt\n",
                                          encoding="utf-8")
    assert deploy.missing_inputs(str(tmp_path)) == ["allow.list",
                                                    "allowlist-urls.txt"]


def test_a_complete_config_root_is_missing_nothing(tmp_path):
    for name in ("adlists.txt", "allow.list", "allowlist-urls.txt"):
        (tmp_path / name).write_text("", encoding="utf-8")
    assert deploy.missing_inputs(str(tmp_path)) == []


def test_an_absent_groups_tree_is_not_an_empty_one(tmp_path):
    # groups/ is a second config root the top-level guard never looks at, and
    # every group, deny list and client is sourced from nowhere else.
    assert deploy.groups_root_missing(str(tmp_path))
    (tmp_path / "groups").mkdir()
    assert not deploy.groups_root_missing(str(tmp_path))


def _stub_api(monkeypatch, get_responses):
    """Replace deploy.api with a fake FTL that answers GET from get_responses
    and records every call, so a test can assert what main() tried to do."""
    calls = []

    def stub(method, path, sid=None, body=None):
        calls.append((method, path, body))
        return 200, get_responses.get(path, {}) if method == "GET" else {}

    monkeypatch.setattr(deploy, "api", stub)
    return calls


def test_an_absent_groups_tree_deletes_no_group_deny_entry_or_client(
        tmp_path, monkeypatch):
    # groups/ never existed here -- a half checkout, the wrong PIHOLE_DIR, a
    # role that has not run yet. Every managed group, deny entry and client is
    # sourced only from inside groups/, so none of it is known to be gone.
    for name in ("adlists.txt", "allow.list", "allowlist-urls.txt"):
        (tmp_path / name).write_text("", encoding="utf-8")
    monkeypatch.setattr(deploy, "DIR", str(tmp_path))
    monkeypatch.setattr(deploy, "GROUPS_DIR", str(tmp_path / "groups"))
    monkeypatch.setattr(deploy, "MANIFEST", str(tmp_path / ".manifest.json"))
    monkeypatch.setattr(deploy, "PW", "")
    monkeypatch.setattr(deploy, "changed", dict.fromkeys(deploy.changed, False))
    monkeypatch.setattr(deploy, "collisions", [])

    calls = _stub_api(monkeypatch, {
        "/groups": {"groups": [
            {"id": 0, "name": "Default", "comment": None},
            {"id": 5, "name": "kids", "comment": deploy.MANAGED},
        ]},
        "/domains/allow/exact": {"domains": []},
        "/domains/allow/regex": {"domains": []},
        "/domains/deny/exact": {"domains": [
            {"domain": "blocked.example", "type": "deny", "kind": "exact",
             "comment": deploy.MANAGED, "groups": [5], "enabled": True}]},
        "/domains/deny/regex": {"domains": []},
        "/clients": {"clients": [
            {"client": "192.168.1.50", "comment": deploy.MANAGED,
             "groups": [5]}]},
        "/lists?type=block": {"lists": []},
    })

    deploy.main()

    destructive = [(m, p) for m, p, _ in calls
                   if (m == "POST" and p.endswith(":batchDelete"))
                   or (m == "DELETE" and p.startswith("/groups/"))]
    assert destructive == []


def _base_state(monkeypatch, tmp_path, allow_list="", allowlist_urls=""):
    """Wire deploy at tmp_path with empty top-level files and an empty (but
    present) groups/, then return the config root for the caller to add to."""
    (tmp_path / "adlists.txt").write_text("", encoding="utf-8")
    (tmp_path / "allow.list").write_text(allow_list, encoding="utf-8")
    (tmp_path / "allowlist-urls.txt").write_text(allowlist_urls, encoding="utf-8")
    (tmp_path / "groups").mkdir()
    monkeypatch.setattr(deploy, "DIR", str(tmp_path))
    monkeypatch.setattr(deploy, "GROUPS_DIR", str(tmp_path / "groups"))
    monkeypatch.setattr(deploy, "MANIFEST", str(tmp_path / ".manifest.json"))
    monkeypatch.setattr(deploy, "PW", "")
    monkeypatch.setattr(deploy, "changed", dict.fromkeys(deploy.changed, False))
    monkeypatch.setattr(deploy, "collisions", [])
    return tmp_path


_EMPTY_COLLECTIONS = {
    "/domains/allow/regex": {"domains": []},
    "/domains/deny/exact": {"domains": []},
    "/domains/deny/regex": {"domains": []},
    "/clients": {"clients": []},
    "/lists?type=block": {"lists": []},
}


def test_first_run_ever_trusts_the_managed_comment_alone(tmp_path, monkeypatch):
    # No manifest yet -- the very first run under this code, or a config root
    # that just moved. Trust the comment alone, same as every run before the
    # manifest existed, rather than silently keeping every row forever.
    _base_state(monkeypatch, tmp_path)

    calls = _stub_api(monkeypatch, {
        "/groups": {"groups": [{"id": 0, "name": "Default", "comment": None}]},
        "/domains/allow/exact": {"domains": [
            {"domain": "stale.example", "type": "allow", "kind": "exact",
             "comment": deploy.MANAGED, "groups": [0], "enabled": True}]},
        **_EMPTY_COLLECTIONS,
    })

    deploy.main()

    removed = [item["item"] for m, p, b in calls
              if m == "POST" and p == "/domains:batchDelete"
              for item in b]
    assert "stale.example" in removed


def test_a_hand_typed_managed_comment_survives_when_the_manifest_disagrees(
        tmp_path, monkeypatch):
    # The admin UI lets an operator type "managed by ansible" into any
    # comment box. The comment alone used to be enough to delete a row on
    # that word; now the last run's own manifest has to agree it created it.
    _base_state(monkeypatch, tmp_path)
    deploy.write_manifest(str(tmp_path / ".manifest.json"),
                          {"allow/exact [managed by ansible]": []})

    calls = _stub_api(monkeypatch, {
        "/groups": {"groups": [{"id": 0, "name": "Default", "comment": None}]},
        "/domains/allow/exact": {"domains": [
            {"domain": "forged.example", "type": "allow", "kind": "exact",
             "comment": deploy.MANAGED, "groups": [0], "enabled": True}]},
        **_EMPTY_COLLECTIONS,
    })

    deploy.main()

    removed = [item["item"] for m, p, b in calls
              if m == "POST" and p == "/domains:batchDelete"
              for item in b]
    assert "forged.example" not in removed


def test_a_hand_added_group_is_not_silently_taken_over(tmp_path, monkeypatch, capsys):
    # "teens" was created through the admin UI, not by this role. Writing
    # managed rows into it, and reporting a clean run, would mean the repo no
    # longer describes the box it just reconciled.
    cfg = _base_state(monkeypatch, tmp_path)
    teens = cfg / "groups" / "teens"
    teens.mkdir(parents=True)
    (teens / "block.list").write_text("teenblock.example\n", encoding="utf-8")
    (teens / "adlists.txt").write_text("", encoding="utf-8")
    (teens / "clients.txt").write_text("", encoding="utf-8")

    calls = _stub_api(monkeypatch, {
        "/groups": {"groups": [
            {"id": 0, "name": "Default", "comment": None},
            {"id": 7, "name": "teens", "comment": "made in the admin UI"}]},
        "/domains/allow/exact": {"domains": []},
        **_EMPTY_COLLECTIONS,
    })

    with pytest.raises(SystemExit):
        deploy.main()

    touched_group_7 = [b for m, p, b in calls
                       if isinstance(b, dict) and 7 in b.get("groups", [])]
    assert touched_group_7 == []
    assert "teens" in capsys.readouterr().err


def test_a_collided_group_is_not_recorded_as_the_managed_identity(monkeypatch):
    # "teens" already exists as a hand-added group; reconcile_groups skips it
    # (a collision). The manifest must not remember it as ours either, for
    # the same reason a collided domain must not be.
    def stub(method, path, sid=None, body=None):
        if method == "GET":
            return 200, {"groups": [
                {"id": 0, "name": "Default", "comment": None},
                {"id": 7, "name": "teens", "comment": "made in the admin UI"}]}
        return 200, {}
    monkeypatch.setattr(deploy, "api", stub)
    monkeypatch.setattr(deploy, "collisions", [])
    record = {}

    deploy.reconcile_groups("sid", ["teens"], record=record)

    assert record["groups"] == []


def test_a_source_that_could_not_be_read_does_not_shrink_the_manifest(
        tmp_path, monkeypatch):
    # allow.list goes missing for one run -- the documented, "recoverable"
    # scenario. The box is correctly left alone (allow_remove=False), but a
    # prior, valid manifest entry for allow/exact must survive this run
    # untouched, or the next ordinary run misreads the still-managed row as
    # a hand-added collision.
    cfg = _base_state(monkeypatch, tmp_path)
    (cfg / "allow.list").unlink()
    deploy.write_manifest(str(cfg / ".manifest.json"),
                          {"allow/exact [managed by ansible]": ["kept.example"]})

    _stub_api(monkeypatch, {
        "/groups": {"groups": [{"id": 0, "name": "Default", "comment": None}]},
        "/domains/allow/exact": {"domains": [
            {"domain": "kept.example", "type": "allow", "kind": "exact",
             "comment": deploy.MANAGED, "groups": [0], "enabled": True}]},
        **_EMPTY_COLLECTIONS,
    })

    deploy.main()

    manifest = deploy.read_manifest(str(cfg / ".manifest.json"))
    assert manifest["allow/exact [managed by ansible]"] == ["kept.example"]


def test_an_unrelated_failure_does_not_truncate_prior_manifest_entries(
        tmp_path, monkeypatch):
    # A prior, fully valid manifest already covers "groups" and "allow/exact".
    # This run dies on an unrelated later kind (clients). Every kind already
    # reconciled by a real prior run, and not touched this run, must keep its
    # last-known-good identities -- an interruption may lose progress, but it
    # must never erase confirmed history.
    cfg = _base_state(monkeypatch, tmp_path, allow_list="kept.example\n")
    deploy.write_manifest(str(cfg / ".manifest.json"), {
        "groups": [],
        "allow/exact [managed by ansible]": ["kept.example"],
    })

    def stub(method, path, sid=None, body=None):
        if method == "GET":
            if path == "/clients":
                return 500, {"error": "boom"}
            return 200, {
                "/groups": {"groups": [
                    {"id": 0, "name": "Default", "comment": None}]},
                "/domains/allow/exact": {"domains": [
                    {"domain": "kept.example", "type": "allow", "kind": "exact",
                     "comment": deploy.MANAGED, "groups": [0], "enabled": True}]},
            }.get(path, {})
        return 200, {}
    monkeypatch.setattr(deploy, "api", stub)

    with pytest.raises(SystemExit):
        deploy.main()

    manifest = deploy.read_manifest(str(cfg / ".manifest.json"))
    assert manifest["allow/exact [managed by ansible]"] == ["kept.example"]


def test_the_manifest_records_this_runs_own_desired_identities(tmp_path, monkeypatch):
    _base_state(monkeypatch, tmp_path, allow_list="kept.example\n")
    _stub_api(monkeypatch, {
        "/groups": {"groups": [{"id": 0, "name": "Default", "comment": None}]},
        "/domains/allow/exact": {"domains": []},
        **_EMPTY_COLLECTIONS,
    })

    deploy.main()

    manifest = deploy.read_manifest(str(tmp_path / ".manifest.json"))
    assert manifest["allow/exact [managed by ansible]"] == ["kept.example"]


def test_an_interrupted_run_keeps_the_manifest_entries_it_already_confirmed(
        tmp_path, monkeypatch):
    # main() dies partway through -- a later GET fails for reasons unrelated
    # to anything reconciled so far. Everything already reconciled must
    # already be durable, or the next run would misread its own, real,
    # just-created row as a hand-added collision.
    _base_state(monkeypatch, tmp_path, allow_list="kept.example\n")

    def stub(method, path, sid=None, body=None):
        if method == "GET":
            if path == "/clients":
                return 500, {"error": "boom"}
            return 200, {
                "/groups": {"groups": [
                    {"id": 0, "name": "Default", "comment": None}]},
            }.get(path, {})
        return 200, {}
    monkeypatch.setattr(deploy, "api", stub)

    with pytest.raises(SystemExit):
        deploy.main()

    manifest = deploy.read_manifest(str(tmp_path / ".manifest.json"))
    assert manifest["allow/exact [managed by ansible]"] == ["kept.example"]
    assert "client [managed by ansible]" not in manifest


def test_an_add_survives_a_later_update_dying_in_the_same_call(tmp_path, monkeypatch):
    # "new.example" (needs adding) and "existing.example" (needs updating,
    # its enabled bit is stale) are both in the SAME reconcile_membership
    # call. The add succeeds and is live on Pi-hole; the update for the
    # unrelated existing.example then dies on a genuine server error. The
    # manifest must still remember new.example as ours -- it really is,
    # right now, on the box -- not just the entries confirmed by calls
    # before this one, the way test_an_interrupted_run_keeps_the_manifest_
    # entries_it_already_confirmed already pins across calls.
    _base_state(monkeypatch, tmp_path,
                allow_list="new.example\nexisting.example\n")

    def stub(method, path, sid=None, body=None):
        if method == "GET":
            return 200, {
                "/groups": {"groups": [
                    {"id": 0, "name": "Default", "comment": None}]},
                "/domains/allow/exact": {"domains": [
                    {"domain": "existing.example", "type": "allow",
                     "kind": "exact", "comment": deploy.MANAGED,
                     "groups": [0], "enabled": False}]},
            }.get(path, {})
        if method == "PUT" and path == "/domains/allow/exact/existing.example":
            return 500, {"error": "boom"}
        return 200, {}
    monkeypatch.setattr(deploy, "api", stub)

    with pytest.raises(SystemExit):
        deploy.main()

    manifest = deploy.read_manifest(str(tmp_path / ".manifest.json"))
    assert "new.example" in manifest["allow/exact [managed by ansible]"]


def test_a_group_add_survives_a_later_group_add_dying_in_the_same_call(monkeypatch):
    # "kids" is created first and lands live on Pi-hole; "teens" then dies on
    # a genuine server error in the same reconcile_groups call. "kids" must
    # still be recorded as ours, the same intra-call guarantee
    # test_an_add_survives_a_later_update_dying_in_the_same_call pins for
    # reconcile_membership.
    def stub(method, path, sid=None, body=None):
        if method == "GET":
            return 200, {"groups": [
                {"id": 0, "name": "Default", "comment": None}]}
        if method == "POST" and path == "/groups":
            if body["name"] == "teens":
                return 500, {"error": "boom"}
            return 200, {}
        return 200, {}
    monkeypatch.setattr(deploy, "api", stub)
    monkeypatch.setattr(deploy, "collisions", [])
    monkeypatch.setattr(deploy, "changed", dict.fromkeys(deploy.changed, False))
    record = {}

    with pytest.raises(SystemExit):
        deploy.reconcile_groups("sid", ["kids", "teens"], record=record)

    assert "kids" in record["groups"]


def test_a_local_deletion_reaches_the_box_even_when_a_remote_list_is_down(
        tmp_path, monkeypatch):
    # allow.list dropped a domain the box still holds; allowlist-urls.txt names
    # a URL that is down. The two are unrelated: an unreachable remote list
    # must not block a deletion that came from the local file.
    _base_state(monkeypatch, tmp_path, allow_list="kept.example\n",
                allowlist_urls="http://dead.example/list.txt\n")
    monkeypatch.setattr(deploy.urllib.request, "urlopen",
                        lambda url, timeout=30: (_ for _ in ()).throw(
                            deploy.urllib.error.URLError("refused")))

    calls = _stub_api(monkeypatch, {
        "/groups": {"groups": [{"id": 0, "name": "Default", "comment": None}]},
        "/domains/allow/exact": {"domains": [
            {"domain": "kept.example", "type": "allow", "kind": "exact",
             "comment": deploy.MANAGED, "groups": [0], "enabled": True},
            {"domain": "gone.example", "type": "allow", "kind": "exact",
             "comment": deploy.MANAGED, "groups": [0], "enabled": True}]},
        **_EMPTY_COLLECTIONS,
    })

    deploy.main()

    removed = [item["item"] for m, p, b in calls
              if m == "POST" and p == "/domains:batchDelete"
              for item in b]
    assert "gone.example" in removed


def test_fetched_allow_entries_are_tagged_distinctly_from_local_ones(
        tmp_path, monkeypatch):
    # Fetched and local entries share a collection on the wire; only the
    # comment tells the mirror (and a human) which file a row came from.
    _base_state(monkeypatch, tmp_path,
                allowlist_urls="http://list.example/a.txt\n")
    monkeypatch.setattr(deploy.urllib.request, "urlopen",
                        lambda url, timeout=30: _FakeResponse("fetched.example\n"))

    calls = _stub_api(monkeypatch, {
        "/groups": {"groups": [{"id": 0, "name": "Default", "comment": None}]},
        "/domains/allow/exact": {"domains": []},
        **_EMPTY_COLLECTIONS,
    })

    deploy.main()

    adds = [b for m, p, b in calls if m == "POST" and p == "/domains/allow/exact"]
    assert any("fetched.example" in b.get("domain", [])
              and b.get("comment") == deploy.MANAGED_FETCHED
              for b in adds)


def test_a_settled_answer_is_not_retried_at_all():
    calls = []

    def call():
        calls.append(1)
        return 201, {}

    assert deploy.retry_transient(call, sleep=lambda _: None) == (201, {})
    assert len(calls) == 1


def test_assemble_desired_scopes_and_unions():
    d = deploy.assemble_desired(
        ["global-ad.txt"],
        [(1, ["kids-ad.txt"], ["bad.com", r"(\.|^)x\.com$"], ["10.0.0.5"])],
    )
    assert d["adlists"] == {"global-ad.txt": _owned(0), "kids-ad.txt": _owned(1)}
    assert d["deny_exact"] == {"bad.com": _owned(1)}
    assert d["deny_regex"] == {r"(\.|^)x\.com$": _owned(1)}
    assert d["clients"] == {"10.0.0.5": _owned(0, 1)}  # joins group AND default


def test_assemble_desired_same_adlist_in_default_and_group_unions():
    d = deploy.assemble_desired(["shared.txt"], [(1, ["shared.txt"], [], [])])
    assert d["adlists"] == {"shared.txt": _owned(0, 1)}


def test_assemble_desired_two_groups_accumulate_not_overwrite():
    # Guards against `+=` -> `=` in the loop: a shared adlist/client across
    # two groups must union all groups, not just the last one'deploy.
    d = deploy.assemble_desired(
        [],
        [(1, ["shared.txt"], [], ["10.0.0.5"]),
         (2, ["shared.txt"], [], ["10.0.0.5"])],
    )
    assert d["adlists"] == {"shared.txt": _owned(1, 2)}
    assert d["clients"] == {"10.0.0.5": _owned(0, 1, 2)}  # both groups + default


def test_assemble_desired_empty():
    assert deploy.assemble_desired([], []) == {
        "adlists": {}, "deny_exact": {}, "deny_regex": {}, "clients": {}}


def test_bucket_by_groups_groups_shared_group_set_into_one_batch():
    # Items inserted out of order so the assertion can only pass if the
    # batch actually sorts them (guards the `sorted(items)`).
    add = {"b": _owned(1), "a": _owned(1), "c": _owned(0, 1)}
    got = deploy._bucket_by_groups(add)
    # sorted by group-set key, items sorted within each batch
    assert got == [(_owned(0, 1), ["c"]), (_owned(1), ["a", "b"])]


def test_bucket_by_groups_empty():
    assert deploy._bucket_by_groups({}) == []


def test_reconcile_membership_rejects_kind_without_item_path():
    # Membership reconcile PUTs through item_path, so a kind that lacks one must
    # fail fast (before any API call) rather than NoneType-crash mid-run.
    pathless = deploy.Kind("pathless", "/nowhere", "/nowhere:batchDelete", "nowhere",
                      "item", {}, "domains")
    assert pathless.item_path is None
    with pytest.raises(AssertionError):
        deploy.reconcile_membership(None, pathless, {})


def test_a_collided_add_is_not_recorded_as_the_managed_identity(monkeypatch):
    # A hand-added row and a config-file entry share a name; the add collides
    # and is skipped. The manifest must not remember it as ours anyway -- a
    # later comment edit to exactly MANAGED would otherwise silently absorb
    # it, and a run after that could delete a row this reconciler never
    # created.
    monkeypatch.setattr(deploy, "collisions", [])

    def stub(method, path, sid=None, body=None):
        if method == "GET":
            return 200, {"domains": []}
        if method == "POST":
            return 400, {"error": {"message": "already present"}}
        return 200, {}
    monkeypatch.setattr(deploy, "api", stub)
    record = {}

    deploy.reconcile_membership(
        "sid", deploy.allow_kind("exact"),
        deploy.network_wide(["shared.example"]), record=record)

    assert deploy.collisions == [("allow/exact", "shared.example")]
    assert record["allow/exact [managed by ansible]"] == []


def test_normalize_groups_empty_means_default_group():
    # FTL may report a default-only entry as [] or [0]; both mean group 0.
    assert deploy.normalize_groups([]) == {0}


def test_normalize_groups_explicit_zero_unchanged():
    assert deploy.normalize_groups([0]) == {0}


def test_normalize_groups_non_default_groups_preserved():
    assert deploy.normalize_groups([0, 2]) == {0, 2}
    assert deploy.normalize_groups([3]) == {3}


def test_build_membership_unions_group_ids_per_entry():
    got = deploy.build_membership([(1, ["a", "b"]), (2, ["b", "c"])])
    assert got == {"a": _owned(1), "b": _owned(1, 2), "c": _owned(2)}


def test_build_membership_empty():
    assert deploy.build_membership([]) == {}


def test_discover_groups_missing_dir_is_empty(tmp_path):
    assert deploy.discover_groups(str(tmp_path / "nope")) == []


def test_discover_groups_lists_subdirs_sorted_by_name(tmp_path):
    (tmp_path / "teens").mkdir()
    (tmp_path / "kids").mkdir()
    got = deploy.discover_groups(str(tmp_path))
    assert [name for name, _ in got] == ["kids", "teens"]
    assert got[0] == ("kids", str(tmp_path / "kids"))


def test_discover_groups_ignores_non_directories(tmp_path):
    (tmp_path / "kids").mkdir()
    _write(tmp_path / "README.txt", "not a group\n")
    assert [name for name, _ in deploy.discover_groups(str(tmp_path))] == ["kids"]


def test_group_paths_to_prune_keeps_paths_still_in_source():
    got = deploy.group_paths_to_prune(
        ["/repo/groups/kids/block.list"],
        ["/box/groups/kids/block.list"],
        "/repo/groups", "/box/groups")
    assert got == []


def test_group_paths_to_prune_removes_a_deleted_group():
    # `find` (file_type: any) lists a group's directory entry alongside its
    # files on both sides, so a kept group's directory must be in
    # source_paths too, not just the files inside it.
    got = deploy.group_paths_to_prune(
        ["/repo/groups/kids", "/repo/groups/kids/block.list"],
        ["/box/groups/kids/block.list", "/box/groups/kids",
         "/box/groups/teens/block.list", "/box/groups/teens"],
        "/repo/groups", "/box/groups")
    assert got == ["/box/groups/teens/block.list", "/box/groups/teens"]


def test_group_paths_to_prune_orders_files_before_their_directory():
    # A plain reverse string sort must never hand back a directory before
    # a path it is a prefix of -- `file: state=absent` fails on a
    # non-empty directory if the order is wrong.
    got = deploy.group_paths_to_prune(
        [], ["/box/groups/kids", "/box/groups/kids/block.list",
             "/box/groups/kids/clients.txt"],
        "/repo/groups", "/box/groups")
    assert got == ["/box/groups/kids/clients.txt",
                    "/box/groups/kids/block.list", "/box/groups/kids"]


def test_group_paths_to_prune_everything_deployed_when_source_is_empty():
    got = deploy.group_paths_to_prune(
        [], ["/box/groups/kids/block.list"], "/repo/groups", "/box/groups")
    assert got == ["/box/groups/kids/block.list"]


def test_group_paths_to_prune_nothing_deployed_is_a_no_op():
    assert deploy.group_paths_to_prune(
        ["/repo/groups/kids/block.list"], [], "/repo/groups", "/box/groups"
    ) == []


def test_resolve_password_reads_from_file(tmp_path):
    f = tmp_path / "pw"
    _write(f, "s3cret\n")  # trailing newline as Ansible writes it
    assert deploy.resolve_password({"PIHOLE_PASSWORD_FILE": str(f)}) == "s3cret"


def test_resolve_password_file_wins_over_inline(tmp_path):
    f = tmp_path / "pw"
    _write(f, "from-file")
    env = {"PIHOLE_PASSWORD_FILE": str(f), "PIHOLE_PASSWORD": "from-env"}
    assert deploy.resolve_password(env) == "from-file"


def test_resolve_password_falls_back_to_inline_env():
    assert deploy.resolve_password({"PIHOLE_PASSWORD": "plain"}) == "plain"


def test_resolve_password_empty_when_unset():
    assert deploy.resolve_password({}) == ""


def test_resolve_password_empty_file_path_is_ignored(tmp_path):
    # An unset Ansible var renders PIHOLE_PASSWORD_FILE="" — treat as absent.
    env = {"PIHOLE_PASSWORD_FILE": "", "PIHOLE_PASSWORD": "plain"}
    assert deploy.resolve_password(env) == "plain"


def test_resolve_password_preserves_inner_whitespace(tmp_path):
    f = tmp_path / "pw"
    _write(f, "a b\tc\n")  # only the trailing newline is stripped
    assert deploy.resolve_password({"PIHOLE_PASSWORD_FILE": str(f)}) == "a b\tc"
