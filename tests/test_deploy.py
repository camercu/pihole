"""Unit tests for the pure decision logic in pihole_deploy.py."""
import pihole_deploy as deploy
import pytest


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


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
