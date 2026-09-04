"""Unit tests for the pure decision logic in pihole_sync_lists.py."""
import pihole_sync_lists as s
import pytest


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_clean_lines_strips_comments_blanks_and_whitespace():
    text = "a.com\n  b.com  \n# comment\n\nc.com # trailing\n"
    assert s.clean_lines(text) == ["a.com", "b.com", "c.com"]


def test_clean_lines_empty_input():
    assert s.clean_lines("") == []


def test_clean_lines_only_comments():
    assert s.clean_lines("# one\n   # two\n") == []


def test_plain_domains_are_not_regex():
    for d in ["www.facebook.com", "example.co.uk", "a-b.example.com"]:
        assert not s.is_regex(d)


def test_real_regex_pattern_detected():
    # from the actual allow.list
    assert s.is_regex(r"(\.|^)twimg\.com$")


def test_regex_metacharacters_detected():
    for pat in ["a|b", "x*", "^host", "end$", "grp(x)", "[abc]"]:
        assert s.is_regex(pat)


def test_split_allow_partitions_exact_and_regex():
    exact, regex = s.split_allow(["a.com", r"(\.|^)twimg\.com$", "b.com"])
    assert exact == ["a.com", "b.com"]
    assert regex == [r"(\.|^)twimg\.com$"]


def test_split_allow_empty():
    assert s.split_allow([]) == ([], [])


def test_host_domain_plain_domain():
    assert s.host_domain("example.com") == "example.com"


def test_host_domain_hosts_format_prefix_stripped():
    assert s.host_domain("0.0.0.0 example.com") == "example.com"
    assert s.host_domain("127.0.0.1\texample.com") == "example.com"


def _owned(*gids):
    """What a config file listing an entry asserts about it: these groups, on."""
    return s.Owned(frozenset(gids), True)


def test_plan_membership_add_update_remove():
    desired = {"a": _owned(1), "b": _owned(1, 2), "c": _owned(2)}
    current = {"b": _owned(1), "c": _owned(2), "d": _owned(1)}
    add, update, remove = s.plan_membership(desired, current)
    assert add == {"a": _owned(1)}          # only in desired
    assert update == {"b": _owned(1, 2)}    # in both, group set differs
    assert remove == ["d"]                  # only in current


def test_plan_membership_noop_when_identical():
    m = {"a": _owned(1), "b": _owned(0, 3)}
    assert s.plan_membership(m, dict(m)) == ({}, {}, [])


def test_plan_membership_remove_is_sorted():
    _, _, remove = s.plan_membership({}, {"c": _owned(1), "a": _owned(1),
                                          "b": _owned(1)})
    assert remove == ["a", "b", "c"]


def test_plan_membership_all_new():
    add, update, remove = s.plan_membership({"a": _owned(1)}, {})
    assert add == {"a": _owned(1)}
    assert update == {} and remove == []


def test_managed_entry_switched_off_by_hand_is_planned_for_re_enabling():
    # A config file listing an entry says it is on, so a managed row toggled off
    # in the admin UI is drift the reconcile has to correct. Nothing else would:
    # mirroring skips rows the reconciler owns, so the block would stay off
    # through every site.yml run and every rebuild.
    desired = s.assemble_desired([], [(2, [], ["bad.example"], [])])["deny_exact"]
    current = {"bad.example": s.Owned(frozenset({2}), False)}
    _, update, _ = s.plan_membership(desired, current)
    assert update == desired


def test_network_wide_entries_are_owned_by_the_default_group_and_enabled():
    # Allowlists name no group, so the files say default group and nothing else.
    # Saying it as membership is what puts them on the one reconcile path.
    assert s.network_wide(["a.example"]) == {"a.example": _owned(0)}


def test_network_wide_dedupes_what_remote_lists_repeat():
    # allow.list and a fetched allowlist can name the same domain; the desired
    # map has one row per entry, as Pi-hole does.
    assert s.network_wide(["a.example", "a.example"]) == {"a.example": _owned(0)}


def test_ftl_already_present_400_is_collision():
    body = {"error": {"key": "database_error",
                      "message": "The item is already present"}}
    assert s.is_collision(400, body)


def test_other_400_is_not_collision():
    assert not s.is_collision(400, {"error": {"message": "bad regex"}})


def test_success_is_not_collision():
    assert not s.is_collision(201, {})


def test_collision_text_body_tolerated():
    assert s.is_collision(409, "duplicate: item already present")
    assert not s.is_collision(500, "internal error")


def test_assemble_desired_scopes_and_unions():
    d = s.assemble_desired(
        ["global-ad.txt"],
        [(1, ["kids-ad.txt"], ["bad.com", r"(\.|^)x\.com$"], ["10.0.0.5"])],
    )
    assert d["adlists"] == {"global-ad.txt": _owned(0), "kids-ad.txt": _owned(1)}
    assert d["deny_exact"] == {"bad.com": _owned(1)}
    assert d["deny_regex"] == {r"(\.|^)x\.com$": _owned(1)}
    assert d["clients"] == {"10.0.0.5": _owned(0, 1)}  # joins group AND default


def test_assemble_desired_same_adlist_in_default_and_group_unions():
    d = s.assemble_desired(["shared.txt"], [(1, ["shared.txt"], [], [])])
    assert d["adlists"] == {"shared.txt": _owned(0, 1)}


def test_assemble_desired_two_groups_accumulate_not_overwrite():
    # Guards against `+=` -> `=` in the loop: a shared adlist/client across
    # two groups must union all groups, not just the last one's.
    d = s.assemble_desired(
        [],
        [(1, ["shared.txt"], [], ["10.0.0.5"]),
         (2, ["shared.txt"], [], ["10.0.0.5"])],
    )
    assert d["adlists"] == {"shared.txt": _owned(1, 2)}
    assert d["clients"] == {"10.0.0.5": _owned(0, 1, 2)}  # both groups + default


def test_assemble_desired_empty():
    assert s.assemble_desired([], []) == {
        "adlists": {}, "deny_exact": {}, "deny_regex": {}, "clients": {}}


def test_bucket_by_groups_groups_shared_group_set_into_one_batch():
    # Items inserted out of order so the assertion can only pass if the
    # batch actually sorts them (guards the `sorted(items)`).
    add = {"b": _owned(1), "a": _owned(1), "c": _owned(0, 1)}
    got = s._bucket_by_groups(add)
    # sorted by group-set key, items sorted within each batch
    assert got == [(_owned(0, 1), ["c"]), (_owned(1), ["a", "b"])]


def test_bucket_by_groups_empty():
    assert s._bucket_by_groups({}) == []


def test_reconcile_membership_rejects_kind_without_item_path():
    # Membership reconcile PUTs through item_path, so a kind that lacks one must
    # fail fast (before any API call) rather than NoneType-crash mid-run.
    pathless = s.Kind("pathless", "/nowhere", "/nowhere:batchDelete", "nowhere",
                      "item", {}, "domains")
    assert pathless.item_path is None
    with pytest.raises(AssertionError):
        s.reconcile_membership(None, pathless, {})


def test_normalize_groups_empty_means_default_group():
    # FTL may report a default-only entry as [] or [0]; both mean group 0.
    assert s.normalize_groups([]) == {0}


def test_normalize_groups_explicit_zero_unchanged():
    assert s.normalize_groups([0]) == {0}


def test_normalize_groups_non_default_groups_preserved():
    assert s.normalize_groups([0, 2]) == {0, 2}
    assert s.normalize_groups([3]) == {3}


def test_build_membership_unions_group_ids_per_entry():
    got = s.build_membership([(1, ["a", "b"]), (2, ["b", "c"])])
    assert got == {"a": _owned(1), "b": _owned(1, 2), "c": _owned(2)}


def test_build_membership_empty():
    assert s.build_membership([]) == {}


def test_discover_groups_missing_dir_is_empty(tmp_path):
    assert s.discover_groups(str(tmp_path / "nope")) == []


def test_discover_groups_lists_subdirs_sorted_by_name(tmp_path):
    (tmp_path / "teens").mkdir()
    (tmp_path / "kids").mkdir()
    got = s.discover_groups(str(tmp_path))
    assert [name for name, _ in got] == ["kids", "teens"]
    assert got[0] == ("kids", str(tmp_path / "kids"))


def test_discover_groups_ignores_non_directories(tmp_path):
    (tmp_path / "kids").mkdir()
    _write(tmp_path / "README.txt", "not a group\n")
    assert [name for name, _ in s.discover_groups(str(tmp_path))] == ["kids"]


def test_resolve_password_reads_from_file(tmp_path):
    f = tmp_path / "pw"
    _write(f, "s3cret\n")  # trailing newline as Ansible writes it
    assert s.resolve_password({"PIHOLE_PASSWORD_FILE": str(f)}) == "s3cret"


def test_resolve_password_file_wins_over_inline(tmp_path):
    f = tmp_path / "pw"
    _write(f, "from-file")
    env = {"PIHOLE_PASSWORD_FILE": str(f), "PIHOLE_PASSWORD": "from-env"}
    assert s.resolve_password(env) == "from-file"


def test_resolve_password_falls_back_to_inline_env():
    assert s.resolve_password({"PIHOLE_PASSWORD": "plain"}) == "plain"


def test_resolve_password_empty_when_unset():
    assert s.resolve_password({}) == ""


def test_resolve_password_empty_file_path_is_ignored(tmp_path):
    # An unset Ansible var renders PIHOLE_PASSWORD_FILE="" — treat as absent.
    env = {"PIHOLE_PASSWORD_FILE": "", "PIHOLE_PASSWORD": "plain"}
    assert s.resolve_password(env) == "plain"


def test_resolve_password_preserves_inner_whitespace(tmp_path):
    f = tmp_path / "pw"
    _write(f, "a b\tc\n")  # only the trailing newline is stripped
    assert s.resolve_password({"PIHOLE_PASSWORD_FILE": str(f)}) == "a b\tc"
