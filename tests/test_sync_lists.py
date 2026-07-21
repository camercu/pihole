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


def test_plan_add_missing_remove_stale():
    add, remove = s.plan(["a", "b", "c"], {"b", "x"})
    assert add == ["a", "c"]  # order preserved
    assert remove == ["x"]


def test_plan_noop_when_identical():
    assert s.plan(["a", "b"], {"a", "b"}) == ([], [])


def test_plan_all_new():
    add, remove = s.plan(["a", "b"], set())
    assert add == ["a", "b"]
    assert remove == []


def test_plan_all_stale():
    add, remove = s.plan([], {"a", "b"})
    assert add == []
    assert remove == ["a", "b"]  # sorted


def test_plan_dedupes_desired():
    add, _ = s.plan(["a", "a", "b"], set())
    assert add == ["a", "b"]


def test_plan_remove_is_sorted():
    _, remove = s.plan([], {"c", "a", "b"})
    assert remove == ["a", "b", "c"]


def test_plan_membership_add_update_remove():
    desired = {"a": {1}, "b": {1, 2}, "c": {2}}
    current = {"b": {1}, "c": {2}, "d": {1}}
    add, update, remove = s.plan_membership(desired, current)
    assert add == {"a": {1}}          # only in desired
    assert update == {"b": {1, 2}}    # in both, group set differs
    assert remove == ["d"]            # only in current


def test_plan_membership_noop_when_identical():
    m = {"a": {1}, "b": {0, 3}}
    assert s.plan_membership(m, dict(m)) == ({}, {}, [])


def test_plan_membership_remove_is_sorted():
    _, _, remove = s.plan_membership({}, {"c": {1}, "a": {1}, "b": {1}})
    assert remove == ["a", "b", "c"]


def test_plan_membership_all_new():
    add, update, remove = s.plan_membership({"a": {1}}, {})
    assert add == {"a": {1}}
    assert update == {} and remove == []


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
    assert d["adlists"] == {"global-ad.txt": {0}, "kids-ad.txt": {1}}
    assert d["deny_exact"] == {"bad.com": {1}}
    assert d["deny_regex"] == {r"(\.|^)x\.com$": {1}}
    assert d["clients"] == {"10.0.0.5": {0, 1}}  # device joins group AND default


def test_assemble_desired_same_adlist_in_default_and_group_unions():
    d = s.assemble_desired(["shared.txt"], [(1, ["shared.txt"], [], [])])
    assert d["adlists"] == {"shared.txt": {0, 1}}


def test_assemble_desired_two_groups_accumulate_not_overwrite():
    # Guards against `+=` -> `=` in the loop: a shared adlist/client across
    # two groups must union all groups, not just the last one's.
    d = s.assemble_desired(
        [],
        [(1, ["shared.txt"], [], ["10.0.0.5"]),
         (2, ["shared.txt"], [], ["10.0.0.5"])],
    )
    assert d["adlists"] == {"shared.txt": {1, 2}}
    assert d["clients"] == {"10.0.0.5": {0, 1, 2}}  # both groups + default


def test_assemble_desired_empty():
    assert s.assemble_desired([], []) == {
        "adlists": {}, "deny_exact": {}, "deny_regex": {}, "clients": {}}


def test_bucket_by_groups_groups_shared_group_set_into_one_batch():
    # Items inserted out of order so the assertion can only pass if the
    # batch actually sorts them (guards the `sorted(items)`).
    add = {"b": {1}, "a": {1}, "c": {0, 1}}
    got = s._bucket_by_groups(add)
    # sorted by group-set key, items sorted within each batch
    assert got == [([0, 1], ["c"]), ([1], ["a", "b"])]


def test_bucket_by_groups_empty():
    assert s._bucket_by_groups({}) == []


def test_reconcile_membership_rejects_kind_without_item_path():
    # allow_kind has no PUT item_path; membership reconcile needs one, so it
    # must fail fast (before any API call) rather than NoneType-crash mid-run.
    with pytest.raises(AssertionError):
        s.reconcile_membership(None, s.allow_kind("exact"), {})


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
    assert got == {"a": {1}, "b": {1, 2}, "c": {2}}


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
