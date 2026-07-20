"""Unit tests for the pure decision logic in pihole_sync_lists.py."""
import pihole_sync_lists as s


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class TestCleanLines:
    def test_strips_comments_blanks_and_whitespace(self):
        text = "a.com\n  b.com  \n# comment\n\nc.com # trailing\n"
        assert s.clean_lines(text) == ["a.com", "b.com", "c.com"]

    def test_empty_input(self):
        assert s.clean_lines("") == []

    def test_only_comments(self):
        assert s.clean_lines("# one\n   # two\n") == []


class TestIsRegex:
    def test_plain_domains_are_not_regex(self):
        for d in ["www.facebook.com", "example.co.uk", "a-b.example.com"]:
            assert not s.is_regex(d)

    def test_real_regex_pattern(self):
        # from the actual allow.list
        assert s.is_regex(r"(\.|^)twimg\.com$")

    def test_metacharacters_detected(self):
        for pat in ["a|b", "x*", "^host", "end$", "grp(x)", "[abc]"]:
            assert s.is_regex(pat)


class TestSplitAllow:
    def test_partitions_exact_and_regex(self):
        exact, regex = s.split_allow(["a.com", r"(\.|^)twimg\.com$", "b.com"])
        assert exact == ["a.com", "b.com"]
        assert regex == [r"(\.|^)twimg\.com$"]

    def test_empty(self):
        assert s.split_allow([]) == ([], [])


class TestHostDomain:
    def test_plain_domain(self):
        assert s.host_domain("example.com") == "example.com"

    def test_hosts_format_prefix_stripped(self):
        assert s.host_domain("0.0.0.0 example.com") == "example.com"
        assert s.host_domain("127.0.0.1\texample.com") == "example.com"


class TestPlan:
    def test_add_missing_remove_stale(self):
        add, remove = s.plan(["a", "b", "c"], {"b", "x"})
        assert add == ["a", "c"]  # order preserved
        assert remove == ["x"]

    def test_noop_when_identical(self):
        assert s.plan(["a", "b"], {"a", "b"}) == ([], [])

    def test_all_new(self):
        add, remove = s.plan(["a", "b"], set())
        assert add == ["a", "b"]
        assert remove == []

    def test_all_stale(self):
        add, remove = s.plan([], {"a", "b"})
        assert add == []
        assert remove == ["a", "b"]  # sorted

    def test_dedupes_desired(self):
        add, _ = s.plan(["a", "a", "b"], set())
        assert add == ["a", "b"]

    def test_remove_is_sorted(self):
        _, remove = s.plan([], {"c", "a", "b"})
        assert remove == ["a", "b", "c"]


class TestPlanMembership:
    def test_add_update_remove(self):
        desired = {"a": {1}, "b": {1, 2}, "c": {2}}
        current = {"b": {1}, "c": {2}, "d": {1}}
        add, update, remove = s.plan_membership(desired, current)
        assert add == {"a": {1}}          # only in desired
        assert update == {"b": {1, 2}}    # in both, group set differs
        assert remove == ["d"]            # only in current

    def test_noop_when_identical(self):
        m = {"a": {1}, "b": {0, 3}}
        assert s.plan_membership(m, dict(m)) == ({}, {}, [])

    def test_remove_is_sorted(self):
        _, _, remove = s.plan_membership({}, {"c": {1}, "a": {1}, "b": {1}})
        assert remove == ["a", "b", "c"]

    def test_all_new(self):
        add, update, remove = s.plan_membership({"a": {1}}, {})
        assert add == {"a": {1}}
        assert update == {} and remove == []


class TestIsCollision:
    def test_ftl_already_present_400_is_collision(self):
        body = {"error": {"key": "database_error",
                          "message": "The item is already present"}}
        assert s.is_collision(400, body)

    def test_other_400_is_not_collision(self):
        assert not s.is_collision(400, {"error": {"message": "bad regex"}})

    def test_success_is_not_collision(self):
        assert not s.is_collision(201, {})

    def test_text_body_tolerated(self):
        assert s.is_collision(409, "duplicate: item already present")
        assert not s.is_collision(500, "internal error")


class TestReconcileMembershipGuard:
    def test_rejects_kind_without_item_path(self):
        # allow_kind has no PUT item_path; membership reconcile needs one, so it
        # must fail fast (before any API call) rather than NoneType-crash mid-run.
        import pytest
        with pytest.raises(AssertionError):
            s.reconcile_membership(None, s.allow_kind("exact"), {})


class TestNormalizeGroups:
    def test_empty_means_default_group(self):
        # FTL may report a default-only entry as [] or [0]; both mean group 0.
        assert s.normalize_groups([]) == {0}

    def test_explicit_zero_unchanged(self):
        assert s.normalize_groups([0]) == {0}

    def test_non_default_groups_preserved(self):
        assert s.normalize_groups([0, 2]) == {0, 2}
        assert s.normalize_groups([3]) == {3}


class TestBuildMembership:
    def test_unions_group_ids_per_entry(self):
        got = s.build_membership([(1, ["a", "b"]), (2, ["b", "c"])])
        assert got == {"a": {1}, "b": {1, 2}, "c": {2}}

    def test_empty(self):
        assert s.build_membership([]) == {}


class TestDiscoverGroups:
    def test_missing_dir_is_empty(self, tmp_path):
        assert s.discover_groups(str(tmp_path / "nope")) == []

    def test_lists_subdirs_sorted_by_name(self, tmp_path):
        (tmp_path / "teens").mkdir()
        (tmp_path / "kids").mkdir()
        got = s.discover_groups(str(tmp_path))
        assert [name for name, _ in got] == ["kids", "teens"]
        assert got[0] == ("kids", str(tmp_path / "kids"))

    def test_ignores_non_directories(self, tmp_path):
        (tmp_path / "kids").mkdir()
        _write(tmp_path / "README.txt", "not a group\n")
        assert [name for name, _ in s.discover_groups(str(tmp_path))] == ["kids"]
