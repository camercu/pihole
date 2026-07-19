"""Unit tests for the pure decision logic in pihole_sync_lists.py."""
import pihole_sync_lists as s


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
