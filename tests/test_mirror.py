"""Unit tests for the pure decision logic in pihole_mirror.py.

Mirroring is the inverse of the reconciler: it reads live Pi-hole state and works
out which config file each hand-added entry belongs in. The invariant these
tests pin down is *faithfulness* — an entry is only routed into a config file
when re-running the reconciler from that file would reproduce the entry's
current group set exactly. Anything else is reported, never silently reshaped.
"""
import json
import os
import pathlib
import subprocess

import pihole_mirror as h
import pytest

MANAGED = "managed by ansible"

# id 0 is Pi-hole's built-in Default group; "kids" is reconciler-managed and
# "guests" was created by hand in the admin UI.
GROUPS = [
    {"id": 0, "name": "Default", "comment": None},
    {"id": 2, "name": "kids", "comment": MANAGED},
    {"id": 3, "name": "guests", "comment": None},
]


def _state(**kw):
    """Live-state fixture with every collection present but empty by default."""
    return {"groups": kw.pop("groups", GROUPS), "lists": kw.pop("lists", []),
            "domains": kw.pop("domains", []), "clients": kw.pop("clients", [])}


def _adlist(address, groups, comment=None, enabled=True):
    return {"address": address, "type": "block", "groups": groups,
            "comment": comment, "enabled": enabled}


def _domain(domain, type_, kind, groups, comment=None, enabled=True):
    return {"domain": domain, "type": type_, "kind": kind, "groups": groups,
            "comment": comment, "enabled": enabled}


def _client(client, groups, comment=None):
    return {"client": client, "groups": groups, "comment": comment}


# ── ownership ───────────────────────────────────────────────────────────────
def test_a_managed_entry_already_in_its_file_is_not_written_again(tmp_path):
    # The file is what put it there, so it is part of what the file should list
    # — but appending it again on every mirror run would duplicate the line.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text("https://a.example/list.txt\n",
                                     encoding="utf-8")
    state = _state(lists=[_adlist("https://a.example/list.txt", [0], MANAGED)])

    plan = h.plan_mirror(state)

    assert plan.files == {"adlists.txt": ["https://a.example/list.txt"]}
    assert plan.unroutable == []
    assert h.pending_changes(str(cfg), plan) == []


def test_hand_added_default_group_adlist_goes_to_top_level_adlists():
    state = _state(lists=[_adlist("https://a.example/list.txt", [0])])
    assert h.plan_mirror(state).files == {
        "adlists.txt": ["https://a.example/list.txt"]}


def test_adlist_with_no_groups_is_treated_as_default_group():
    # FTL reports a default-only entry as either [] or [0].
    state = _state(lists=[_adlist("https://a.example/list.txt", [])])
    assert h.plan_mirror(state).files == {
        "adlists.txt": ["https://a.example/list.txt"]}


def test_group_scoped_adlist_goes_to_that_groups_file():
    state = _state(lists=[_adlist("https://k.example/list.txt", [2])])
    assert h.plan_mirror(state).files == {
        "groups/kids/adlists.txt": ["https://k.example/list.txt"]}


def test_adlist_in_default_and_a_group_is_written_to_both_files():
    # assemble_desired unions the same URL from both files onto one row, so
    # writing both reproduces the live group set exactly.
    state = _state(lists=[_adlist("https://s.example/list.txt", [0, 2])])
    assert h.plan_mirror(state).files == {
        "adlists.txt": ["https://s.example/list.txt"],
        "groups/kids/adlists.txt": ["https://s.example/list.txt"],
    }


# ── allow domains: the config expresses these network-wide only ─────────────
def test_hand_added_allow_domain_goes_to_allow_list():
    state = _state(domains=[_domain("ok.example", "allow", "exact", [0])])
    assert h.plan_mirror(state).files == {"allow.list": ["ok.example"]}


def test_allow_regex_goes_to_allow_list_verbatim():
    pattern = r"(\.|^)twimg\.example$"
    state = _state(domains=[_domain(pattern, "allow", "regex", [0])])
    assert h.plan_mirror(state).files == {"allow.list": [pattern]}


def test_group_scoped_allow_domain_is_reported_not_narrowed():
    state = _state(domains=[_domain("ok.example", "allow", "exact", [2])])
    plan = h.plan_mirror(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == ["allow/exact ok.example"]
    assert "network-wide" in plan.unroutable[0][1]


def test_a_fetched_allowlist_domain_is_invisible_to_the_mirror():
    # allowlist-urls.txt's own curated domains carry a distinct comment so the
    # mirror can tell them from allow.list's. Routing, protecting or reporting
    # on them would fork the upstream list into allow.list permanently.
    state = _state(domains=[_domain("fetched.example", "allow", "exact", [0],
                                    h.MANAGED_FETCHED)])
    plan = h.plan_mirror(state)
    assert plan.files == {}
    assert plan.unroutable == []
    assert plan.protected == frozenset()


def test_a_fetched_allowlist_domain_is_never_written_into_allow_list(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "allow.list").write_text("kept.example\n", encoding="utf-8")
    state = _only_default_group(
        domains=[_domain("kept.example", "allow", "exact", [0], MANAGED),
                 _domain("fetched.example", "allow", "exact", [0],
                         h.MANAGED_FETCHED)])

    _merge(tmp_path, state, cfg)

    assert h.clean_lines((cfg / "allow.list").read_text()) == ["kept.example"]


# ── deny domains: the config expresses these per group only ─────────────────
def test_group_scoped_deny_domain_goes_to_that_groups_block_list():
    state = _state(domains=[_domain("bad.example", "deny", "exact", [2])])
    assert h.plan_mirror(state).files == {
        "groups/kids/block.list": ["bad.example"]}


def test_deny_domain_in_default_group_is_reported_not_silently_narrowed():
    # Routing this to one group's block.list would stop blocking it for
    # everyone else — a behaviour change the user never asked for.
    state = _state(domains=[_domain("bad.example", "deny", "exact", [0, 2])])
    plan = h.plan_mirror(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == ["deny/exact bad.example"]


def test_deny_domain_blocked_network_wide_only_says_so():
    # No group to name: the config simply has no network-wide blocklist, and
    # the reason has to say that rather than trail off.
    state = _state(domains=[_domain("bad.example", "deny", "exact", [0])])
    plan = h.plan_mirror(state)
    assert plan.files == {}
    assert "no network-wide blocklist" in plan.unroutable[0][1]


def test_deny_domain_spanning_two_groups_is_written_to_both():
    pattern = r"(\.|^)bad\.example$"
    state = _state(domains=[_domain(pattern, "deny", "regex", [2, 3])])
    assert h.plan_mirror(state).files == {
        "groups/kids/block.list": [pattern],
        "groups/guests/block.list": [pattern],
    }


# ── clients: the config always places a device in its group AND default ─────
def test_client_in_group_and_default_goes_to_that_groups_clients_file():
    state = _state(clients=[_client("10.0.0.5", [0, 2])])
    assert h.plan_mirror(state).files == {
        "groups/kids/clients.txt": ["10.0.0.5"]}


def test_client_without_the_default_group_is_reported_not_widened():
    # Mirroring this would hand the device the default group's adlists on the
    # next reconcile — more blocking than the user configured.
    state = _state(clients=[_client("10.0.0.5", [2])])
    plan = h.plan_mirror(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == ["client 10.0.0.5"]


def test_client_in_the_default_group_only_is_reported():
    # The config has no top-level clients file: group membership is the only
    # thing it can say about a device.
    state = _state(clients=[_client("10.0.0.5", [0])])
    plan = h.plan_mirror(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == ["client 10.0.0.5"]


# ── things the config cannot say ────────────────────────────────────────────
def test_disabled_entry_is_reported_not_mirrored_as_enabled():
    # The reconciler adds everything enabled; mirroring a UI-disabled entry
    # would switch it back on at the next run.
    state = _state(lists=[_adlist("https://a.example/list.txt", [0], enabled=False)])
    plan = h.plan_mirror(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == ["adlist https://a.example/list.txt"]
    assert "disabled" in plan.unroutable[0][1]


def test_entry_in_an_unknown_group_id_is_reported():
    state = _state(lists=[_adlist("https://a.example/list.txt", [99])])
    plan = h.plan_mirror(state)
    assert plan.files == {}
    assert "99" in plan.unroutable[0][1]


def test_domain_of_a_kind_the_config_has_no_rule_for_is_reported():
    # Routing dispatched by falling through to the client rule, so a domain type
    # this router does not know — one a later FTL adds — was written into a
    # group's clients.txt as if it were a device.
    state = _state(domains=[_domain("x.example", "sinkhole", "exact", [0, 2])])
    plan = h.plan_mirror(state)
    assert plan.files == {}  # not "groups/kids/clients.txt": ["x.example"]
    assert [item for item, _ in plan.unroutable] == ["sinkhole/exact x.example"]
    assert "device" not in plan.unroutable[0][1]  # nor rejected as one


def test_every_adoptable_kind_has_a_single_entry_api_path():
    # Adoption PUTs through this table. A kind missing from it would 404 against
    # a live box and nowhere else — the integration tests only adopt an adlist.
    for kind in h.Kind:
        if kind is h.Kind.ALLOW_ADLIST:
            continue  # never routed, so never adopted
        assert h._item_path(h.Entry(kind, "x.example", (0,), True))


# ── group directories ───────────────────────────────────────────────────────
def test_hand_created_group_yields_a_group_directory():
    assert h.plan_mirror(_state()).group_dirs == ["guests"]


def test_group_dir_is_listed_for_any_group_an_entry_routes_into():
    state = _state(domains=[_domain("bad.example", "deny", "exact", [2])])
    plan = h.plan_mirror(state)
    assert plan.group_dirs == ["guests", "kids"]


def test_default_group_never_becomes_a_directory():
    state = _state(groups=[{"id": 0, "name": "Default", "comment": None}])
    assert h.plan_mirror(state).group_dirs == []


# ── determinism ─────────────────────────────────────────────────────────────
def test_lines_within_a_file_are_sorted_and_deduped():
    state = _state(lists=[_adlist("https://b.example/l.txt", [0]),
                          _adlist("https://a.example/l.txt", [0]),
                          _adlist("https://b.example/l.txt", [0])])
    assert h.plan_mirror(state).files["adlists.txt"] == [
        "https://a.example/l.txt", "https://b.example/l.txt"]


# ── merging mirrored lines into an existing config file ────────────────────
def test_merge_appends_a_new_entry_to_an_existing_file():
    assert h.merge_lines("a.example\n", ["b.example"]) == "a.example\nb.example\n"


def test_merge_into_an_absent_or_empty_file_writes_just_the_entries():
    assert h.merge_lines("", ["a.example"]) == "a.example\n"


def test_merge_preserves_comments_and_blank_lines_verbatim():
    existing = "# Blocklists.\n\nhttps://a.example/l.txt\n"
    assert h.merge_lines(existing, ["https://b.example/l.txt"]) == (
        "# Blocklists.\n\nhttps://a.example/l.txt\nhttps://b.example/l.txt\n")


def test_merge_is_a_no_op_when_every_entry_is_already_present():
    # Rewriting an unchanged file would show up as noise in `git diff`.
    assert h.merge_lines("a.example\n", ["a.example"]) is None


def test_merge_skips_entries_already_present_and_appends_the_rest():
    assert h.merge_lines("a.example\n", ["a.example", "b.example"]) == (
        "a.example\nb.example\n")


def test_merge_ignores_trailing_comments_when_deciding_presence():
    assert h.merge_lines("a.example # ours\n", ["a.example"]) is None


def test_merge_appends_an_entry_that_exists_only_as_a_commented_example():
    # clients.txt ships its examples commented out; a device really added in
    # the UI has to become a live line, not stay an example.
    assert h.merge_lines("# 10.0.0.5\n", ["10.0.0.5"]) == "# 10.0.0.5\n10.0.0.5\n"


def test_merge_adds_the_missing_newline_before_appending():
    assert h.merge_lines("a.example", ["b.example"]) == "a.example\nb.example\n"


def test_merge_dedupes_repeated_entries_in_one_call():
    assert h.merge_lines("", ["a.example", "a.example"]) == "a.example\n"


# ── deciding what a mirror run would change, before changing it ────────────────
def test_pending_reports_the_full_text_a_file_would_be_given(tmp_path):
    (tmp_path / "adlists.txt").write_text("a.example\n", encoding="utf-8")
    plan = h.Plan(files={"adlists.txt": ["b.example"]}, group_dirs=[],
                  unroutable=[], routed=[])
    assert h.pending_changes(tmp_path, plan) == [
        ("adlists.txt", "a.example\nb.example\n")]


def test_pending_covers_a_file_that_does_not_exist_yet(tmp_path):
    plan = h.Plan(files={"groups/kids/block.list": ["bad.example"]},
                  group_dirs=["kids"], unroutable=[], routed=[])
    assert h.pending_changes(tmp_path, plan) == [
        ("groups/kids/block.list", "bad.example\n")]


def test_pending_is_empty_when_every_entry_is_already_recorded(tmp_path):
    (tmp_path / "adlists.txt").write_text("a.example\n", encoding="utf-8")
    plan = h.Plan(files={"adlists.txt": ["a.example"]}, group_dirs=[],
                  unroutable=[], routed=[])
    assert h.pending_changes(tmp_path, plan) == []


def test_pending_changes_nothing_on_disk(tmp_path):
    # The drift check runs this against a working tree it must not touch.
    path = tmp_path / "adlists.txt"
    path.write_text("a.example\n", encoding="utf-8")
    plan = h.Plan(files={"adlists.txt": ["b.example"]}, group_dirs=[],
                  unroutable=[], routed=[])
    h.pending_changes(tmp_path, plan)
    assert path.read_text() == "a.example\n"
    assert not (tmp_path / "groups").exists()


def test_write_changes_creates_missing_directories(tmp_path):
    h.write_changes(tmp_path, [("groups/kids/block.list", "bad.example\n")])
    assert (tmp_path / "groups/kids/block.list").read_text() == "bad.example\n"


# ── groups the config tree has nothing to say about ─────────────────────────
def test_group_with_entries_to_write_is_not_reported_as_unconfigured(tmp_path):
    # The check runs without writing, so "does the directory exist yet" is the
    # wrong question — this group is about to get a file.
    plan = h.Plan(files={"groups/kids/block.list": ["bad.example"]},
                  group_dirs=["kids"], unroutable=[], routed=[])
    assert h.groups_without_config(tmp_path, plan) == []


def test_group_with_an_existing_directory_is_not_reported(tmp_path):
    (tmp_path / "groups" / "kids").mkdir(parents=True)
    plan = h.Plan(files={}, group_dirs=["kids"], unroutable=[], routed=[])
    assert h.groups_without_config(tmp_path, plan) == []


def test_group_with_neither_files_nor_a_directory_is_reported(tmp_path):
    # git does not track an empty directory, so there is nothing to create —
    # only something to tell the user about.
    plan = h.Plan(files={}, group_dirs=["guests"], unroutable=[], routed=[])
    assert h.groups_without_config(tmp_path, plan) == ["guests"]


# ── handing a captured entry over to the reconciler ─────────────────────────
def _entry(kind, entry, groups, enabled=True):
    return h.Entry(kind, entry, tuple(groups), enabled)


def test_entry_recorded_in_its_config_file_can_be_adopted():
    adlist = _entry("adlist", "https://a.example/l.txt", [0])
    present = {"adlists.txt": {"https://a.example/l.txt"}}
    assert h.plan_adopt([(adlist, ["adlists.txt"])], present) == [adlist]


def test_entry_missing_from_its_config_file_is_not_adopted():
    # Marking it managed would hand the reconciler an entry no file asks for,
    # and the next run would delete it.
    routed = [(_entry("adlist", "https://a.example/l.txt", [0]), ["adlists.txt"])]
    assert h.plan_adopt(routed, {"adlists.txt": {"https://other.example/l.txt"}}) == []


def test_entry_recorded_in_only_some_of_its_files_is_not_adopted():
    # A shared adlist in the default group and kids: with only the top-level
    # file recording it, adopting would drop kids from its group set.
    routed = [(_entry("adlist", "https://a.example/l.txt", [0, 2]),
               ["adlists.txt", "groups/kids/adlists.txt"])]
    present = {"adlists.txt": {"https://a.example/l.txt"},
               "groups/kids/adlists.txt": set()}
    assert h.plan_adopt(routed, present) == []


def test_adoption_distinguishes_entries_of_different_kinds():
    # The same name allowed network-wide and denied for a group are two rows.
    allowed = _entry("allow/exact", "x.example", [0])
    routed = [(allowed, ["allow.list"]),
              (_entry("deny/exact", "x.example", [2]),
               ["groups/kids/block.list"])]
    present = {"allow.list": {"x.example"}, "groups/kids/block.list": set()}
    assert h.plan_adopt(routed, present) == [allowed]


def test_adoption_reads_config_files_the_way_the_reconciler_does(tmp_path):
    (tmp_path / "adlists.txt").write_text(
        "# a comment\nhttps://a.example/l.txt # ours\n", encoding="utf-8")
    assert h.read_present(tmp_path, ["adlists.txt", "missing.txt"]) == {
        "adlists.txt": {"https://a.example/l.txt"}, "missing.txt": set()}


# ── shapes the config file cannot round-trip ────────────────────────────────
def test_regex_domain_that_reads_as_a_plain_domain_is_reported():
    # block.list carries no shape marker: the reconciler re-derives regex-ness
    # from the text. A keyword regex like this has no metacharacters, so it
    # would come back as an exact match and stop blocking subdomains.
    state = _state(domains=[_domain("doubleclick", "deny", "regex", [2])])
    plan = h.plan_mirror(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == ["deny/regex doubleclick"]
    assert "regex" in plan.unroutable[0][1]


def test_allow_regex_that_reads_as_a_plain_domain_is_reported():
    state = _state(domains=[_domain("doubleclick", "allow", "regex", [0])])
    assert h.plan_mirror(state).files == {}


def test_regex_domain_with_metacharacters_still_routes():
    pattern = r"(\.|^)ads\.example$"
    state = _state(domains=[_domain(pattern, "deny", "regex", [2])])
    assert h.plan_mirror(state).files == {"groups/kids/block.list": [pattern]}


def test_exact_domain_that_reads_as_a_regex_is_reported():
    # The mirror case: the reconciler would push this back as a regex.
    state = _state(domains=[_domain("ads*.example", "deny", "exact", [2])])
    assert h.plan_mirror(state).files == {}


def test_entry_with_a_comment_character_is_reported():
    # merge_lines judges presence after stripping '#', so an entry containing
    # one would be appended again by every mirror run and never read back whole.
    url = "https://a.example/l.txt#frag"
    state = _state(lists=[_adlist(url, [0])])
    plan = h.plan_mirror(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == [f"adlist {url}"]


def test_entry_with_surrounding_whitespace_is_reported():
    state = _state(lists=[_adlist(" https://a.example/l.txt ", [0])])
    assert h.plan_mirror(state).files == {}


# ── group names that cannot be directories ──────────────────────────────────
def test_group_named_with_a_path_traversal_is_reported_not_written():
    groups = GROUPS + [{"id": 4, "name": "../../evil", "comment": None}]
    state = _state(groups=groups,
                   domains=[_domain("x.example", "deny", "exact", [4])])
    plan = h.plan_mirror(state)
    assert plan.files == {}
    assert plan.group_dirs == ["guests"]
    assert any("../../evil" in item for item, _ in plan.unroutable)


def test_group_named_with_a_slash_is_reported():
    groups = GROUPS + [{"id": 4, "name": "a/b", "comment": None}]
    state = _state(groups=groups,
                   domains=[_domain("x.example", "deny", "exact", [4])])
    plan = h.plan_mirror(state)
    assert plan.files == {}
    assert "a/b" not in plan.group_dirs


def test_group_named_dot_is_reported():
    groups = GROUPS + [{"id": 4, "name": ".", "comment": None}]
    plan = h.plan_mirror(_state(groups=groups))
    assert "." not in plan.group_dirs
    assert any("'.'" in item for item, _ in plan.unroutable)


# ── allow adlists, which the config format has no file for ──────────────────
def test_allow_type_adlist_is_reported_rather_than_ignored():
    # Pi-hole keeps allow adlists in the same table under a different type;
    # dropping them from the export would make the drift check say "in sync"
    # about a setting no file records.
    state = _state()
    state["allow_lists"] = [{"address": "https://a.example/allow.txt",
                             "type": "allow", "groups": [0], "comment": None,
                             "enabled": True}]
    plan = h.plan_mirror(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == [
        "allow adlist https://a.example/allow.txt"]


def test_plan_records_the_row_it_decided_against():
    # Adoption happens later, against a second look at live state; without the
    # record the plan was made from there is nothing to re-check.
    state = _state(lists=[_adlist("https://a.example/l.txt", [0, 2])])
    assert h.plan_mirror(state).routed == [
        (_entry("adlist", "https://a.example/l.txt", [0, 2]),
         ["adlists.txt", "groups/kids/adlists.txt"])]


# ── adoption re-checks live state before changing anything ──────────────────
def _live(**kw):
    return _state(**kw)


def test_entry_still_matching_the_plan_is_adopted():
    planned = _entry("adlist", "https://a.example/l.txt", [0])
    state = _live(lists=[_adlist("https://a.example/l.txt", [0])])
    ready, skipped = h.adoptable_now([planned], state)
    assert (ready, skipped) == ([planned], [])


def test_entry_regrouped_since_the_plan_is_left_alone():
    # Someone moved it in the UI between mirroring and adopt: the config files
    # record the old group set, so handing it over would narrow it silently.
    planned = _entry("adlist", "https://a.example/l.txt", [0])
    state = _live(lists=[_adlist("https://a.example/l.txt", [0, 2])])
    assert h.adoptable_now([planned], state)[0] == []


def test_a_planned_entry_left_alone_is_named_with_the_reason():
    # Adoption used to drop these silently and still report success, so a run
    # that handed over nothing it planned looked exactly like one that worked.
    planned = _entry("adlist", "https://a.example/l.txt", [0])
    state = _live(lists=[_adlist("https://a.example/l.txt", [0, 2])])
    _, skipped = h.adoptable_now([planned], state)
    assert [s.entry for s in skipped] == [planned]
    assert "changed since" in skipped[0].reason
    assert skipped[0].stale  # so the run says so rather than reporting success


def test_entry_disabled_since_the_plan_is_left_alone():
    # Someone switched it off in the UI between mirroring and adopt. Mirroring
    # refuses to route a disabled row at all, so adopting one would stamp it as
    # the reconciler's while it is off — and the reconciler sets enabled only on
    # add, so nothing would ever switch it back on.
    at_mirror = _live(lists=[_adlist("https://a.example/l.txt", [0])])
    planned = h.plan_adopt(h.plan_mirror(at_mirror).routed,
                           {"adlists.txt": {"https://a.example/l.txt"}})
    switched_off = _live(lists=[_adlist("https://a.example/l.txt", [0],
                                        enabled=False)])
    assert h.adoptable_now(planned, switched_off)[0] == []


def test_entry_already_owned_by_the_reconciler_is_skipped():
    planned = _entry("adlist", "https://a.example/l.txt", [0])
    state = _live(lists=[_adlist("https://a.example/l.txt", [0], MANAGED)])
    ready, skipped = h.adoptable_now([planned], state)
    assert ready == []
    assert "already" in skipped[0].reason
    # Not stale: this is a repeat run finding its work done, so it must not
    # fail the playbook every time someone runs `just adopt` twice.
    assert not skipped[0].stale


def test_entry_gone_from_the_box_is_skipped():
    planned = _entry("adlist", "https://a.example/l.txt", [0])
    ready, skipped = h.adoptable_now([planned], _live())
    assert ready == []
    assert "no longer" in skipped[0].reason
    assert skipped[0].stale


def test_a_plan_survives_the_json_round_trip_between_deciding_and_doing():
    # --plan-adopt writes the decision as JSON on the controller and --adopt
    # reads it back on the Pi. Group ids arrive as a list; a record compared by
    # value would match nothing if it stayed one, and adoption would silently
    # hand over nothing while reporting success.
    state = _live(lists=[_adlist("https://a.example/l.txt", [0, 2])])
    recorded = {"adlists.txt": {"https://a.example/l.txt"},
                "groups/kids/adlists.txt": {"https://a.example/l.txt"}}
    planned = h.plan_adopt(h.plan_mirror(state).routed, recorded)

    carried = h.entries_from_json(json.loads(json.dumps(h.entries_to_json(planned))))

    assert h.adoptable_now(carried, state)[0] == planned
    # A Kind, not the bare string it compares equal to: the shell asks `is` of
    # it to decide what goes in the PUT body, and a string answers no to that.
    assert all(isinstance(e.kind, h.Kind) for e in carried)


# ── exit codes, which are what the playbooks gate on ────────────────────────
def _only_default_group(**kw):
    """Live state with just the built-in group, so no group-directory warning
    muddies what the exit code is being asserted about."""
    return _state(groups=[{"id": 0, "name": "Default", "comment": None}], **kw)


def _state_file(tmp_path, state):
    path = tmp_path / "state.json"
    path.write_text(json.dumps(state), encoding="utf-8")
    return str(path)


def _check(tmp_path, state, cfg):
    return h.main(["--check", _state_file(tmp_path, state), "--dir", str(cfg)])


def _merge(tmp_path, state, cfg):
    return h.main(["--merge", _state_file(tmp_path, state), "--dir", str(cfg)])


# ── deletions made in the admin UI ──────────────────────────────────────────
def test_entry_deleted_in_the_admin_ui_is_removed_from_its_config_file(tmp_path):
    # Capture ran one way only, so deleting a blocklist in the UI left the file
    # still listing it and the next site.yml put it straight back.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text(
        "# our blocklists\nhttps://gone.example/l.txt\nhttps://kept.example/l.txt\n",
        encoding="utf-8")
    state = _only_default_group(
        lists=[_adlist("https://kept.example/l.txt", [0], MANAGED)])

    _merge(tmp_path, state, cfg)

    assert (cfg / "adlists.txt").read_text() == (
        "# our blocklists\nhttps://kept.example/l.txt\n")


def test_a_file_the_mirror_cannot_route_to_is_never_pruned(tmp_path):
    # allowlist-urls.txt names remote lists to fetch, not entries Pi-hole holds,
    # so no live row corresponds to a line here and every one would look deleted.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "allowlist-urls.txt").write_text("https://a.example/allow.txt\n",
                                            encoding="utf-8")

    _merge(tmp_path, _only_default_group(), cfg)

    assert (cfg / "allowlist-urls.txt").read_text() == "https://a.example/allow.txt\n"


def test_nothing_is_pruned_from_a_file_the_box_was_never_deployed_from(tmp_path):
    # A freshly installed Pi-hole holds its own default blocklist and nothing
    # else. Every entry these files list is missing from it — not because
    # anyone deleted them, but because they were never deployed here. Pruning
    # on that reading empties the config the first time someone runs a mirror
    # against a box they have not deployed to yet.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text(
        "https://one.example/l.txt\nhttps://two.example/l.txt\n"
        "https://three.example/l.txt\n", encoding="utf-8")
    fresh = _only_default_group(
        lists=[_adlist("https://shipped.example/l.txt", [0])])

    _merge(tmp_path, fresh, cfg)

    kept = h.clean_lines((cfg / "adlists.txt").read_text())
    assert "https://one.example/l.txt" in kept
    assert "https://two.example/l.txt" in kept
    assert "https://three.example/l.txt" in kept


def test_the_report_says_how_many_entries_each_file_lost(tmp_path, capsys):
    # Comments survive a prune, so a section whose every entry went still shows
    # its heading and the file reads as though the entries are there. The count
    # is what tells a reviewer of the diff that the heading now means nothing.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text(
        "# ads\nhttps://gone.example/l.txt\nhttps://also-gone.example/l.txt\n"
        "https://kept.example/l.txt\n", encoding="utf-8")
    state = _only_default_group(
        lists=[_adlist("https://kept.example/l.txt", [0], MANAGED)])

    _merge(tmp_path, state, cfg)

    assert "adlists.txt (2 removed)" in capsys.readouterr().out


def test_an_undescribed_group_is_drift_not_unrecordable(tmp_path, capsys):
    # A group made by hand in the admin UI has no config directory yet. A
    # person can create one -- unlike a genuinely unexpressible setting -- so
    # this belongs with drift, which a check does not pass on, not with the
    # format's permanent limitations, which it does.
    cfg = tmp_path / "config"
    cfg.mkdir()
    state = _state(groups=[
        {"id": 0, "name": "Default", "comment": None},
        {"id": 9, "name": "guests", "comment": "made in the admin UI"}])

    rc = _check(tmp_path, state, cfg)

    assert rc == h.DRIFT
    assert "guests" in capsys.readouterr().err


def test_a_refusal_outranks_a_setting_that_cannot_be_expressed(tmp_path, capsys):
    # Both playbooks pass exit 4, because an unexpressible setting has no fix.
    # Reporting 4 for a run that also declined to prune hid the refusal behind
    # something normal: one disabled entry made every refusal read as green.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text(
        "https://one.example/l.txt\nhttps://two.example/l.txt\n",
        encoding="utf-8")
    state = _only_default_group(
        lists=[_adlist("https://shipped.example/l.txt", [0])],
        domains=[_domain("off.example", "deny", "exact", [0], enabled=False)])

    assert _merge(tmp_path, state, cfg) == h.UNPRUNED
    said = capsys.readouterr()
    assert "it is disabled" in said.err
    assert "adlists.txt" in said.err


def test_a_run_that_declined_to_prune_does_not_call_itself_in_sync(tmp_path,
                                                                   capsys):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text("https://one.example/l.txt\n",
                                     encoding="utf-8")

    # Nothing to write back, so the old wording had nothing to report and said
    # the files matched the box — on the one run that had just declined to make
    # them match it.
    h.main(["--check", _state_file(tmp_path, _only_default_group()),
            "--dir", str(cfg)])

    assert "in sync" not in capsys.readouterr().out


def test_a_declined_run_gets_a_summary_line_like_every_other_verdict(tmp_path,
                                                                     capsys):
    # The per-file warnings scroll past in the playbook's debug dump; the
    # summary is the line that survives it.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text("https://one.example/l.txt\n",
                                     encoding="utf-8")

    h.main(["--check", _state_file(tmp_path, _only_default_group()),
            "--dir", str(cfg)])

    assert "ERROR: 1 config file(s) left as they are" in capsys.readouterr().err


def test_refusing_to_prune_is_reported_and_fails_the_run(tmp_path, capsys):
    # Silence would leave the operator believing the files now match the box.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text(
        "https://one.example/l.txt\nhttps://two.example/l.txt\n",
        encoding="utf-8")
    fresh = _only_default_group(
        lists=[_adlist("https://shipped.example/l.txt", [0])])

    assert _merge(tmp_path, fresh, cfg) == h.UNPRUNED
    said = capsys.readouterr().err
    assert "adlists.txt" in said
    assert "2" in said


def test_a_deletion_survives_when_the_remaining_row_is_protected(tmp_path):
    # allow.list lists three domains, all previously captured. In the UI the
    # operator deletes two of them and ticks a group on the third, so the box
    # now holds only a row the config format cannot place network-wide -- a
    # protected row, not a routed one, but proof this file was deployed here.
    # box_holds_any_of ignoring plan.protected reads "nothing routed" as
    # "never deployed", refuses the two real deletions, and tells the
    # operator to deploy first -- which would undo them.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "allow.list").write_text("a.example\nb.example\nc.example\n",
                                    encoding="utf-8")
    groups = [{"id": 0, "name": "Default", "comment": None},
             {"id": 2, "name": "kids", "comment": MANAGED}]
    state = _state(groups=groups,
                   domains=[_domain("a.example", "allow", "exact", [2], MANAGED)])

    rc = _merge(tmp_path, state, cfg)

    assert (cfg / "allow.list").read_text() == "a.example\n"
    assert rc == h.OK


def test_an_unroutable_row_only_protects_files_its_own_kind_could_reach(tmp_path):
    # allow.list lists a domain still deployed (kept.example, proving the file
    # was deployed here) and one deleted in the UI (shared.example). A
    # disabled deny/exact row happens to share the deleted domain's name; the
    # two never share a file, so the deny row being protected must not freeze
    # the unrelated deletion in allow.list.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "allow.list").write_text("kept.example\nshared.example\n",
                                    encoding="utf-8")
    state = _only_default_group(
        domains=[_domain("kept.example", "allow", "exact", [0], MANAGED),
                 _domain("shared.example", "deny", "exact", [0], enabled=False)])

    rc = _merge(tmp_path, state, cfg)

    assert h.clean_lines((cfg / "allow.list").read_text()) == ["kept.example"]
    assert rc == h.UNRECORDABLE


def test_force_prune_captures_a_wholesale_deletion(tmp_path):
    # The one case the evidence rule declines wrongly: every entry really was
    # deleted in the UI, so nothing managed is left to prove the box took the
    # file. The flag is how an operator says so.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text("https://gone.example/l.txt\n",
                                     encoding="utf-8")

    h.main(["--merge", _state_file(tmp_path, _only_default_group()),
            "--dir", str(cfg), "--force-prune"])

    assert h.clean_lines((cfg / "adlists.txt").read_text()) == []


def test_evidence_does_not_require_the_row_to_be_managed(tmp_path):
    # File-level presence, not managed-only, was the deliberate choice: the
    # ownership comment is free text an operator can type in the UI, so
    # trusting it for evidence would be trusting exactly the field a UI edit
    # can rewrite. A hand-added row matching a file's line is evidence enough
    # that this box has taken this file before.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "allow.list").write_text("kept.example\ngone.example\n",
                                    encoding="utf-8")
    state = _only_default_group(
        domains=[_domain("kept.example", "allow", "exact", [0])])  # hand-added

    _merge(tmp_path, state, cfg)

    assert h.clean_lines((cfg / "allow.list").read_text()) == ["kept.example"]


def test_the_removed_count_is_what_left_not_what_changed(tmp_path, capsys):
    # A run that drops a deleted entry and picks up a new one in the same file
    # must count only the drop; a symmetric difference would count the
    # addition too and tell the operator twice as many lines went missing.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "allow.list").write_text("gone.example\nkept.example\n",
                                    encoding="utf-8")
    state = _only_default_group(
        domains=[_domain("kept.example", "allow", "exact", [0], MANAGED),
                 _domain("new.example", "allow", "exact", [0], MANAGED)])

    _merge(tmp_path, state, cfg)

    assert "allow.list (1 removed)" in capsys.readouterr().out


def test_force_prune_never_reports_a_refusal(tmp_path, capsys):
    # Under --force-prune the operator has already said the deletions were
    # real; refused_prunes must not run at all, or its warning would
    # contradict the flag that just overrode it.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text("https://one.example/l.txt\n",
                                     encoding="utf-8")

    rc = h.main(["--merge", _state_file(tmp_path, _only_default_group()),
                "--dir", str(cfg), "--force-prune"])

    assert rc == h.OK
    assert "left as they are" not in capsys.readouterr().err


def test_a_declined_merge_says_declined_not_no_changes(tmp_path, capsys):
    # "no changes" on a run that just refused to make one reads as clean.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text("https://one.example/l.txt\n",
                                     encoding="utf-8")

    _merge(tmp_path, _only_default_group(), cfg)

    assert "DECLINED" in capsys.readouterr().out


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True,
                   capture_output=True, text=True)


def _init_git_repo(cfg):
    _git(cfg, "init", "-q")
    _git(cfg, "config", "user.email", "test@example.com")
    _git(cfg, "config", "user.name", "test")
    _git(cfg, "add", "-A")
    _git(cfg, "commit", "-q", "-m", "initial")


def test_working_tree_is_dirty_true_for_an_uncommitted_owned_file(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "allow.list").write_text("a.example\n", encoding="utf-8")
    _init_git_repo(cfg)
    (cfg / "allow.list").write_text("a.example\nb.example\n", encoding="utf-8")

    assert h.working_tree_is_dirty(str(cfg), ["allow.list"]) is True


def test_working_tree_is_dirty_false_when_committed(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "allow.list").write_text("a.example\n", encoding="utf-8")
    _init_git_repo(cfg)

    assert h.working_tree_is_dirty(str(cfg), ["allow.list"]) is False


def test_working_tree_is_dirty_none_outside_a_git_repo(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "allow.list").write_text("a.example\n", encoding="utf-8")

    assert h.working_tree_is_dirty(str(cfg), ["allow.list"]) is None


def test_merge_refuses_a_dirty_working_tree(tmp_path, capsys):
    # An uncommitted hand-edit to allow.list and a mirror run both touch the
    # same file; merging into it makes the two indistinguishable in git diff,
    # and the run would overwrite whatever is not yet on the box.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "allow.list").write_text("a.example\n", encoding="utf-8")
    _init_git_repo(cfg)
    (cfg / "allow.list").write_text("a.example\nb.example\n", encoding="utf-8")
    state = _only_default_group(
        domains=[_domain("a.example", "allow", "exact", [0], MANAGED)])

    rc = _merge(tmp_path, state, cfg)

    assert rc == h.DIRTY
    assert h.clean_lines((cfg / "allow.list").read_text()) == ["a.example",
                                                                "b.example"]
    assert "uncommitted" in capsys.readouterr().err


def test_nothing_is_pruned_when_live_state_is_empty(tmp_path):
    # An unprovisioned or wiped box answers with nothing at all. Reading that as
    # "the operator deleted everything" would empty the config in one run.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text("https://a.example/l.txt\n", encoding="utf-8")
    empty = {"groups": [], "lists": [], "allow_lists": [], "domains": [],
             "clients": []}

    _merge(tmp_path, empty, cfg)

    assert (cfg / "adlists.txt").read_text() == "https://a.example/l.txt\n"


def test_check_exits_zero_when_every_setting_is_already_recorded(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text("https://a.example/l.txt\n", encoding="utf-8")
    state = _only_default_group(lists=[_adlist("https://a.example/l.txt", [0])])
    assert _check(tmp_path, state, cfg) == h.OK


def test_check_exits_drift_when_a_setting_could_be_captured(tmp_path):
    # What verify.yml fails on: `just mirror` would write this into the files.
    cfg = tmp_path / "config"
    cfg.mkdir()
    state = _only_default_group(lists=[_adlist("https://a.example/l.txt", [0])])
    assert _check(tmp_path, state, cfg) == h.DRIFT


def test_check_exits_unrecordable_when_no_outstanding_setting_can_be_captured(tmp_path):
    # What verify.yml does not fail on: there is no fix to apply, and a check
    # that stays red for something unfixable is one people learn to ignore.
    cfg = tmp_path / "config"
    cfg.mkdir()
    state = _only_default_group()
    state["allow_lists"] = [{"address": "https://a.example/allow.txt",
                             "type": "allow", "groups": [0], "comment": None,
                             "enabled": True}]
    assert _check(tmp_path, state, cfg) == h.UNRECORDABLE


def test_no_verdict_shares_a_status_with_a_run_that_never_started():
    # argparse exits 2 on a usage error, so a mistyped flag once landed on the
    # value meaning "capturable drift" and verify.yml told the operator to run a
    # mirror run that would find nothing.
    with pytest.raises(SystemExit) as exit_info:
        h.main(["--no-such-flag"])
    assert exit_info.value.code not in (h.OK, h.DRIFT, h.UNRECORDABLE)


def test_check_that_cannot_read_its_state_fails_rather_than_reporting_in_sync(tmp_path):
    # The hole this separation closes: a check that crashed used to leave the
    # same empty stdout as a clean one, and verify.yml read that as healthy.
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        h.main(["--check", str(bad), "--dir", str(tmp_path)])


def test_the_helper_scripts_are_executable():
    # The mirror, adopt and verify playbooks run these straight from the repo
    # working tree, so the mode bit is behaviour, not housekeeping.
    files = pathlib.Path(h.__file__).parent
    for name in ("pihole_mirror.py", "pihole_deploy.py"):
        assert os.access(files / name, os.X_OK), f"{name} is not executable"
