"""Unit tests for the pure decision logic in pihole_harvest.py.

Harvest is the inverse of the reconciler: it reads live Pi-hole state and works
out which config file each hand-added entry belongs in. The invariant these
tests pin down is *faithfulness* — an entry is only routed into a config file
when re-running the reconciler from that file would reproduce the entry's
current group set exactly. Anything else is reported, never silently reshaped.
"""
import json
import os
import pathlib

import pihole_harvest as h
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
def test_managed_entries_are_not_harvested():
    # Already in the config files; harvesting them would duplicate lines.
    state = _state(lists=[_adlist("https://a.example/list.txt", [0], MANAGED)])
    plan = h.plan_harvest(state)
    assert plan.files == {}
    assert plan.unroutable == []


def test_hand_added_default_group_adlist_goes_to_top_level_adlists():
    state = _state(lists=[_adlist("https://a.example/list.txt", [0])])
    assert h.plan_harvest(state).files == {
        "adlists.txt": ["https://a.example/list.txt"]}


def test_adlist_with_no_groups_is_treated_as_default_group():
    # FTL reports a default-only entry as either [] or [0].
    state = _state(lists=[_adlist("https://a.example/list.txt", [])])
    assert h.plan_harvest(state).files == {
        "adlists.txt": ["https://a.example/list.txt"]}


def test_group_scoped_adlist_goes_to_that_groups_file():
    state = _state(lists=[_adlist("https://k.example/list.txt", [2])])
    assert h.plan_harvest(state).files == {
        "groups/kids/adlists.txt": ["https://k.example/list.txt"]}


def test_adlist_in_default_and_a_group_is_written_to_both_files():
    # assemble_desired unions the same URL from both files onto one row, so
    # writing both reproduces the live group set exactly.
    state = _state(lists=[_adlist("https://s.example/list.txt", [0, 2])])
    assert h.plan_harvest(state).files == {
        "adlists.txt": ["https://s.example/list.txt"],
        "groups/kids/adlists.txt": ["https://s.example/list.txt"],
    }


# ── allow domains: the config expresses these network-wide only ─────────────
def test_hand_added_allow_domain_goes_to_allow_list():
    state = _state(domains=[_domain("ok.example", "allow", "exact", [0])])
    assert h.plan_harvest(state).files == {"allow.list": ["ok.example"]}


def test_allow_regex_goes_to_allow_list_verbatim():
    pattern = r"(\.|^)twimg\.example$"
    state = _state(domains=[_domain(pattern, "allow", "regex", [0])])
    assert h.plan_harvest(state).files == {"allow.list": [pattern]}


def test_group_scoped_allow_domain_is_reported_not_narrowed():
    state = _state(domains=[_domain("ok.example", "allow", "exact", [2])])
    plan = h.plan_harvest(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == ["allow/exact ok.example"]
    assert "network-wide" in plan.unroutable[0][1]


# ── deny domains: the config expresses these per group only ─────────────────
def test_group_scoped_deny_domain_goes_to_that_groups_block_list():
    state = _state(domains=[_domain("bad.example", "deny", "exact", [2])])
    assert h.plan_harvest(state).files == {
        "groups/kids/block.list": ["bad.example"]}


def test_deny_domain_in_default_group_is_reported_not_silently_narrowed():
    # Routing this to one group's block.list would stop blocking it for
    # everyone else — a behaviour change the user never asked for.
    state = _state(domains=[_domain("bad.example", "deny", "exact", [0, 2])])
    plan = h.plan_harvest(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == ["deny/exact bad.example"]


def test_deny_domain_blocked_network_wide_only_says_so():
    # No group to name: the config simply has no network-wide blocklist, and
    # the reason has to say that rather than trail off.
    state = _state(domains=[_domain("bad.example", "deny", "exact", [0])])
    plan = h.plan_harvest(state)
    assert plan.files == {}
    assert "no network-wide blocklist" in plan.unroutable[0][1]


def test_deny_domain_spanning_two_groups_is_written_to_both():
    pattern = r"(\.|^)bad\.example$"
    state = _state(domains=[_domain(pattern, "deny", "regex", [2, 3])])
    assert h.plan_harvest(state).files == {
        "groups/kids/block.list": [pattern],
        "groups/guests/block.list": [pattern],
    }


# ── clients: the config always places a device in its group AND default ─────
def test_client_in_group_and_default_goes_to_that_groups_clients_file():
    state = _state(clients=[_client("10.0.0.5", [0, 2])])
    assert h.plan_harvest(state).files == {
        "groups/kids/clients.txt": ["10.0.0.5"]}


def test_client_without_the_default_group_is_reported_not_widened():
    # Harvesting this would hand the device the default group's adlists on the
    # next reconcile — more blocking than the user configured.
    state = _state(clients=[_client("10.0.0.5", [2])])
    plan = h.plan_harvest(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == ["client 10.0.0.5"]


def test_client_in_the_default_group_only_is_reported():
    # The config has no top-level clients file: group membership is the only
    # thing it can say about a device.
    state = _state(clients=[_client("10.0.0.5", [0])])
    plan = h.plan_harvest(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == ["client 10.0.0.5"]


# ── things the config cannot say ────────────────────────────────────────────
def test_disabled_entry_is_reported_not_harvested_as_enabled():
    # The reconciler adds everything enabled; harvesting a UI-disabled entry
    # would switch it back on at the next run.
    state = _state(lists=[_adlist("https://a.example/list.txt", [0], enabled=False)])
    plan = h.plan_harvest(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == ["adlist https://a.example/list.txt"]
    assert "disabled" in plan.unroutable[0][1]


def test_entry_in_an_unknown_group_id_is_reported():
    state = _state(lists=[_adlist("https://a.example/list.txt", [99])])
    plan = h.plan_harvest(state)
    assert plan.files == {}
    assert "99" in plan.unroutable[0][1]


def test_domain_of_a_kind_the_config_has_no_rule_for_is_reported():
    # Routing dispatched by falling through to the client rule, so a domain type
    # this router does not know — one a later FTL adds — was written into a
    # group's clients.txt as if it were a device.
    state = _state(domains=[_domain("x.example", "sinkhole", "exact", [0, 2])])
    plan = h.plan_harvest(state)
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
    assert h.plan_harvest(_state()).group_dirs == ["guests"]


def test_group_dir_is_listed_for_any_group_an_entry_routes_into():
    state = _state(domains=[_domain("bad.example", "deny", "exact", [2])])
    plan = h.plan_harvest(state)
    assert plan.group_dirs == ["guests", "kids"]


def test_default_group_never_becomes_a_directory():
    state = _state(groups=[{"id": 0, "name": "Default", "comment": None}])
    assert h.plan_harvest(state).group_dirs == []


# ── determinism ─────────────────────────────────────────────────────────────
def test_lines_within_a_file_are_sorted_and_deduped():
    state = _state(lists=[_adlist("https://b.example/l.txt", [0]),
                          _adlist("https://a.example/l.txt", [0]),
                          _adlist("https://b.example/l.txt", [0])])
    assert h.plan_harvest(state).files["adlists.txt"] == [
        "https://a.example/l.txt", "https://b.example/l.txt"]


# ── merging harvested lines into an existing config file ────────────────────
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


# ── deciding what a harvest would change, before changing it ────────────────
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
    plan = h.plan_harvest(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == ["deny/regex doubleclick"]
    assert "regex" in plan.unroutable[0][1]


def test_allow_regex_that_reads_as_a_plain_domain_is_reported():
    state = _state(domains=[_domain("doubleclick", "allow", "regex", [0])])
    assert h.plan_harvest(state).files == {}


def test_regex_domain_with_metacharacters_still_routes():
    pattern = r"(\.|^)ads\.example$"
    state = _state(domains=[_domain(pattern, "deny", "regex", [2])])
    assert h.plan_harvest(state).files == {"groups/kids/block.list": [pattern]}


def test_exact_domain_that_reads_as_a_regex_is_reported():
    # The mirror case: the reconciler would push this back as a regex.
    state = _state(domains=[_domain("ads*.example", "deny", "exact", [2])])
    assert h.plan_harvest(state).files == {}


def test_entry_with_a_comment_character_is_reported():
    # merge_lines judges presence after stripping '#', so an entry containing
    # one would be appended again by every harvest and never read back whole.
    url = "https://a.example/l.txt#frag"
    state = _state(lists=[_adlist(url, [0])])
    plan = h.plan_harvest(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == [f"adlist {url}"]


def test_entry_with_surrounding_whitespace_is_reported():
    state = _state(lists=[_adlist(" https://a.example/l.txt ", [0])])
    assert h.plan_harvest(state).files == {}


# ── group names that cannot be directories ──────────────────────────────────
def test_group_named_with_a_path_traversal_is_reported_not_written():
    groups = GROUPS + [{"id": 4, "name": "../../evil", "comment": None}]
    state = _state(groups=groups,
                   domains=[_domain("x.example", "deny", "exact", [4])])
    plan = h.plan_harvest(state)
    assert plan.files == {}
    assert plan.group_dirs == ["guests"]
    assert any("../../evil" in item for item, _ in plan.unroutable)


def test_group_named_with_a_slash_is_reported():
    groups = GROUPS + [{"id": 4, "name": "a/b", "comment": None}]
    state = _state(groups=groups,
                   domains=[_domain("x.example", "deny", "exact", [4])])
    plan = h.plan_harvest(state)
    assert plan.files == {}
    assert "a/b" not in plan.group_dirs


def test_group_named_dot_is_reported():
    groups = GROUPS + [{"id": 4, "name": ".", "comment": None}]
    plan = h.plan_harvest(_state(groups=groups))
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
    plan = h.plan_harvest(state)
    assert plan.files == {}
    assert [item for item, _ in plan.unroutable] == [
        "allow adlist https://a.example/allow.txt"]


def test_plan_records_the_row_it_decided_against():
    # Adoption happens later, against a second look at live state; without the
    # record the plan was made from there is nothing to re-check.
    state = _state(lists=[_adlist("https://a.example/l.txt", [0, 2])])
    assert h.plan_harvest(state).routed == [
        (_entry("adlist", "https://a.example/l.txt", [0, 2]),
         ["adlists.txt", "groups/kids/adlists.txt"])]


# ── adoption re-checks live state before changing anything ──────────────────
def _live(**kw):
    return _state(**kw)


def test_entry_still_matching_the_plan_is_adopted():
    planned = _entry("adlist", "https://a.example/l.txt", [0])
    state = _live(lists=[_adlist("https://a.example/l.txt", [0])])
    assert h.adoptable_now([planned], state) == [planned]


def test_entry_regrouped_since_the_plan_is_left_alone():
    # Someone moved it in the UI between harvest and adopt: the config files
    # record the old group set, so handing it over would narrow it silently.
    planned = _entry("adlist", "https://a.example/l.txt", [0])
    state = _live(lists=[_adlist("https://a.example/l.txt", [0, 2])])
    assert h.adoptable_now([planned], state) == []


def test_entry_disabled_since_the_plan_is_left_alone():
    # Someone switched it off in the UI between harvest and adopt. Harvest
    # refuses to route a disabled row at all, so adopting one would stamp it as
    # the reconciler's while it is off — and the reconciler sets enabled only on
    # add, so nothing would ever switch it back on.
    at_harvest = _live(lists=[_adlist("https://a.example/l.txt", [0])])
    planned = h.plan_adopt(h.plan_harvest(at_harvest).routed,
                           {"adlists.txt": {"https://a.example/l.txt"}})
    switched_off = _live(lists=[_adlist("https://a.example/l.txt", [0],
                                        enabled=False)])
    assert h.adoptable_now(planned, switched_off) == []


def test_entry_already_owned_by_the_reconciler_is_skipped():
    planned = _entry("adlist", "https://a.example/l.txt", [0])
    state = _live(lists=[_adlist("https://a.example/l.txt", [0], MANAGED)])
    assert h.adoptable_now([planned], state) == []


def test_entry_gone_from_the_box_is_skipped():
    planned = _entry("adlist", "https://a.example/l.txt", [0])
    assert h.adoptable_now([planned], _live()) == []


def test_a_plan_survives_the_json_round_trip_between_deciding_and_doing():
    # --plan-adopt writes the decision as JSON on the controller and --adopt
    # reads it back on the Pi. Group ids arrive as a list; a record compared by
    # value would match nothing if it stayed one, and adoption would silently
    # hand over nothing while reporting success.
    state = _live(lists=[_adlist("https://a.example/l.txt", [0, 2])])
    recorded = {"adlists.txt": {"https://a.example/l.txt"},
                "groups/kids/adlists.txt": {"https://a.example/l.txt"}}
    planned = h.plan_adopt(h.plan_harvest(state).routed, recorded)

    carried = h.entries_from_json(json.loads(json.dumps(h.entries_to_json(planned))))

    assert h.adoptable_now(carried, state) == planned
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


def test_check_exits_zero_when_every_setting_is_already_recorded(tmp_path):
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text("https://a.example/l.txt\n", encoding="utf-8")
    state = _only_default_group(lists=[_adlist("https://a.example/l.txt", [0])])
    assert _check(tmp_path, state, cfg) == h.OK


def test_check_exits_drift_when_a_setting_could_be_captured(tmp_path):
    # What verify.yml fails on: `just harvest` would write this into the files.
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


def test_check_that_cannot_read_its_state_fails_rather_than_reporting_in_sync(tmp_path):
    # The hole this separation closes: a check that crashed used to leave the
    # same empty stdout as a clean one, and verify.yml read that as healthy.
    bad = tmp_path / "bad.json"
    bad.write_text("not json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        h.main(["--check", str(bad), "--dir", str(tmp_path)])


def test_the_helper_scripts_are_executable():
    # The harvest, adopt and verify playbooks run these straight from the repo
    # working tree, so the mode bit is behaviour, not housekeeping.
    files = pathlib.Path(h.__file__).parent
    for name in ("pihole_harvest.py", "pihole_sync_lists.py"):
        assert os.access(files / name, os.X_OK), f"{name} is not executable"
