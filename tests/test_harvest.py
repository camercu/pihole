"""Unit tests for the pure decision logic in pihole_harvest.py.

Harvest is the inverse of the reconciler: it reads live Pi-hole state and works
out which config file each hand-added entry belongs in. The invariant these
tests pin down is *faithfulness* — an entry is only routed into a config file
when re-running the reconciler from that file would reproduce the entry's
current group set exactly. Anything else is reported, never silently reshaped.
"""
import pihole_harvest as h

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


def test_deny_domain_spanning_two_groups_is_written_to_both():
    state = _state(domains=[_domain("bad.example", "deny", "regex", [2, 3])])
    assert h.plan_harvest(state).files == {
        "groups/kids/block.list": ["bad.example"],
        "groups/guests/block.list": ["bad.example"],
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
