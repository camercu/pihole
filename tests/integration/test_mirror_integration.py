"""End-to-end tests: mirroring hand-made changes off a real Pi-hole container.

The unit tests pin the routing rules against a hand-written state dict; these
prove the export really reads that shape out of a live FTL API, so a change to
Pi-hole's response format is caught here rather than on the user's box.

Assertions look for the entries a test created rather than for exact file
contents: a stock Pi-hole already carries an unmanaged adlist of its own, and
mirroring it is the correct behaviour, not interference.
"""
import json

import pytest

pytestmark = pytest.mark.integration

MANAGED = "managed by ansible"
UI_COMMENT = "added in the UI"


@pytest.fixture
def ui(pihole):
    """Adds entries the way a person would in the admin UI, and removes them after.

    The shared fixture only resets *managed* state, which is exactly what the
    mirror tests must not rely on — so anything added here is tracked and
    deleted, keeping one test's hand-made entries out of the next one's export.
    """
    api = pihole.api
    lists, domains, groups = [], [], []

    class UI:
        def group(self, name):
            api.post("/groups", {"name": name, "comment": UI_COMMENT,
                                 "enabled": True})
            groups.append(name)
            return next(g["id"] for g in api.groups() if g["name"] == name)

        def adlist(self, address, gids=None):
            # FTL takes the list type as a query parameter, not a body field.
            st, body = api.post("/lists?type=block",
                                {"address": [address], "comment": UI_COMMENT,
                                 "enabled": True, "groups": gids or [0]})
            assert st in (200, 201), f"adding adlist: {st} {body}"
            lists.append(address)
            return address

        def domain(self, domain, type_, gids=None):
            st, body = api.post(f"/domains/{type_}/exact",
                                {"domain": [domain], "comment": UI_COMMENT,
                                 "enabled": True, "groups": gids or [0]})
            assert st in (200, 201), f"adding {type_} domain: {st} {body}"
            domains.append({"item": domain, "type": type_, "kind": "exact"})
            return domain

    yield UI()

    if domains:
        api.post("/domains:batchDelete", domains)
    if lists:
        api.post("/lists:batchDelete", [{"item": a, "type": "block"} for a in lists])
    for name in groups:
        api._call("DELETE", "/groups/" + name)


def _export(pihole, tmp_path):
    r = pihole.run_mirror("--export")
    assert r.returncode == 0, r.stderr
    path = tmp_path / "state.json"
    path.write_text(r.stdout, encoding="utf-8")
    return json.loads(r.stdout), path


def test_export_reports_live_state_in_the_shape_the_planner_reads(pihole, ui,
                                                                  tmp_path):
    address = ui.adlist("https://hand.example/l.txt")
    state, _ = _export(pihole, tmp_path)

    assert set(state) == {"groups", "lists", "allow_lists", "domains",
                          "clients"}
    row = next(x for x in state["lists"] if x["address"] == address)
    assert row["comment"] == UI_COMMENT
    assert row["enabled"] is True
    # The planner reads an absent or empty group list as the default group, so
    # whichever of [] or [0] FTL returns has to be one of those two.
    assert set(row.get("groups", [])) in ({0}, set())


def test_hand_added_entries_land_in_the_config_files(pihole, ui, tmp_path):
    gid = ui.group("guests")
    ui.adlist("https://hand.example/l.txt")
    ui.domain("ok.example", "allow")
    ui.domain("bad.example", "deny", [gid])
    _, state = _export(pihole, tmp_path)

    cfg = tmp_path / "config"
    cfg.mkdir()
    merge = pihole.run_mirror("--merge", str(state), "--dir", str(cfg))
    assert "CHANGED" in merge.stdout, merge.stderr

    assert "https://hand.example/l.txt" in (cfg / "adlists.txt").read_text()
    assert "ok.example" in (cfg / "allow.list").read_text()
    assert (cfg / "groups/guests/block.list").read_text() == "bad.example\n"

    # A second merge of the same state finds everything recorded already.
    again = pihole.run_mirror("--merge", str(state), "--dir", str(cfg))
    assert "no changes" in again.stdout


def test_an_entry_deleted_in_the_admin_ui_leaves_the_config_file(pihole, ui,
                                                                 tmp_path):
    # The other half of capture: without it the admin UI can only ever add, and
    # a blocklist deleted there is put straight back by the next reconcile.
    address = ui.adlist("https://deleted.example/l.txt")
    _, state = _export(pihole, tmp_path)
    cfg = tmp_path / "config"
    cfg.mkdir()
    assert "CHANGED" in pihole.run_mirror("--merge", str(state),
                                           "--dir", str(cfg)).stdout
    assert address in (cfg / "adlists.txt").read_text()

    pihole.api.post("/lists:batchDelete", [{"item": address, "type": "block"}])
    _, after = _export(pihole, tmp_path)

    assert "CHANGED" in pihole.run_mirror("--merge", str(after),
                                           "--dir", str(cfg)).stdout
    assert address not in (cfg / "adlists.txt").read_text()


def test_a_managed_entry_already_recorded_is_not_written_twice(pihole, tmp_path):
    # A file listing what the box holds has to include the reconciler's own
    # entries — that is what lets a deletion be told apart from an addition —
    # so the guard against re-appending them is that a line already there counts
    # as present, not that they are left out.
    address = "https://managed.example/l.txt"
    st, body = pihole.api.post("/lists?type=block",
                               {"address": [address], "comment": MANAGED,
                                "enabled": True})
    assert st in (200, 201), f"{st} {body}"
    _, state = _export(pihole, tmp_path)

    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text(address + "\n", encoding="utf-8")
    pihole.run_mirror("--merge", str(state), "--dir", str(cfg))
    pihole.run_mirror("--merge", str(state), "--dir", str(cfg))

    assert (cfg / "adlists.txt").read_text().count(address) == 1


def test_an_adopted_entry_stops_colliding_with_the_reconciler(pihole, ui, tmp_path):
    address = ui.adlist("https://hand.example/l.txt")
    _, state = _export(pihole, tmp_path)
    cfg = tmp_path / "config"
    cfg.mkdir()
    assert "CHANGED" in pihole.run_mirror("--merge", str(state),
                                           "--dir", str(cfg)).stdout
    # Narrow the captured file to this test's own entry, leaving the stock
    # adlist Pi-hole ships unmanaged and out of the way.
    (cfg / "adlists.txt").write_text(address + "\n", encoding="utf-8")

    plan = pihole.run_mirror("--plan-adopt", str(state), "--dir", str(cfg))
    assert plan.returncode == 0, plan.stderr
    assert address in plan.stdout
    pairs = tmp_path / "adoptable.json"
    pairs.write_text(plan.stdout, encoding="utf-8")

    adopt = pihole.run_mirror("--adopt", str(pairs))
    assert "CHANGED" in adopt.stdout, adopt.stderr

    row = next(x for x in pihole.api.lists() if x["address"] == address)
    assert row["comment"] == MANAGED
    assert row["enabled"] is True
    assert set(row["groups"]) == {0}

    # The whole point: reconciling from the captured file is now a clean no-op
    # instead of the collision the hand-added comment used to cause.
    r = pihole.run_sync(cfg)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "no changes" in r.stdout


def test_an_unrecorded_entry_is_not_handed_over(pihole, ui, tmp_path):
    # Adopting an entry no config file lists would let the next reconcile
    # delete it, turning a capture tool into a way to lose settings.
    address = ui.adlist("https://unrecorded.example/l.txt")
    _, state = _export(pihole, tmp_path)
    empty = tmp_path / "empty"
    empty.mkdir()

    plan = pihole.run_mirror("--plan-adopt", str(state), "--dir", str(empty))
    assert plan.returncode == 0, plan.stderr
    assert address not in plan.stdout

    row = next(x for x in pihole.api.lists() if x["address"] == address)
    assert row["comment"] == UI_COMMENT


def test_an_allow_adlist_is_reported_rather_than_passed_over(pihole, tmp_path):
    # Pi-hole keeps allow adlists in the same table under a different type. The
    # config has no file for them, so the drift check must say so instead of
    # calling a box that carries one "in sync".
    address = "https://allowlist.example/l.txt"
    st, body = pihole.api.post("/lists?type=allow",
                               {"address": [address], "comment": UI_COMMENT,
                                "enabled": True})
    assert st in (200, 201), f"{st} {body}"
    try:
        state, path = _export(pihole, tmp_path)
        assert any(x["address"] == address for x in state["allow_lists"])

        cfg = tmp_path / "config"
        cfg.mkdir()
        check = pihole.run_mirror("--check", str(path), "--dir", str(cfg))
        assert address in check.stderr
        assert "allow adlist" in check.stderr
    finally:
        pihole.api.post("/lists:batchDelete", [{"item": address, "type": "allow"}])
