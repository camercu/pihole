"""End-to-end tests: the deploy script reconciling a real Pi-hole v6 container.

Each test gets a clean Pi-hole (managed state wiped) via the ``pihole`` fixture,
builds a config tree on disk, then runs the *actual* deployed script against the
live FTL API and asserts the resulting server state.
"""
import pytest
from conftest import UI_COMMENT

pytestmark = pytest.mark.integration


def _cfg(root, files):
    """Materialise a config tree from {relpath: contents} under root."""
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _gid(api, name):
    return next(g["id"] for g in api.groups() if g["name"] == name)


def _row(rows, key, value):
    return next((r for r in rows if r.get(key) == value), None)


def test_full_reconcile_is_applied_then_idempotent(pihole, tmp_path):
    api, side = pihole.api, pihole.sidecar
    side.serve("block.txt", "0.0.0.0 ads.example\n0.0.0.0 track.example\n")
    side.serve("allow.txt", "0.0.0.0 allowed-remote.example\n")
    cfg = _cfg(tmp_path, {
        "adlists.txt": side.block_url + "\n",
        "allow.list": "allowed.example\n(\\.|^)twimg\\.example$\n",
        "allowlist-urls.txt": side.allow_url + "\n",
        "groups/kids/block.list": "bad.example\n(\\.|^)badregex\\.example$\n",
        "groups/kids/adlists.txt": side.block_url + "\n",  # shared -> union
        "groups/kids/clients.txt": "10.0.0.5\n",
    })

    r = pihole.run_deploy(cfg)
    assert r.returncode == 0, r.stderr
    assert "CHANGED" in r.stdout
    assert "Rebuilding gravity" in r.stdout  # adlists changed -> gravity ran

    kids = _gid(api, "kids")
    assert _row(api.groups(), "name", "kids")["comment"] == "managed by ansible"

    # Shared adlist belongs to both the default group and kids.
    adlist = _row(api.lists(), "address", side.block_url)
    assert adlist is not None
    assert set(adlist["groups"]) == {0, kids}

    deny = {d["domain"]: d for d in api.domains() if d["type"] == "deny"}
    assert set(deny["bad.example"]["groups"]) == {kids}
    assert deny["bad.example"]["kind"] == "exact"
    assert deny["(\\.|^)badregex\\.example$"]["kind"] == "regex"

    allow = {d["domain"]: d for d in api.domains() if d["type"] == "allow"}
    assert "allowed.example" in allow                 # from allow.list
    assert "allowed-remote.example" in allow          # fetched from allowlist-urls
    assert "(\\.|^)twimg\\.example$" in allow
    assert set(allow["allowed.example"]["groups"]) == {0}  # network-wide

    client = _row(api.clients(), "client", "10.0.0.5")
    assert set(client["groups"]) == {0, kids}  # its group AND the default group

    # Second run with identical config must be a no-op.
    r2 = pihole.run_deploy(cfg)
    assert r2.returncode == 0, r2.stderr
    assert "no changes" in r2.stdout
    assert "CHANGED" not in r2.stdout


def test_hand_added_collision_is_reported_and_left_untouched(pihole, ui, tmp_path):
    api = pihole.api
    # Added through `ui` so it is removed afterwards. The shared fixture resets
    # only managed rows, so a hand-added one left behind outlives its test and
    # collides with whichever test creates that domain next.
    ui.domain("bad.example", "deny")
    cfg = _cfg(tmp_path, {"groups/kids/block.list": "bad.example\n"})

    r = pihole.run_deploy(cfg)

    assert r.returncode == 1  # collision surfaced, not silently swallowed
    assert "already exists as a hand-added entry" in r.stderr
    # The hand-added entry keeps its own comment; the deploy did not seize it.
    row = _row(api.domains(), "domain", "bad.example")
    assert row["comment"] == UI_COMMENT


def test_a_managed_entry_switched_off_by_hand_is_switched_back_on(pihole, tmp_path):
    # A config file listing a domain says it is blocked. Switching the row off in
    # the admin UI leaves it managed, so mirroring skips it as already recorded and
    # the drift check calls the box in sync — the block would stay off through
    # every run and every rebuild if the reconcile did not assert it.
    api = pihole.api
    # A domain no other test uses: reset_managed clears only managed rows, so a
    # hand-added one from an earlier test would collide here instead.
    domain = "switchedoff.example"
    cfg = _cfg(tmp_path, {"groups/kids/block.list": domain + "\n"})
    assert pihole.run_deploy(cfg).returncode == 0

    row = _row(api.domains(), "domain", domain)
    st, j = api._call("PUT", "/domains/deny/exact/" + domain,
                      {"comment": "managed by ansible", "enabled": False,
                       "groups": row["groups"]})
    assert st in (200, 201, 204), f"switching it off by hand: {st} {j}"
    assert _row(api.domains(), "domain", domain)["enabled"] is False

    r = pihole.run_deploy(cfg)

    assert r.returncode == 0, r.stderr
    assert "CHANGED" in r.stdout
    assert _row(api.domains(), "domain", domain)["enabled"] is True


def test_a_managed_allow_domain_switched_off_by_hand_is_switched_back_on(pihole,
                                                                        tmp_path):
    # Allowlists reconcile network-wide rather than per group, and used to take a
    # path that diffed on presence alone — so this one entry kind kept the very
    # gap the enabled assertion closed everywhere else, while the README claimed
    # ownership was total.
    api = pihole.api
    domain = "switchedoffallow.example"
    cfg = _cfg(tmp_path, {"allow.list": domain + "\n"})
    assert pihole.run_deploy(cfg).returncode == 0

    st, j = api._call("PUT", "/domains/allow/exact/" + domain,
                      {"comment": "managed by ansible", "enabled": False,
                       "groups": [0]})
    assert st in (200, 201, 204), f"switching it off by hand: {st} {j}"
    assert _row(api.domains(), "domain", domain)["enabled"] is False

    r = pihole.run_deploy(cfg)

    assert r.returncode == 0, r.stderr
    assert "CHANGED" in r.stdout
    assert _row(api.domains(), "domain", domain)["enabled"] is True


def test_converge_adds_reassigns_and_removes(pihole, tmp_path):
    api = pihole.api
    cfg = _cfg(tmp_path, {
        "groups/kids/block.list": "keep.example\ndrop.example\n",
        "groups/kids/clients.txt": "10.0.0.9\n",
    })
    r1 = pihole.run_deploy(cfg)
    assert r1.returncode == 0, r1.stderr
    kids = _gid(api, "kids")
    assert set(_row(api.clients(), "client", "10.0.0.9")["groups"]) == {0, kids}

    # Drop a denied domain; move the client from kids to teens (PUT reassign).
    (cfg / "groups/kids/block.list").write_text("keep.example\n", encoding="utf-8")
    (cfg / "groups/kids/clients.txt").unlink()
    (cfg / "groups/teens").mkdir()
    (cfg / "groups/teens/clients.txt").write_text("10.0.0.9\n", encoding="utf-8")

    r2 = pihole.run_deploy(cfg)
    assert r2.returncode == 0, r2.stderr
    assert "CHANGED" in r2.stdout

    denied = {d["domain"] for d in api.domains() if d["type"] == "deny"}
    assert "keep.example" in denied
    assert "drop.example" not in denied  # removed
    teens = _gid(api, "teens")
    assert set(_row(api.clients(), "client", "10.0.0.9")["groups"]) == {0, teens}
