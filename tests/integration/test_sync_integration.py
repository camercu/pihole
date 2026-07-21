"""End-to-end tests: the sync script reconciling a real Pi-hole v6 container.

Each test gets a clean Pi-hole (managed state wiped) via the ``pihole`` fixture,
builds a config tree on disk, then runs the *actual* deployed script against the
live FTL API and asserts the resulting server state.
"""
import pytest

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

    r = pihole.run_sync(cfg)
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
    r2 = pihole.run_sync(cfg)
    assert r2.returncode == 0, r2.stderr
    assert "no changes" in r2.stdout
    assert "CHANGED" not in r2.stdout


def test_hand_added_collision_is_reported_and_left_untouched(pihole, tmp_path):
    api = pihole.api
    # A domain someone added by hand (comment != MANAGED) that config also wants.
    st, j = api.post("/domains/deny/exact",
                     {"domain": ["bad.example"], "comment": "added by hand",
                      "enabled": True})
    assert st in (200, 201), j
    cfg = _cfg(tmp_path, {"groups/kids/block.list": "bad.example\n"})

    r = pihole.run_sync(cfg)

    assert r.returncode == 1  # collision surfaced, not silently swallowed
    assert "already exists as a hand-added entry" in r.stderr
    # The hand-added entry keeps its own comment; sync did not seize it.
    row = _row(api.domains(), "domain", "bad.example")
    assert row["comment"] == "added by hand"


def test_converge_adds_reassigns_and_removes(pihole, tmp_path):
    api = pihole.api
    cfg = _cfg(tmp_path, {
        "groups/kids/block.list": "keep.example\ndrop.example\n",
        "groups/kids/clients.txt": "10.0.0.9\n",
    })
    r1 = pihole.run_sync(cfg)
    assert r1.returncode == 0, r1.stderr
    kids = _gid(api, "kids")
    assert set(_row(api.clients(), "client", "10.0.0.9")["groups"]) == {0, kids}

    # Drop a denied domain; move the client from kids to teens (PUT reassign).
    (cfg / "groups/kids/block.list").write_text("keep.example\n", encoding="utf-8")
    (cfg / "groups/kids/clients.txt").unlink()
    (cfg / "groups/teens").mkdir()
    (cfg / "groups/teens/clients.txt").write_text("10.0.0.9\n", encoding="utf-8")

    r2 = pihole.run_sync(cfg)
    assert r2.returncode == 0, r2.stderr
    assert "CHANGED" in r2.stdout

    denied = {d["domain"] for d in api.domains() if d["type"] == "deny"}
    assert "keep.example" in denied
    assert "drop.example" not in denied  # removed
    teens = _gid(api, "teens")
    assert set(_row(api.clients(), "client", "10.0.0.9")["groups"]) == {0, teens}
