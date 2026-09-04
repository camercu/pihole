"""End-to-end test: the smoke checker against a real, blocking Pi-hole.

Loads gravity with a known ad domain, then runs the deployed smoke script over
real DNS + the FTL API. Proves the health check has teeth: a blocked domain is
seen as blocked, and a domain that resolves is NOT mistaken for blocked.
"""
import pytest

pytestmark = pytest.mark.integration


def _load_gravity(pihole, tmp_path):
    """Give Pi-hole a blocklist containing ads.example and rebuild gravity."""
    pihole.sidecar.serve("block.txt", "0.0.0.0 ads.example\n")
    cfg = tmp_path / "cfg"
    cfg.mkdir()
    (cfg / "adlists.txt").write_text(pihole.sidecar.block_url + "\n",
                                     encoding="utf-8")
    r = pihole.run_deploy(cfg)
    assert r.returncode == 0, r.stderr


def test_smoke_passes_against_a_healthy_pihole(pihole, tmp_path):
    _load_gravity(pihole, tmp_path)
    r = pihole.run_smoke_in_net({
        "SMOKE_RESOLVE_DOMAIN": "example.com",
        "SMOKE_BLOCKED_DOMAIN": "ads.example",
    })
    assert r.returncode == 0, r.stdout + r.stderr
    assert "SMOKE OK" in r.stdout
    assert "[FAIL]" not in r.stdout


def test_smoke_fails_when_the_blocked_domain_is_not_blocked(pihole, tmp_path):
    _load_gravity(pihole, tmp_path)
    # example.com resolves, so demanding it be "blocked" must make the check fail.
    r = pihole.run_smoke_in_net({
        "SMOKE_RESOLVE_DOMAIN": "example.com",
        "SMOKE_BLOCKED_DOMAIN": "example.com",
    })
    assert r.returncode == 1
    assert "SMOKE FAILED" in r.stderr
