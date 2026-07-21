"""Integration harness: run the helper scripts against a real Pi-hole v6 container.

These tests exercise the *deployed artifact* end-to-end — the sync script talks
to a genuine FTL API, so they catch API-contract drift that the pure unit tests
cannot. They are opt-in: set ``PIHOLE_IT=1`` to run them (CI does). Without it
they skip, keeping ``pytest`` fast for the red-green loop and pre-commit.

Container runtime is auto-detected (docker, then podman). A sidecar HTTP server
serves adlist/allowlist fixtures so gravity and remote-allowlist fetches stay
hermetic and fast — no reliance on the public internet.
"""
import json
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

import pytest

# Pinned for reproducibility; bump deliberately. Version tags are immutable.
PIHOLE_IMAGE = "docker.io/pihole/pihole:2026.07.2"
FILES_IMAGE = "docker.io/library/python:3.12-alpine"
PASSWORD = "test-it-pw"

NET = "pihole-it-net"
PIHOLE_CT = "pihole-it"
FILES_CT = "pihole-it-files"
PIHOLE_PORT = 8081  # host -> pihole :80
FILES_PORT = 8000  # host -> fileserver :8000 (also reachable in-net as FILES_CT)

MANAGED = "managed by ansible"
_ROOT = Path(__file__).resolve().parents[2]
SYNC_SCRIPT = _ROOT / "ansible/roles/pihole/files/pihole_sync_lists.py"
BACKUP_SCRIPT = _ROOT / "ansible/roles/backup/files/pihole_backup.py"
SMOKE_SCRIPT = _ROOT / "ansible/roles/verify/files/pihole_smoke.py"


def _detect_runtime():
    """First container runtime whose daemon actually answers, or None."""
    for name in ("docker", "podman"):
        exe = shutil.which(name)
        if not exe:
            continue
        try:
            if subprocess.run([exe, "info"], capture_output=True,
                              timeout=15).returncode == 0:
                return exe
        except subprocess.TimeoutExpired:
            continue
    return None


def _rt(*args, check=True):
    return subprocess.run([RUNTIME, *args], capture_output=True, text=True,
                          check=check)


RUNTIME = _detect_runtime()


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "integration: end-to-end test needing a container runtime")


def _require_runtime():
    """Skip unless opted in; fail loudly if opted in but no runtime (no false green)."""
    if os.environ.get("PIHOLE_IT") != "1":
        pytest.skip("integration tests are opt-in; set PIHOLE_IT=1 to run")
    if RUNTIME is None:
        pytest.fail("PIHOLE_IT=1 but no working docker/podman runtime found")


class Api:
    """Minimal FTL API client for arranging fixtures and asserting state."""

    def __init__(self, base, password):
        self.base = base
        self.sid = None
        self.sid = self._login(password)

    def _call(self, method, path, body=None):
        url = self.base + path
        if self.sid:
            url += ("&" if "?" in url else "?") + "sid=" + self.sid
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={"Content-Type": "application/json",
                     "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if raw else {})
        except urllib.error.HTTPError as e:
            raw = e.read()
            try:
                return e.code, json.loads(raw)
            except json.JSONDecodeError:
                return e.code, raw.decode("utf-8", "replace")

    def _login(self, password):
        st, j = self._call("POST", "/auth", {"password": password})
        assert st == 200, f"auth failed: {st} {j}"
        return j["session"]["sid"]

    def logout(self):
        """Release this client's session seat (FTL's pool is small)."""
        if self.sid:
            self._call("DELETE", "/auth")
            self.sid = None

    def get(self, path):
        st, j = self._call("GET", path)
        assert st == 200, f"GET {path}: {st} {j}"
        return j

    def post(self, path, body):
        return self._call("POST", path, body)

    def groups(self):
        return self.get("/groups")["groups"]

    def lists(self):
        return self.get("/lists?type=block")["lists"]

    def domains(self):
        return self.get("/domains")["domains"]

    def clients(self):
        return self.get("/clients")["clients"]

    def wait_writable(self, timeout=30):
        """Block until FTL accepts a write again.

        Gravity swaps the config database asynchronously; for a short window
        afterwards writes fail with "readonly database". A create/delete of a
        throwaway group probes the very table the tests mutate.
        """
        deadline = time.time() + timeout
        probe = "_it_writable_probe"
        while True:
            st, j = self._call("POST", "/groups",
                               {"name": probe, "comment": MANAGED, "enabled": True})
            if st in (200, 201):
                self._call("DELETE", "/groups/" + probe)
                return
            if "readonly" not in json.dumps(j).lower() or time.time() > deadline:
                assert st in (200, 201), f"DB never became writable: {st} {j}"
            time.sleep(0.5)

    def reset_managed(self):
        """Delete every managed entry so each test starts from a clean slate.

        Cheap (API calls only), so tests get isolation without paying to restart
        the container. Entries are removed before groups (referential order).
        """
        doms = [{"item": d["domain"], "type": d["type"], "kind": d["kind"]}
                for d in self.domains() if d.get("comment") == MANAGED]
        if doms:
            self._call("POST", "/domains:batchDelete", doms)
        lists_ = [{"item": lst["address"], "type": "block"}
                  for lst in self.lists() if lst.get("comment") == MANAGED]
        if lists_:
            self._call("POST", "/lists:batchDelete", lists_)
        clis = [{"item": c["client"]} for c in self.clients()
                if c.get("comment") == MANAGED]
        if clis:
            self._call("POST", "/clients:batchDelete", clis)
        for g in self.groups():
            if g.get("comment") == MANAGED:
                self._call("DELETE", "/groups/" + urllib.parse.quote(g["name"]))


def _wait_api(base, timeout=90):
    """Poll until the FTL API authenticates, or fail."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            req = urllib.request.Request(
                base + "/auth", data=json.dumps({"password": PASSWORD}).encode(),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=5) as r:
                if r.status == 200:
                    return
        except (urllib.error.URLError, OSError) as e:
            last = e
        time.sleep(1)
    raise RuntimeError(f"Pi-hole API never became ready: {last}")


class Sidecar:
    """The in-network HTTP server; hosts adlist/allowlist fixtures.

    ``block_url`` is resolvable by gravity (inside the container network);
    ``allow_url`` is published to the host so the sync script (running here)
    can fetch it too.
    """

    def __init__(self):
        self.block_url = f"http://{FILES_CT}:{FILES_PORT}/block.txt"
        self.allow_url = f"http://localhost:{FILES_PORT}/allow.txt"

    def serve(self, name, text):
        """Publish a fixture file into the sidecar's webroot via stdin."""
        subprocess.run(
            [RUNTIME, "exec", "-i", FILES_CT, "sh", "-c", f"cat > /srv/{name}"],
            input=text, text=True, check=True, capture_output=True)


@pytest.fixture(scope="session")
def _containers():
    """Start Pi-hole + sidecar once per session; tear down after."""
    _require_runtime()
    # Clean any leftovers from an interrupted run.
    _rt("rm", "-f", PIHOLE_CT, FILES_CT, check=False)
    _rt("network", "rm", NET, check=False)
    _rt("network", "create", NET, check=False)
    _rt("run", "-d", "--name", FILES_CT, "--network", NET,
        "-p", f"{FILES_PORT}:{FILES_PORT}", "-w", "/srv", FILES_IMAGE,
        "sh", "-c", f"mkdir -p /srv && python -m http.server {FILES_PORT}")
    _rt("run", "-d", "--name", PIHOLE_CT, "--network", NET,
        "-e", "TZ=UTC", "-e", f"FTLCONF_webserver_api_password={PASSWORD}",
        "-e", "FTLCONF_dns_upstreams=1.1.1.1",
        "-p", f"{PIHOLE_PORT}:80", PIHOLE_IMAGE)
    base = f"http://localhost:{PIHOLE_PORT}/api"
    try:
        _wait_api(base)
        yield base
    finally:
        logs = _rt("logs", PIHOLE_CT, check=False).stdout
        _rt("rm", "-f", PIHOLE_CT, FILES_CT, check=False)
        _rt("network", "rm", NET, check=False)
        if os.environ.get("PIHOLE_IT_KEEP_LOGS"):
            print(logs)


@pytest.fixture
def pihole(_containers):
    """Per-test clean Pi-hole: managed state wiped, fresh Api + Sidecar."""
    api = Api(_containers, PASSWORD)
    api.wait_writable()  # absorb any gravity DB-swap left by a prior test
    api.reset_managed()
    yield SimpleEnv(base=_containers, api=api, sidecar=Sidecar())
    api.logout()  # don't leak the session seat between tests


class SimpleEnv:
    def __init__(self, base, api, sidecar):
        self.base = base
        self.api = api
        self.sidecar = sidecar

    def run_sync(self, config_dir):
        """Run the real sync script as a subprocess against the container."""
        env = {**os.environ,
               "PIHOLE_API": self.base,
               "PIHOLE_PASSWORD": PASSWORD,
               "PIHOLE_DIR": str(config_dir)}
        return subprocess.run(
            ["python", str(SYNC_SCRIPT)], env=env, text=True,
            capture_output=True)

    def run_backup(self, restic_env):
        """Run the real backup script; restic_env carries the RESTIC_* settings."""
        env = {**os.environ,
               "PIHOLE_API": self.base,
               "PIHOLE_PASSWORD": PASSWORD,
               **restic_env}
        return subprocess.run(
            ["python", str(BACKUP_SCRIPT)], env=env, text=True,
            capture_output=True)

    def run_smoke_in_net(self, extra_env=None):
        """Run the smoke script *inside* the container network.

        DNS is queried over UDP, which host->container port forwarding handles
        unreliably on some runtimes; running from the sidecar (same network as
        Pi-hole) keeps the check reliable everywhere. Defaults point at the
        Pi-hole container by name; callers override the probe domains.
        """
        subprocess.run([RUNTIME, "cp", str(SMOKE_SCRIPT),
                        f"{FILES_CT}:/tmp/pihole_smoke.py"],
                       check=True, capture_output=True)
        env = {"PIHOLE_API": f"http://{PIHOLE_CT}/api",
               "PIHOLE_PASSWORD": PASSWORD,
               "SMOKE_DNS_HOST": PIHOLE_CT,
               "SMOKE_DNS_PORT": "53",
               **(extra_env or {})}
        eflags = [x for k, v in env.items() for x in ("-e", f"{k}={v}")]
        return subprocess.run(
            [RUNTIME, "exec", *eflags, FILES_CT, "python3",
             "/tmp/pihole_smoke.py"], text=True, capture_output=True)
