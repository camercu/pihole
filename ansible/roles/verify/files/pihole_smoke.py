#!/usr/bin/env python3
"""Post-deploy smoke test: prove the box is actually resolving and blocking.

Runs on (or against) the Pi-hole host and checks the things a green Ansible run
does NOT prove — that DNS really answers, that gravity is loaded and blocking is
on, that a known ad domain is actually sinkholed, and (optionally) that unbound
answers directly. Prints one PASS/FAIL line per check and exits non-zero if any
check fails, so it drops straight into `verify.yml` or a shell.

Environment:
  PIHOLE_API           API base (default http://localhost/api)
  PIHOLE_PASSWORD      admin/API password ('' => no auth). A wrong password or
                       an unreachable API is reported as a FAIL line, not a
                       crash — the run still prints every check and exits 1.
  SMOKE_DNS_HOST       resolver to query   (default 127.0.0.1)
  SMOKE_DNS_PORT       resolver port       (default 53)
  SMOKE_RESOLVE_DOMAIN domain that must resolve      (default example.com)
  SMOKE_BLOCKED_DOMAIN domain that must be blocked   (default doubleclick.net)
  SMOKE_UNBOUND_PORT   if set, also require unbound to answer on this port
"""
import json
import os
import socket
import struct
import sys
import urllib.request


# ── pure DNS wire helpers (unit-tested) ─────────────────────────────────────
def build_query(name, qid=0x1234):
    """A minimal DNS query packet for the A record of `name` (recursion desired)."""
    parts = name.split(".")
    if any(not part for part in parts):
        # An empty label ("a..b", trailing dot) would encode a zero-length octet
        # mid-name, silently truncating the query. Reject rather than mis-encode.
        raise ValueError(f"invalid domain {name!r}: empty label")
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    labels = b"".join(bytes([len(x)]) + x.encode() for x in parts) + b"\x00"
    return header + labels + struct.pack(">HH", 1, 1)  # QTYPE A, QCLASS IN


def _skip_name(msg, off):
    """Advance past a (possibly compressed) DNS name, returning the new offset."""
    while True:
        length = msg[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:  # compression pointer ends the name
            return off + 2
        off += 1 + length


def parse_answers(resp):
    """The IPv4 addresses in a DNS response's answer section."""
    _, _, qd, an, _, _ = struct.unpack(">HHHHHH", resp[:12])
    off = 12
    for _ in range(qd):  # skip the echoed question(s)
        off = _skip_name(resp, off) + 4
    addrs = []
    for _ in range(an):
        off = _skip_name(resp, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", resp[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:  # an A record
            addrs.append(".".join(str(b) for b in resp[off:off + 4]))
        off += rdlen
    return addrs


def parse_response(resp):
    """Addresses in a DNS response, or None if the packet can't be parsed.

    None means "no usable answer" (garbled/truncated datagram) and is kept
    distinct from [] ("a valid response with an empty answer section"), because
    only the latter is a legitimate NXDOMAIN-style block.
    """
    try:
        return parse_answers(resp)
    except (struct.error, IndexError):
        return None


def is_blocked(addrs):
    """A name is blocked when it resolves to nothing or only to 0.0.0.0."""
    return all(a == "0.0.0.0" for a in addrs)


def classify_resolve(addrs):
    """A domain resolves only when the resolver returned a real (non-sinkhole) A."""
    return bool(addrs) and not is_blocked(addrs)


def classify_blocked(addrs):
    """A domain is blocked only when the resolver actually answered (not None)
    and that answer is a sinkhole — 0.0.0.0 or an empty NXDOMAIN answer.

    A None (timeout/socket error) is NOT a block: a dead resolver must never
    read as "blocking works"."""
    return addrs is not None and is_blocked(addrs)


# ── I/O shell ───────────────────────────────────────────────────────────────
API = os.environ.get("PIHOLE_API", "http://localhost/api")
PW = os.environ.get("PIHOLE_PASSWORD", "")


def dns_query(server, port, name, timeout=5):
    """Resolve `name`'s A records via one UDP query.

    Returns the list of A addresses (possibly empty for an NXDOMAIN answer),
    or None if the resolver never gave a usable response (timeout, socket
    error, unparseable packet). Callers must treat None as "unknown", not
    "blocked" — see classify_blocked.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_query(name), (server, int(port)))
        resp = sock.recvfrom(4096)[0]
    except OSError:
        return None
    finally:
        sock.close()
    return parse_response(resp)


def _api(method, path, sid=None, body=None):
    """Call the FTL API. Returns (status, json), or (None, {}) if the endpoint
    is unreachable or answers with a non-2xx/garbled body.

    Failing soft (rather than raising) is deliberate: the smoke test's job is to
    turn a broken deploy into a readable FAIL line, so an API that is down or
    rejecting our credentials must degrade to a failed check, not a traceback."""
    url = API + path
    if sid:
        url += ("&" if "?" in url else "?") + "sid=" + sid
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except (OSError, ValueError):  # URLError/HTTPError (down, 401) or bad JSON
        return None, {}


def login():
    """API session id, or None if auth isn't possible (no password set, API
    down, or wrong password). None means "unauthenticated"; the checks below
    then fail loudly against a real box rather than crashing here.

    Contract: SOFT — never raises. A health check exists to turn every failure
    (incl. bad auth) into a readable FAIL line, so it degrades where sync's
    login() die()s and backup's login() raises. The three are intentionally
    not shared: the divergent error policy is the point."""
    if not PW:
        return None
    _, j = _api("POST", "/auth", body={"password": PW})
    try:
        return j["session"]["sid"]
    except (KeyError, TypeError):
        return None


def logout(sid):
    """Release the API session seat (see pihole_sync_lists.logout)."""
    if sid:
        _api("DELETE", "/auth", sid)


def main():
    sid = login()
    dns_host = os.environ.get("SMOKE_DNS_HOST", "127.0.0.1")
    dns_port = os.environ.get("SMOKE_DNS_PORT", "53")
    resolve_domain = os.environ.get("SMOKE_RESOLVE_DOMAIN", "example.com")
    blocked_domain = os.environ.get("SMOKE_BLOCKED_DOMAIN", "doubleclick.net")
    unbound_port = os.environ.get("SMOKE_UNBOUND_PORT")

    checks = []  # (ok, label)

    if PW and sid is None:
        # A password was configured but we hold no session: API unreachable or
        # the password is wrong. Name it so the operator isn't left guessing why
        # every API check "got None".
        checks.append((False, "API login (failed — API unreachable or wrong password)"))

    _, blk = _api("GET", "/dns/blocking", sid)
    checks.append((blk.get("blocking") == "enabled",
                   f"blocking enabled (got {blk.get('blocking')!r})"))

    _, summary = _api("GET", "/stats/summary", sid)
    count = summary.get("gravity", {}).get("domains_being_blocked", 0)
    checks.append((count > 0, f"gravity populated ({count} domains)"))
    logout(sid)  # remaining checks are DNS-only; free the seat now

    good = dns_query(dns_host, dns_port, resolve_domain)
    checks.append((classify_resolve(good),
                   f"{resolve_domain} resolves ({good or 'no answer'})"))

    bad = dns_query(dns_host, dns_port, blocked_domain)
    checks.append((classify_blocked(bad),
                   f"{blocked_domain} blocked ({bad or 'no answer'})"))

    if unbound_port:
        via_unbound = dns_query(dns_host, unbound_port, resolve_domain)
        checks.append((classify_resolve(via_unbound),
                       f"unbound answers on :{unbound_port} ({via_unbound or 'no answer'})"))

    for ok, label in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not all(ok for ok, _ in checks):
        print("SMOKE FAILED", file=sys.stderr)
        sys.exit(1)
    print("SMOKE OK")


if __name__ == "__main__":
    main()
