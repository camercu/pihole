#!/usr/bin/env python3
"""Post-deploy smoke test: prove the box is actually resolving and blocking.

Runs on (or against) the Pi-hole host and checks the things a green Ansible run
does NOT prove — that DNS really answers, that gravity is loaded and blocking is
on, that a known ad domain is actually sinkholed, and (optionally) that unbound
answers directly. Prints one PASS/FAIL line per check and exits non-zero if any
check fails, so it drops straight into `verify.yml` or a shell.

Environment:
  PIHOLE_API           API base (default http://localhost/api)
  PIHOLE_PASSWORD      admin/API password ('' => no auth)
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


def is_blocked(addrs):
    """A name is blocked when it resolves to nothing or only to 0.0.0.0."""
    return all(a == "0.0.0.0" for a in addrs)


# ── I/O shell ───────────────────────────────────────────────────────────────
API = os.environ.get("PIHOLE_API", "http://localhost/api")
PW = os.environ.get("PIHOLE_PASSWORD", "")


def dns_query(server, port, name, timeout=5):
    """Resolve `name`'s A records via one UDP query; [] on timeout/error."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(build_query(name), (server, int(port)))
        return parse_answers(sock.recvfrom(4096)[0])
    except (OSError, struct.error):
        return []
    finally:
        sock.close()


def _api(method, path, sid=None, body=None):
    url = API + path
    if sid:
        url += ("&" if "?" in url else "?") + "sid=" + sid
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read()
        return r.status, (json.loads(raw) if raw else {})


def login():
    if not PW:
        return None
    _, j = _api("POST", "/auth", body={"password": PW})
    return j["session"]["sid"]


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

    _, blk = _api("GET", "/dns/blocking", sid)
    checks.append((blk.get("blocking") == "enabled",
                   f"blocking enabled (got {blk.get('blocking')!r})"))

    _, summary = _api("GET", "/stats/summary", sid)
    count = summary.get("gravity", {}).get("domains_being_blocked", 0)
    checks.append((count > 0, f"gravity populated ({count} domains)"))
    logout(sid)  # remaining checks are DNS-only; free the seat now

    good = dns_query(dns_host, dns_port, resolve_domain)
    checks.append((bool(good) and not is_blocked(good),
                   f"{resolve_domain} resolves ({good or 'no answer'})"))

    bad = dns_query(dns_host, dns_port, blocked_domain)
    checks.append((is_blocked(bad), f"{blocked_domain} blocked ({bad or 'no answer'})"))

    if unbound_port:
        via_unbound = dns_query(dns_host, unbound_port, resolve_domain)
        checks.append((bool(via_unbound),
                       f"unbound answers on :{unbound_port} ({via_unbound or 'no answer'})"))

    for ok, label in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    if not all(ok for ok, _ in checks):
        print("SMOKE FAILED", file=sys.stderr)
        sys.exit(1)
    print("SMOKE OK")


if __name__ == "__main__":
    main()
