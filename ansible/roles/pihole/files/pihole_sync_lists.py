#!/usr/bin/env python3
"""Reconcile Pi-hole blocklists/allowlists from config files via the FTL REST API.

Declarative and idempotent: entries we manage (comment == MANAGED) are made to
match the config files exactly — missing ones added, ours no longer in config
removed. Entries added by hand (any other comment) are left untouched.

Runs on the Pi-hole host against the local API. Reads, from PIHOLE_DIR:
  adlists.txt          block adlists   (one URL per line, '#' comments)
  allow.list           allowed domains (exact or regex, one per line)
  allowlist-urls.txt   remote allowlists to fetch and allow

Environment:
  PIHOLE_PASSWORD  admin/API password ('' => API needs no auth)
  PIHOLE_API       API base   (default http://localhost/api)
  PIHOLE_DIR       config dir (default /etc/pihole/managed)

Prints 'CHANGED' when it modifies anything (for Ansible's changed_when).

Structure: the pure functions below (clean_lines, is_regex, split_allow,
host_domain, plan) hold the decision logic and are unit-tested; everything that
touches the network or filesystem is the thin shell beneath them.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import NamedTuple

MANAGED = "managed by ansible"
# A line is a regex pattern (not a plain domain) if it contains any of these.
_REGEX_CHARS = re.compile(r"[\[\](){}|^$\\*+?]")


# ── pure core (unit-tested) ─────────────────────────────────────────────────
def clean_lines(text):
    """Lines with '#' comments and surrounding whitespace stripped, blanks dropped."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


def is_regex(entry):
    """True if entry is a regex pattern rather than a plain domain."""
    return bool(_REGEX_CHARS.search(entry))


def split_allow(entries):
    """Partition allow entries into (exact_domains, regex_patterns)."""
    exact = [e for e in entries if not is_regex(e)]
    regex = [e for e in entries if is_regex(e)]
    return exact, regex


def host_domain(line):
    """Domain from a plain or hosts-format line ('0.0.0.0 example.com' -> example.com)."""
    return line.split()[-1]


def plan(desired, current):
    """Pure diff: (to_add, to_remove).

    to_add   = desired entries not already present (order preserved, de-duped).
    to_remove = managed-and-present entries no longer desired (sorted).
    """
    desired_seen = dict.fromkeys(desired)  # de-dupe, keep order
    current = set(current)
    add = [d for d in desired_seen if d not in current]
    remove = sorted(c for c in current if c not in desired_seen)
    return add, remove


# ── list kinds (data describing each reconcilable list) ─────────────────────
class Kind(NamedTuple):
    label: str  # human label, e.g. "adlist", "allow/exact"
    path: str  # GET current + POST add
    del_path: str  # POST batch-delete
    collection: str  # top-level key in the GET response
    field: str  # entry field / add-body field
    del_extra: dict  # extra fields on each batch-delete item
    bucket: str  # which change bucket to flag ("adlists"/"domains")


ADLIST = Kind("adlist", "/lists?type=block", "/lists:batchDelete",
              "lists", "address", {"type": "block"}, "adlists")


def allow_kind(kind):  # kind: "exact" | "regex"
    return Kind(f"allow/{kind}", f"/domains/allow/{kind}", "/domains:batchDelete",
                "domains", "domain", {"type": "allow", "kind": kind}, "domains")


# ── I/O shell ───────────────────────────────────────────────────────────────
API = os.environ.get("PIHOLE_API", "http://localhost/api")
PW = os.environ.get("PIHOLE_PASSWORD", "")
DIR = os.environ.get("PIHOLE_DIR", "/etc/pihole/managed")

changed = {"adlists": False, "domains": False}
# Set False if any remote allowlist fails to download. When a source is
# incomplete we must NOT treat its domains as "removed" — a transient network
# blip would otherwise delete legitimately-managed allow entries.
fetch_ok = True


def api(method, path, sid=None, body=None):
    """Call the FTL API. Returns (status_code, decoded_json_or_text)."""
    url = API + path
    if sid:
        url += ("&" if "?" in url else "?") + "sid=" + urllib.parse.quote(sid)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, _decode(r.read())
    except urllib.error.HTTPError as e:
        return e.code, _decode(e.read())


def _decode(raw):
    """JSON when possible; some endpoints (e.g. /action/gravity) stream text."""
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return raw.decode("utf-8", "replace")


def die(msg):
    print("ERROR: " + msg, file=sys.stderr)
    sys.exit(1)


def login():
    if not PW:
        return None  # no password set => API accepts unauthenticated calls
    st, j = api("POST", "/auth", body={"password": PW})
    if st != 200:
        die(f"authentication failed (HTTP {st}): {j}")
    return j["session"]["sid"]


def read_file(name):
    path = os.path.join(DIR, name)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return clean_lines(f.read())


def fetch_domains(url):
    """Fetch a remote allowlist; tolerate plain or hosts-format lines."""
    global fetch_ok
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            text = r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"WARN: could not fetch {url}: {e}", file=sys.stderr)
        fetch_ok = False
        return []
    return [host_domain(line) for line in clean_lines(text)]


def reconcile(sid, kind, desired, allow_remove=True):
    """Make the MANAGED entries of one list kind match `desired`."""
    st, j = api("GET", kind.path, sid)
    if st != 200:
        die(f"GET {kind.label} failed (HTTP {st}): {j}")
    current = {x[kind.field] for x in j.get(kind.collection, [])
               if x.get("comment") == MANAGED}
    add, remove = plan(desired, current)

    if add:
        st, j = api("POST", kind.path, sid,
                    {kind.field: add, "comment": MANAGED, "enabled": True})
        if st not in (200, 201):
            die(f"adding {kind.label} failed (HTTP {st}): {j}")
        changed[kind.bucket] = True
        print(f"  + {len(add)} {kind.label}")

    if remove and not allow_remove:
        print(f"  ~ skipping removal of {len(remove)} {kind.label} "
              "(a source failed to load; not removing to avoid data loss)",
              file=sys.stderr)
    elif remove:
        st, j = api("POST", kind.del_path, sid,
                    [{"item": r, **kind.del_extra} for r in remove])
        if st not in (200, 204):
            die(f"removing {kind.label} failed (HTTP {st}): {j}")
        changed[kind.bucket] = True
        print(f"  - {len(remove)} {kind.label}")


def main():
    sid = login()

    allow_exact, allow_regex = split_allow(read_file("allow.list"))
    for url in read_file("allowlist-urls.txt"):
        allow_exact += fetch_domains(url)

    # allow_exact draws on remote lists; only remove exact entries if every
    # source loaded (fetch_ok). Adlists and regex don't fetch, so removal is
    # always safe there.
    reconcile(sid, ADLIST, read_file("adlists.txt"))
    reconcile(sid, allow_kind("exact"), allow_exact, allow_remove=fetch_ok)
    reconcile(sid, allow_kind("regex"), allow_regex)

    # Apply: gravity re-fetches adlists (needed for adlist changes); a plain
    # DNS restart is enough to pick up domain-list changes.
    if changed["adlists"]:
        print("Rebuilding gravity...")
        st, _ = api("POST", "/action/gravity", sid)
        if st != 200:
            die(f"gravity rebuild failed (HTTP {st})")
    elif changed["domains"]:
        print("Reloading DNS...")
        api("POST", "/action/restartdns", sid)

    print("CHANGED" if (changed["adlists"] or changed["domains"]) else "no changes")


if __name__ == "__main__":
    main()
