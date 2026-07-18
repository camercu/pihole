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
"""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

API = os.environ.get("PIHOLE_API", "http://localhost/api")
PW = os.environ.get("PIHOLE_PASSWORD", "")
DIR = os.environ.get("PIHOLE_DIR", "/etc/pihole/managed")
MANAGED = "managed by ansible"
# A line is a regex pattern (not a plain domain) if it contains any of these.
REGEX_CHARS = re.compile(r"[\[\](){}|^$\\*+?]")

changed = {"adlists": False, "domains": False}
# Set False if any remote allowlist fails to download. When a source is
# incomplete we must NOT treat its domains as "removed" — a transient network
# blip would otherwise delete legitimately-managed allow entries.
fetch_ok = True


def api(method, path, sid=None, body=None):
    """Call the FTL API. Returns (status_code, decoded_json_or_{})."""
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


def clean_lines(text):
    """Strip '#' comments and surrounding whitespace; drop blank lines."""
    out = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


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
    return [line.split()[-1] for line in clean_lines(text)]


def reconcile_adlists(sid, desired):
    st, j = api("GET", "/lists?type=block", sid)
    if st != 200:
        die(f"GET lists failed (HTTP {st}): {j}")
    current = {x["address"] for x in j.get("lists", []) if x.get("comment") == MANAGED}
    add = [a for a in desired if a not in current]
    remove = [a for a in current if a not in desired]
    if add:
        st, j = api("POST", "/lists?type=block", sid,
                    {"address": add, "comment": MANAGED, "enabled": True})
        if st not in (200, 201):
            die(f"adding adlists failed (HTTP {st}): {j}")
        changed["adlists"] = True
        print(f"  + {len(add)} adlist(s)")
    if remove:
        st, j = api("POST", "/lists:batchDelete", sid,
                    [{"item": a, "type": "block"} for a in remove])
        if st not in (200, 204):
            die(f"removing adlists failed (HTTP {st}): {j}")
        changed["adlists"] = True
        print(f"  - {len(remove)} adlist(s)")


def reconcile_allow(sid, kind, desired, allow_remove=True):
    st, j = api("GET", f"/domains/allow/{kind}", sid)
    if st != 200:
        die(f"GET domains failed (HTTP {st}): {j}")
    current = {x["domain"] for x in j.get("domains", []) if x.get("comment") == MANAGED}
    desired = set(desired)
    add = sorted(desired - current)
    remove = sorted(current - desired)
    if add:
        st, j = api("POST", f"/domains/allow/{kind}", sid,
                    {"domain": add, "comment": MANAGED, "enabled": True})
        if st not in (200, 201):
            die(f"adding allow/{kind} failed (HTTP {st}): {j}")
        changed["domains"] = True
        print(f"  + {len(add)} allow/{kind}")
    if remove and not allow_remove:
        print(f"  ~ skipping removal of {len(remove)} allow/{kind} "
              "(a source failed to load; not removing to avoid data loss)",
              file=sys.stderr)
    elif remove:
        st, j = api("POST", "/domains:batchDelete", sid,
                    [{"item": d, "type": "allow", "kind": kind} for d in remove])
        if st not in (200, 204):
            die(f"removing allow/{kind} failed (HTTP {st}): {j}")
        changed["domains"] = True
        print(f"  - {len(remove)} allow/{kind}")


def main():
    sid = login()

    local_allow = read_file("allow.list")
    allow_exact = [d for d in local_allow if not REGEX_CHARS.search(d)]
    allow_regex = [d for d in local_allow if REGEX_CHARS.search(d)]
    for url in read_file("allowlist-urls.txt"):
        allow_exact += fetch_domains(url)

    # allow_exact draws on remote lists; only remove exact entries if every
    # source loaded (fetch_ok). Adlists and regex don't fetch, so removal is
    # always safe there.
    reconcile_adlists(sid, read_file("adlists.txt"))
    reconcile_allow(sid, "exact", allow_exact, allow_remove=fetch_ok)
    reconcile_allow(sid, "regex", allow_regex)

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
