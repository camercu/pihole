#!/usr/bin/env python3
"""Reconcile Pi-hole blocklists/allowlists/groups from config files via the FTL API.

Declarative and idempotent: entries we manage (comment == MANAGED) are made to
match the config files exactly — missing ones added, ours no longer in config
removed. Entries added by hand (any other comment) are left untouched.

Runs on the Pi-hole host against the local API. Reads, from PIHOLE_DIR:
  adlists.txt          block adlists   (one URL per line, '#' comments)  -> default group
  allow.list           allowed domains (exact or regex, one per line)    -> network-wide
  allowlist-urls.txt   remote allowlists to fetch and allow
  groups/<name>/       one dir per Pi-hole group, each with:
    block.list           domains blocked for that group (exact or regex)
    adlists.txt          remote blocklists for that group
    clients.txt          devices in that group (IP/MAC/hostname/subnet)
  A device joins its group AND the default group (keeps ad/threat blocking).

Environment:
  PIHOLE_PASSWORD  admin/API password ('' => API needs no auth)
  PIHOLE_API       API base   (default http://localhost/api)
  PIHOLE_DIR       config dir (default /etc/pihole/managed)

Prints 'CHANGED' when it modifies anything (for Ansible's changed_when). Exits
non-zero if an entry couldn't be added because it already exists as a hand-added
one (warned and skipped, so the rest of the run still converges).

Structure: the pure functions below (clean_lines, is_regex, split_allow,
host_domain, plan_membership, build_membership, network_wide, assemble_desired,
normalize_groups, discover_groups, is_collision, is_transient) hold the decision
logic and are
unit-tested; everything that touches the network or filesystem is the thin shell
beneath them.
"""
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import NamedTuple

MANAGED = "managed by ansible"
# A line is a regex pattern (not a plain domain) if it contains any of these.
_REGEX_CHARS = re.compile(r"[\[\](){}|^$\\*+?]")
# FTL rejects a duplicate add with this message; we treat it as a soft collision
# (something already added the entry by hand) rather than a fatal error.
_ALREADY_PRESENT = "already present"
# SQLite's two "ask again" conditions, verbatim. A gravity rebuild swaps the
# database, so a write landing mid-swap meets one of these and succeeds on the
# retry; every other database error stays broken however long you wait.
_TRANSIENT_DB = ("database is locked", "readonly database")
# Backoff between retries of a transient answer, in seconds. Spans a gravity
# swap (well under a second in practice) without letting a genuinely stuck
# database hold the playbook for more than about a quarter of a minute.
_DB_RETRY_WAITS = (0.25, 0.5, 1, 2, 4, 8)


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


def is_collision(status, body):
    """True if an add failed because the entry already exists (hand-added).

    FTL answers a duplicate add with HTTP 400 and a message containing
    "already present"; anything else at 400 (e.g. a bad regex) is a real error.
    """
    if status not in (400, 409):
        return False
    return _ALREADY_PRESENT in json.dumps(body).lower()


def is_transient(status, body):
    """True if FTL refused the call because its database was momentarily busy.

    Gravity rebuilds swap the database underneath FTL, and for a short window
    writes are refused with one of SQLite's two "ask again" conditions. That is
    not the caller's mistake and not a state to reconcile against — it is the
    same call, not yet made. Distinguished from a real database error, which
    keeps answering the same way however long you wait.
    """
    if 200 <= status < 300:
        return False
    said = json.dumps(body).lower()
    return any(cond in said for cond in _TRANSIENT_DB)


def split_allow(entries):
    """Partition allow entries into (exact_domains, regex_patterns)."""
    exact = [e for e in entries if not is_regex(e)]
    regex = [e for e in entries if is_regex(e)]
    return exact, regex


def host_domain(line):
    """Domain from a plain or hosts-format line ('0.0.0.0 example.com' -> example.com)."""
    return line.split()[-1]


def resolve_password(env):
    """API password from a file (PIHOLE_PASSWORD_FILE) or inline (PIHOLE_PASSWORD).

    The file form keeps the secret out of the process environment and out of
    Ansible's task output — a bare env var leaks at -vvv and lives in
    /proc/<pid>/environ. A file path wins over the inline value; an empty path
    (an unset Ansible var renders as "") counts as absent. Only the trailing
    newline Ansible appends is stripped, so a password's own spaces survive.
    """
    path = env.get("PIHOLE_PASSWORD_FILE") or ""
    if path:
        with open(path, encoding="utf-8") as f:
            return f.read().rstrip("\n")
    return env.get("PIHOLE_PASSWORD", "")


def discover_groups(groups_dir):
    """(name, path) for each subdirectory of groups_dir, sorted by name.

    A group's directory name is its Pi-hole group name. A missing groups_dir (no
    groups configured) yields []; non-directory entries are ignored.
    """
    if not os.path.isdir(groups_dir):
        return []
    out = []
    for name in sorted(os.listdir(groups_dir)):
        path = os.path.join(groups_dir, name)
        if os.path.isdir(path):
            out.append((name, path))
    return out


class Owned(NamedTuple):
    """What a config file asserts about a row the reconciler owns.

    A Pi-hole entry exists once but can belong to several groups, and a file
    that lists an entry is saying it is switched on. Both travel as one value so
    the diff below compares the whole assertion: a field named here is
    reconciled without anyone having to add a second comparison for it, which is
    what let a managed row sit switched off in the admin UI unnoticed.

    groups is a frozenset so the record can key the add-batch buckets.
    """
    groups: frozenset
    enabled: bool


def plan_membership(desired, current):
    """Diff item -> Owned mappings: (add, update, remove).

      add    = {item: Owned} desired but absent — create in that state.
      update = {item: Owned} present in a different state — PUT the desired one.
      remove = sorted items present but no longer desired — delete.
    """
    add = {i: g for i, g in desired.items() if i not in current}
    update = {i: g for i, g in desired.items()
              if i in current and g != current[i]}
    remove = sorted(i for i in current if i not in desired)
    return add, update, remove


def normalize_groups(groups):
    """A group-id list as a set, treating "no groups" as the default group.

    Pi-hole shows an entry with no explicit group assignment in the default
    group; FTL may report that as [] or [0]. Normalising empty -> {0} makes the
    reconcile idempotent whichever representation FTL returns, instead of PUTting
    a default-only entry back to [0] on every run.
    """
    return set(groups) or {DEFAULT_GROUP}


def network_wide(entries):
    """{entry: Owned} for entries the config applies to the whole network.

    Allowlists name no group: the files say network-wide, which is the default
    group and nothing else. Expressed as membership so allow entries reconcile
    through the same path, and so the same whole-record comparison, as every
    other kind — they were once diffed on presence alone, which is how a managed
    allow domain switched off in the admin UI stayed off through every run.
    """
    return {e: Owned(frozenset({DEFAULT_GROUP}), True) for e in entries}


def build_membership(entries_by_group):
    """[(group_id, [entries])] -> {entry: Owned}, unioning duplicates.

    The same entry configured under several groups collapses to one entry owned
    by all of them (Pi-hole stores each domain/adlist once, group-tagged). Every
    entry a file lists is desired enabled — the files have no way to say
    otherwise, and the reconcile makes that assertion true.
    """
    groups = {}
    for gid, entries in entries_by_group:
        for entry in entries:
            groups.setdefault(entry, set()).add(gid)
    return {entry: Owned(frozenset(gids), True) for entry, gids in groups.items()}


def assemble_desired(default_adlists, group_inputs):
    """Build the four desired membership maps from parsed config (pure).

    This is where the product decisions live, so they are unit-testable without
    a Pi-hole:
      - top-level adlists.txt applies to the default group; each group's
        adlists.txt to that group (same URL in both unions onto one row);
      - a group's block.list denies domains for that group only (exact vs regex
        split by shape);
      - a group's devices join both their group AND the default group, so they
        keep network-wide ad/threat blocking on top of the group's block lists.

    default_adlists: adlist URLs for the default group.
    group_inputs: list of (gid, adlist_urls, block_lines, client_ids) per group.
    Returns {"adlists"|"deny_exact"|"deny_regex"|"clients": {entry: set(gids)}}.
    """
    adlists = [(DEFAULT_GROUP, default_adlists)]
    deny_exact, deny_regex, clients = [], [], []
    for gid, adlist_urls, block_lines, client_ids in group_inputs:
        adlists.append((gid, adlist_urls))
        block_exact, block_regex = split_allow(block_lines)
        deny_exact.append((gid, block_exact))
        deny_regex.append((gid, block_regex))
        clients += [(gid, client_ids), (DEFAULT_GROUP, client_ids)]
    return {
        "adlists": build_membership(adlists),
        "deny_exact": build_membership(deny_exact),
        "deny_regex": build_membership(deny_regex),
        "clients": build_membership(clients),
    }


# ── list kinds (data describing each reconcilable list) ─────────────────────
class Kind(NamedTuple):
    label: str  # human label, e.g. "adlist", "allow/exact"
    path: str  # GET current + POST add
    del_path: str  # POST batch-delete
    collection: str  # top-level key in the GET response
    field: str  # entry field / add-body field
    del_extra: dict  # extra fields on each batch-delete item
    bucket: str  # which change bucket to flag ("adlists"/"domains"/"clients")
    item_path: object = None  # entry -> single-item URL for PUT (group reassign)
    enabled: bool = True  # send an "enabled" body field (clients have none)


def _q(entry):
    return urllib.parse.quote(entry, safe="")


ADLIST = Kind("adlist", "/lists?type=block", "/lists:batchDelete",
              "lists", "address", {"type": "block"}, "adlists",
              lambda e: f"/lists/{_q(e)}?type=block")

# A client (device) is reconciled like a list entry, but keyed by "client",
# carrying no enabled flag, and its groups control which lists reach the device.
CLIENT = Kind("client", "/clients", "/clients:batchDelete",
              "clients", "client", {}, "clients",
              lambda e: f"/clients/{_q(e)}", enabled=False)


def allow_kind(kind):  # kind: "exact" | "regex"
    return Kind(f"allow/{kind}", f"/domains/allow/{kind}", "/domains:batchDelete",
                "domains", "domain", {"type": "allow", "kind": kind}, "domains",
                lambda e: f"/domains/allow/{kind}/{_q(e)}")


def deny_kind(kind):  # kind: "exact" | "regex"
    return Kind(f"deny/{kind}", f"/domains/deny/{kind}", "/domains:batchDelete",
                "domains", "domain", {"type": "deny", "kind": kind}, "domains",
                lambda e: f"/domains/deny/{kind}/{_q(e)}")


# ── I/O shell ───────────────────────────────────────────────────────────────
API = os.environ.get("PIHOLE_API", "http://localhost/api")
PW = resolve_password(os.environ)
DIR = os.environ.get("PIHOLE_DIR", "/etc/pihole/managed")
GROUPS_DIR = os.path.join(DIR, "groups")  # one subdir per Pi-hole group

DEFAULT_GROUP = 0  # Pi-hole's built-in "Default" group; never created or removed

changed = {"adlists": False, "domains": False, "groups": False, "clients": False}
# Set False if any remote allowlist fails to download. When a source is
# incomplete we must NOT treat its domains as "removed" — a transient network
# blip would otherwise delete legitimately-managed allow entries.
fetch_ok = True
# Entries we couldn't add because something already added them by hand. We skip
# them (rest of the run still converges) and exit non-zero at the end so the
# collision is visible instead of silently unmanaged.
collisions = []


def retry_transient(call, sleep=time.sleep, waits=_DB_RETRY_WAITS):
    """Repeat `call` while it answers with a transient database condition.

    Returns the first settled answer — or the last transient one, once the waits
    run out, so the caller still sees FTL's own words and fails on them. Bounded
    on purpose: a database that never unlocks is a real fault, and a run that
    hangs on it is worse than one that stops.
    """
    for wait in waits:
        status, body = call()
        if not is_transient(status, body):
            return status, body
        sleep(wait)
    return call()


def api(method, path, sid=None, body=None):
    """Call the FTL API. Returns (status_code, decoded_json_or_text).

    Every call the script makes comes through here, so this is where waiting out
    a database swap belongs: a locked or read-only answer means the call has not
    happened yet, and the alternative — dying on it — aborts a whole deploy for
    a window that closes on its own.
    """
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
    return retry_transient(lambda: _request(req))


def _request(req):
    """One HTTP round trip to FTL, as (status, decoded body)."""
    try:
        # Bound the call so a stalled pihole-FTL can't hang the playbook forever.
        with urllib.request.urlopen(req, timeout=30) as r:
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
    """API session id (or None if unauthenticated).

    Contract: FAIL HARD. This script mutates managed state, so bad auth must
    stop the run loudly rather than silently reconcile against nothing. Kept
    deliberately separate from backup/smoke's login(), which have their own
    error contracts (raise / soft-None) suited to their jobs.
    """
    if not PW:
        return None  # no password set => API accepts unauthenticated calls
    st, j = api("POST", "/auth", body={"password": PW})
    if st != 200:
        die(f"authentication failed (HTTP {st}): {j}")
    return j["session"]["sid"]


def logout(sid):
    """Release the API session so its seat is freed immediately, not in 30 min.

    FTL has a small pool of session seats; a script that logs in every run and
    never logs out can exhaust them (overlapping timers, rapid re-runs).
    """
    if sid:
        api("DELETE", "/auth", sid)


def read_path(path):
    """Cleaned lines of a config file, or [] if it doesn't exist."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return clean_lines(f.read())


def read_file(name):
    return read_path(os.path.join(DIR, name))


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


def add_entries(sid, kind, items, extra):
    """POST items (as one batch), isolating hand-added collisions per item.

    FTL fails the whole batch if any single item already exists, so on a collision
    we retry each item alone: non-colliding ones still apply; colliders are recorded
    (see `collisions`) and skipped so the rest of the run still converges. A
    non-collision error is still fatal. Returns the number actually added.
    """
    if not items:
        return 0
    st, j = api("POST", kind.path, sid, {kind.field: items, **extra})
    if st in (200, 201):
        return len(items)
    if not is_collision(st, j):
        die(f"adding {kind.label} failed (HTTP {st}): {j}")
    added = 0
    for it in items:
        st, j = api("POST", kind.path, sid, {kind.field: [it], **extra})
        if st in (200, 201):
            added += 1
        elif is_collision(st, j):
            collisions.append((kind.label, it))
            print(f"WARN: {kind.label} {it!r} already exists as a hand-added entry; "
                  "remove it (Pi-hole UI or config) so it can be managed.",
                  file=sys.stderr)
        else:
            die(f"adding {kind.label} {it!r} failed (HTTP {st}): {j}")
    return added


def reconcile_membership(sid, kind, desired, allow_remove=True):
    """Reconcile one list kind against {entry: Owned}.

    The only reconcile path, so every kind is held to the same comparison.
    Managed entries are created (batched by the state the files assert), PUT
    back whenever any part of that state has drifted, and deleted when no longer
    desired. allow_remove=False holds the deletions back when a source failed to
    load, since an incomplete desired set must not read as "these were removed".
    """
    assert kind.item_path is not None, f"{kind.label} kind has no PUT item_path"
    st, j = api("GET", kind.path, sid)
    if st != 200:
        die(f"GET {kind.label} failed (HTTP {st}): {j}")
    # Only a kind that has the column can be off; for the rest the files' "on"
    # has to compare equal to itself, or every run would PUT a field FTL has
    # nowhere to put and never converge.
    current = {x[kind.field]: Owned(frozenset(normalize_groups(x.get("groups", []))),
                                    bool(x.get("enabled", True)) if kind.enabled
                                    else True)
               for x in j.get(kind.collection, []) if x.get("comment") == MANAGED}
    add, update, remove = plan_membership(desired, current)

    def body_for(owned):
        # Clients carry no enabled column, so the field is omitted rather than
        # sent as a value FTL has nowhere to put.
        state = {"enabled": owned.enabled} if kind.enabled else {}
        return {"comment": MANAGED, "groups": sorted(owned.groups), **state}

    for owned, items in _bucket_by_groups(add):
        added = add_entries(sid, kind, items, body_for(owned))
        if added:
            changed[kind.bucket] = True
            print(f"  + {added} {kind.label} -> groups {sorted(owned.groups)}")

    for entry, owned in update.items():
        st, j = api("PUT", kind.item_path(entry), sid, body_for(owned))
        if st not in (200, 201, 204):
            die(f"reasserting {kind.label} {entry!r} failed (HTTP {st}): {j}")
        changed[kind.bucket] = True
        print(f"  ~ {entry} -> groups {sorted(owned.groups)}, enabled {owned.enabled}")

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


def _bucket_by_groups(add):
    """Group an {entry: Owned} add-map into (Owned, [entries]).

    Entries the files assert the same thing about POST together; the sort keys
    make output stable. Sorted by group ids then enabled, since a frozenset has
    no order of its own.
    """
    buckets = {}
    for entry, owned in add.items():
        buckets.setdefault(owned, []).append(entry)
    return [(owned, sorted(items)) for owned, items in
            sorted(buckets.items(), key=lambda kv: (sorted(kv[0].groups), kv[0].enabled))]


def group_ids(sid):
    """name -> id for every Pi-hole group (built-in + managed)."""
    st, j = api("GET", "/groups", sid)
    if st != 200:
        die(f"GET groups failed (HTTP {st}): {j}")
    return {g["name"]: g["id"] for g in j.get("groups", [])}


def reconcile_groups(sid, desired_names):
    """Ensure a Pi-hole group exists for each configured group dir.

    Creates managed groups that are missing and removes managed groups no longer
    configured. The built-in "Default" group and any group a user made by hand
    (comment != MANAGED) are left untouched. Returns name -> id for all groups.
    """
    st, j = api("GET", "/groups", sid)
    if st != 200:
        die(f"GET groups failed (HTTP {st}): {j}")
    present = {g["name"] for g in j.get("groups", [])}
    managed = {g["name"] for g in j.get("groups", []) if g.get("comment") == MANAGED}
    add = [n for n in dict.fromkeys(desired_names) if n not in present]
    remove = sorted(n for n in managed if n not in set(desired_names))

    for name in add:
        st, j = api("POST", "/groups", sid,
                    {"name": name, "comment": MANAGED, "enabled": True})
        if st not in (200, 201):
            die(f"adding group {name!r} failed (HTTP {st}): {j}")
        changed["groups"] = True
        print(f"  + group {name}")

    for name in remove:
        st, j = api("DELETE", f"/groups/{urllib.parse.quote(name)}", sid)
        if st not in (200, 204):
            die(f"removing group {name!r} failed (HTTP {st}): {j}")
        changed["groups"] = True
        print(f"  - group {name}")

    return group_ids(sid)


def main():
    sid = login()
    try:
        groups = discover_groups(GROUPS_DIR)
        name_to_id = reconcile_groups(sid, [name for name, _ in groups])

        # Allowlists apply network-wide (default group only).
        allow_exact, allow_regex = split_allow(read_file("allow.list"))
        for url in read_file("allowlist-urls.txt"):
            allow_exact += fetch_domains(url)
        # allow_exact draws on remote lists; only remove exact entries if every
        # source loaded (fetch_ok). Regex doesn't fetch, so removal is always safe.
        reconcile_membership(sid, allow_kind("exact"), network_wide(allow_exact),
                             allow_remove=fetch_ok)
        reconcile_membership(sid, allow_kind("regex"), network_wide(allow_regex))

        # Read each group's files, then assemble the desired group-scoped state (the
        # product decisions live in assemble_desired, unit-tested). Block adlists span
        # one namespace across groups, so all four maps reconcile via membership.
        group_inputs = [
            (name_to_id[name],
             read_path(os.path.join(path, "adlists.txt")),
             read_path(os.path.join(path, "block.list")),
             read_path(os.path.join(path, "clients.txt")))
            for name, path in groups
        ]
        desired = assemble_desired(read_file("adlists.txt"), group_inputs)
        reconcile_membership(sid, ADLIST, desired["adlists"])
        reconcile_membership(sid, deny_kind("exact"), desired["deny_exact"])
        reconcile_membership(sid, deny_kind("regex"), desired["deny_regex"])
        reconcile_membership(sid, CLIENT, desired["clients"])

        # Apply: gravity re-fetches adlists (needed for adlist changes); a plain DNS
        # restart is enough to pick up domain-, group-, and client-list changes.
        if changed["adlists"]:
            print("Rebuilding gravity...")
            st, _ = api("POST", "/action/gravity", sid)
            if st != 200:
                die(f"gravity rebuild failed (HTTP {st})")
        elif any(changed.values()):
            print("Reloading DNS...")
            api("POST", "/action/restartdns", sid)

        print("CHANGED" if any(changed.values()) else "no changes")
    finally:
        logout(sid)

    # Everything appliable has been applied; fail loudly so a hand-added collision
    # isn't left silently unmanaged.
    if collisions:
        print(f"ERROR: {len(collisions)} entr{'y' if len(collisions) == 1 else 'ies'} "
              "skipped due to hand-added collisions (see warnings above)",
              file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
