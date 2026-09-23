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
normalize_groups, discover_groups, resolve_password, is_collision, is_transient,
is_timeout, apply_needed, config_root_missing, missing_inputs, groups_root_missing) hold the decision
logic and are unit-tested;
everything that touches the network or filesystem is the thin shell beneath them.
retry_transient sits in that shell and is unit-tested too, by injecting its wait.
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
# Fetched allowlist-urls.txt domains are indistinguishable from allow.list's
# own on the wire (same kind, same collection); tagged separately so the
# mirror can tell a URL's own curated list apart from an operator's edits and
# leave the former alone rather than forking it into allow.list.
MANAGED_FETCHED = "managed by ansible (fetched)"
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
# Statuses meaning a delete's target is gone. FTL answers 404 when none of the
# items exist -- which is also what a resend gets after the first delete
# landed and its ack was lost -- and absence is what a delete is for.
_DELETED = (200, 204, 404)


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


def is_timeout(exc):
    """True if `exc` (raised by a urlopen call) means FTL is slow, not gone.

    A read timeout raises bare TimeoutError; a connect/send-phase timeout is
    wrapped by urllib in a URLError instead, so it is caught here by its
    `.reason` rather than its own type. Either way it is a different signal
    from a dropped connection: retrying it would turn one bounded wait into
    several, so callers treat this as fatal rather than as "ask again".
    """
    return isinstance(exc, TimeoutError) or isinstance(
        getattr(exc, "reason", None), TimeoutError)


def apply_needed(changed, pending):
    """What FTL must do for reconciled writes to take effect: "gravity",
    "dns" or None.

    `pending` is what an earlier run wrote to the box but never got applied.
    Gravity re-fetches adlists and reloads DNS too, so it covers "dns".
    """
    if changed["adlists"] or pending == "gravity":
        return "gravity"
    if any(changed.values()) or pending == "dns":
        return "dns"
    return None


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


def group_paths_to_prune(source_paths, deployed_paths, source_root, deployed_root):
    """Deployed group-tree paths this repo's own tree no longer describes.

    Mirrors main.yml's `relpath`/`regex_replace` chain: every source_paths
    entry maps onto the path it would occupy under deployed_root, and
    whatever is deployed outside that set is stale. Sorted so a path always
    precedes any ancestor directory it lives under -- a child's path is
    always the longer string with its parent as a prefix, so a plain reverse
    sort clears each directory's contents before `file: state=absent`
    reaches the directory itself.
    """
    kept = {os.path.join(deployed_root, os.path.relpath(p, source_root))
            for p in source_paths}
    return sorted((p for p in deployed_paths if p not in kept), reverse=True)


def manifest_key(kind_label, comment):
    """Manifest key for one reconcile call.

    kind.label alone collides when two calls share a collection under
    different comments (allow/exact local vs. allow/exact fetched); comment
    alone collides across kinds that share MANAGED (deny/exact, deny/regex,
    ...). Together they name exactly one call.
    """
    return f"{kind_label} [{comment}]"


def known_identities(manifest, kind_label, comment):
    """The identities manifest says this call created, or None to trust the
    comment alone -- no manifest yet (first run since it existed) reads the
    same as no restriction, not as "nothing is ours"."""
    if manifest is None:
        return None
    return set(manifest.get(manifest_key(kind_label, comment), []))


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
# What this reconciler itself created, keyed by kind + comment so two
# reconciles sharing a collection (allow.list vs. allowlist-urls.txt's fetched
# domains) never see each other's identities. The MANAGED comment alone is not
# proof of authorship -- it is free text the admin UI lets anyone type -- so
# a row is only ever deleted when both agree it is ours. Written after every
# add/remove actually lands, not once per call or once at the end, so an
# interruption -- between calls or partway through one -- loses at most the
# mutations it never reached, not this run's own already-confirmed
# identities, which would otherwise read as hand-added collisions on the
# next run.
MANIFEST = os.path.join(DIR, ".manifest.json")
# Manifest key for an apply ("gravity"/"dns") a run's writes needed but did not
# finish. A later run sees no drift -- the writes are already on the box -- so
# this record is the only thing that gets them applied.
_APPLY_PENDING = "apply pending"

DEFAULT_GROUP = 0  # Pi-hole's built-in "Default" group; never created or removed

changed = {"adlists": False, "domains": False, "groups": False, "clients": False}
# Entries we couldn't add because something already added them by hand. We skip
# them (rest of the run still converges) and exit non-zero at the end so the
# collision is visible instead of silently unmanaged.
collisions = []


def retry_transient(call, sleep=None, waits=_DB_RETRY_WAITS, retry_dropped=True):
    """Repeat `call` while it answers with a transient database condition, or
    while the connection itself drops.

    FTL also closes its sockets while gravity restarts DNS; that is the same
    "not yet, ask again" window as a locked database, just signalled by an
    exception instead of a body. A timeout is not that window -- it means FTL
    is still there but slow, so it is left to propagate rather than turning one
    bounded wait into several. retry_dropped=False turns off the drop retry
    too, for a caller whose own retry would be worse than the drop -- see
    api()'s docstring. Returns the first settled answer — or the last
    transient one, once the waits run out, so the caller still sees FTL's own
    words and fails on them. Bounded on purpose: an API that never comes back
    is a real fault, and a run that hangs on it is worse than one that stops.
    """
    sleep = sleep if sleep is not None else time.sleep
    for wait in waits:
        try:
            status, body = call()
        except OSError as e:
            if is_timeout(e) or not retry_dropped:
                raise
            sleep(wait)
            continue
        if not is_transient(status, body):
            return status, body
        sleep(wait)
    return call()


def api(method, path, sid=None, body=None, retry_dropped=None):
    """Call the FTL API. Returns (status_code, decoded_json_or_text).

    Every call the script makes comes through here, so this is where waiting out
    a database swap belongs: a locked or read-only answer means the call has not
    happened yet, and the alternative — dying on it — aborts a whole deploy for
    a window that closes on its own.

    A dropped connection is resent too, and for a write a lost ack can mean the
    first attempt already acted. So every write must say retry_dropped=True
    (a resend is safe: idempotent, or its duplicate answer is handled) or
    False (acting twice does harm). A GET is always safe to resend.
    """
    if retry_dropped is None:
        if method != "GET":
            raise TypeError(f"{method} {path}: declare retry_dropped -- is "
                            "resending this write after a lost ack safe?")
        retry_dropped = True
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
    return retry_transient(lambda: _request(req), retry_dropped=retry_dropped)


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

    A dropped connection here is retried like any other call: login lands in
    the window an earlier run's DNS restart may still hold open, so a fatal
    drop would fail the ordinary case to guard the rare one. The rare one: a
    retry after a lost ack (not a lost request) mints a second session, whose
    seat leaks until FTL's idle timeout reclaims it -- a real but minor cost.
    If the connection never comes back, the run still stops with a message,
    not a raw traceback.
    """
    if not PW:
        return None  # no password set => API accepts unauthenticated calls
    try:
        st, j = api("POST", "/auth", body={"password": PW}, retry_dropped=True)
    except OSError as e:
        if is_timeout(e):
            die(f"authentication failed: FTL did not respond in time ({e})")
        die(f"authentication failed: connection dropped before a response ({e})")
    if st != 200:
        die(f"authentication failed (HTTP {st}): {j}")
    return j["session"]["sid"]


def logout(sid):
    """Release the API session so its seat is freed immediately, not in 30 min.

    FTL has a small pool of session seats; a script that logs in every run and
    never logs out can exhaust them (overlapping timers, rapid re-runs).
    """
    if sid:
        api("DELETE", "/auth", sid, retry_dropped=True)  # answer is ignored


_TOP_LEVEL_FILES = ("adlists.txt", "allow.list", "allowlist-urls.txt")


def config_root_missing(root):
    """True if the config root is not there to be read at all."""
    return not os.path.isdir(root)


def missing_inputs(root):
    """The top-level config files that are not there, sorted.

    A file that is absent has not said "nothing"; it has said nothing. The two
    read the same to read_path and the difference is every entry it would have
    listed, so the caller is told which files it never saw and declines to
    delete on their say-so — the same rule fetch_domains already applies to a
    remote list that would not download. Group files are not here: a group
    directory is allowed to carry only the files it needs.
    """
    return sorted(n for n in _TOP_LEVEL_FILES
                  if not os.path.exists(os.path.join(root, n)))


def groups_root_missing(root):
    """True if this config's per-group tree is not there to be read at all.

    Distinct from config_root_missing: the top-level files can be complete
    while groups/ itself is missing, and every group, deny list, client and
    group-scoped adlist is sourced only from inside it — so this alone has to
    gate all four, the way missing_inputs gates the top-level files. An empty
    (but present) groups/ is not this: that is every group having been
    deleted on purpose, and must still reach the box.
    """
    return not os.path.isdir(os.path.join(root, "groups"))


def read_path(path):
    """Cleaned lines of a config file, or [] if it doesn't exist."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return clean_lines(f.read())


def read_file(name):
    return read_path(os.path.join(DIR, name))


def read_manifest(path):
    """What the last successful run recorded, or None if there is none yet."""
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write_manifest(path, manifest):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, sort_keys=True, indent=2)


def fetch_domains(url):
    """Fetch a remote allowlist; tolerate plain or hosts-format lines.

    Returns (domains, ok) rather than raising or setting shared state: one bad
    URL among several must not read as every fetched domain being unknown, and
    must not touch whether allow.list's own, unrelated entries can be removed.
    """
    try:
        with urllib.request.urlopen(url, timeout=30) as r:
            text = r.read().decode("utf-8", "replace")
    except (urllib.error.URLError, TimeoutError) as e:
        print(f"WARN: could not fetch {url}: {e}", file=sys.stderr)
        return [], False
    return [host_domain(line) for line in clean_lines(text)], True


def _fetch_by_key(sid, path, collection, field):
    """A fresh key -> row map for `path`, to corroborate a collision.

    The caller's own snapshot predates this call's writes, so it cannot tell a
    hand-added row from one this same call created moments ago (its ack lost
    to a dropped connection, then retried into a collision). A fresh GET can.
    """
    st, j = api("GET", path, sid)
    if st != 200:
        return {}
    return {x[field]: x for x in j.get(collection, [])}


def _is_self_retried(rows_by_key, key, comment):
    """True if `key`'s row, fetched fresh after a collision, carries `comment`
    -- this call's own write landing twice, not a hand-added row.

    Comment alone, with no manifest check. The caller's snapshot, taken before
    any write, said `key` was absent, so a row now carrying our comment is
    this call's own write -- short of someone typing our exact comment into
    the admin UI for the same entry within the same few seconds. The manifest
    cannot help here: it records the previous run, so a key new to this run is
    never in it. Same trust the first run ever (no manifest) already places in
    the comment.
    """
    row = rows_by_key.get(key)
    return row is not None and row.get("comment") == comment


def add_entries(sid, kind, items, extra, on_added=None):
    """POST items (as one batch), isolating hand-added collisions per item.

    FTL fails the whole batch if any single item already exists, so on a collision
    we retry each item alone: non-colliding ones still apply; colliders are recorded
    (see `collisions`) and skipped so the rest of the run still converges. A
    non-collision error is still fatal. Returns (count actually added, items that
    collided) -- the caller needs the second half too, since a collided identity
    was never actually created and must not be recorded as this run's own.

    A per-item collision is not always a hand-added row: the batch POST can
    have landed with its ack lost to a dropped connection, so the retry
    collides with an entry this very call created. _is_self_retried tells the
    two apart.

    on_added, if given, is called with the items just confirmed live: once
    with the whole batch on the fast path (one POST, genuinely atomic), or
    once per item on the fallback path (a separate POST each, so a later
    item's real failure must not un-confirm an item that already succeeded).
    Lets a caller persist partial progress before any later item -- or any
    later step in the same run -- might die.
    """
    if not items:
        return 0, []
    # A resend's duplicate answer is a collision, corroborated below.
    st, j = api("POST", kind.path, sid, {kind.field: items, **extra},
                retry_dropped=True)
    if st in (200, 201):
        if on_added:
            on_added(items)
        return len(items), []
    if not is_collision(st, j):
        die(f"adding {kind.label} failed (HTTP {st}): {j}")
    added = 0
    collided = []
    live = None  # fetched at most once, only if a collision actually occurs
    for it in items:
        st, j = api("POST", kind.path, sid, {kind.field: [it], **extra},
                    retry_dropped=True)
        if st in (200, 201):
            added += 1
            if on_added:
                on_added([it])
        elif is_collision(st, j):
            if live is None:
                live = _fetch_by_key(sid, kind.path, kind.collection, kind.field)
            if _is_self_retried(live, it, extra.get("comment")):
                added += 1
                if on_added:
                    on_added([it])
                continue
            collisions.append((kind.label, it))
            collided.append(it)
            print(f"WARN: {kind.label} {it!r} already exists as a hand-added entry; "
                  "remove it (Pi-hole UI or config) so it can be managed.",
                  file=sys.stderr)
        else:
            die(f"adding {kind.label} {it!r} failed (HTTP {st}): {j}")
    return added, collided


def reconcile_membership(sid, kind, desired, allow_remove=True, comment=MANAGED,
                         known=None, record=None, flush=None):
    """Reconcile one list kind against {entry: Owned}.

    The only reconcile path, so every kind is held to the same comparison.
    Managed entries are created (batched by the state the files assert), PUT
    back whenever any part of that state has drifted, and deleted when no longer
    desired. allow_remove=False holds the deletions back when a source failed to
    load, since an incomplete desired set must not read as "these were removed".
    comment distinguishes rows this call owns from rows another call against the
    same collection owns (fetched allowlist domains vs. allow.list's own), so
    two calls sharing a kind never see, update or remove each other's rows.

    known, from the last successful run's manifest, is the second half of
    "ours": the comment alone is free text the admin UI lets anyone type, so a
    row only counts as this call's to update or delete when both agree. None
    (no manifest yet) trusts the comment alone, same as before the manifest
    existed. record, when given, is kept up to date with this call's
    confirmed-live identities under its own key as each add/remove actually
    lands -- not only once the whole call finishes -- so a later step in this
    same call dying for real (a genuine server error, not a collision) leaves
    the manifest matching what is actually live, rather than losing everything
    this call did. flush, when given, is called after every such update so the
    manifest is durable on disk before any later step risks the same fate.
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
               for x in j.get(kind.collection, []) if x.get("comment") == comment
               and (known is None or x[kind.field] in known)}
    add, update, remove = plan_membership(desired, current)

    def body_for(owned):
        # Clients carry no enabled column, so the field is omitted rather than
        # sent as a value FTL has nowhere to put.
        state = {"enabled": owned.enabled} if kind.enabled else {}
        return {"comment": comment, "groups": sorted(owned.groups), **state}

    # allow_remove=False means a source this call's desired set depends on
    # could not be read, so desired itself is incomplete this run --
    # recording any of it would shrink the manifest to less than what the
    # last trustworthy run already established; see the same guard on the
    # remove step below.
    confirmed = set(current)

    def _sync():
        if record is not None and allow_remove:
            record[manifest_key(kind.label, comment)] = sorted(confirmed)
            if flush is not None:
                flush()

    def _on_added(added_items):
        confirmed.update(added_items)
        _sync()

    for owned, items in _bucket_by_groups(add):
        added, _collided = add_entries(sid, kind, items, body_for(owned),
                                       on_added=_on_added)
        if added:
            changed[kind.bucket] = True
            print(f"  + {added} {kind.label} -> groups {sorted(owned.groups)}")

    for entry, owned in update.items():
        st, j = api("PUT", kind.item_path(entry), sid, body_for(owned),
                    retry_dropped=True)  # PUT is idempotent
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
                    [{"item": r, **kind.del_extra} for r in remove],
                    retry_dropped=True)  # a resend's 404 is in _DELETED
        if st not in _DELETED:
            die(f"removing {kind.label} failed (HTTP {st}): {j}")
        changed[kind.bucket] = True
        print(f"  - {len(remove)} {kind.label}: {', '.join(sorted(remove))}")
        confirmed.difference_update(remove)

    _sync()


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


def reconcile_groups(sid, desired_names, allow_remove=True, known=None, record=None,
                     flush=None):
    """Ensure a Pi-hole group exists for each configured group dir.

    Creates managed groups that are missing and removes managed groups no longer
    configured. The built-in "Default" group and any group a user made by hand
    (comment != MANAGED) are left untouched. allow_remove=False holds deletions
    back the same way reconcile_membership does, for the same reason: groups/
    itself being unreadable must not read as "no groups configured" here either.
    known/record carry the manifest the same way reconcile_membership's do: a
    group only deletes when the last successful run's own record agrees the
    MANAGED comment is telling the truth. record is kept up to date as each
    group is actually created, not only once every group in this call has
    landed, so a later group in the same call dying for real (a genuine
    server error) leaves the manifest matching what is actually live. flush,
    when given, is called after every such update for the same reason
    reconcile_membership's does.
    Returns (name -> id for all groups, the desired names that collided with
    a hand-added group of the same name -- the caller must not write into
    those this run).
    """
    st, j = api("GET", "/groups", sid)
    if st != 200:
        die(f"GET groups failed (HTTP {st}): {j}")
    by_name = {g["name"]: g for g in j.get("groups", [])}
    present = set(by_name)
    managed = {n for n in by_name
              if by_name[n].get("comment") == MANAGED
              and (known is None or n in known)}
    # A name already present under any other comment is a group someone else
    # made; add_entries already has this branch for domains/lists/clients, and
    # a group deserves the same rather than being silently written into.
    collided = sorted(n for n in dict.fromkeys(desired_names)
                      if n in present and by_name[n].get("comment") != MANAGED)
    for name in collided:
        collisions.append(("group", name))
        print(f"WARN: group {name!r} already exists as a hand-added group; "
              "remove it (Pi-hole UI) so it can be managed.", file=sys.stderr)
    add = [n for n in dict.fromkeys(desired_names) if n not in present]
    remove = sorted(n for n in managed if n not in set(desired_names))

    # Removed names are never in desired_names, so a removal succeeding or
    # dying part-way through never changes what this call's record should
    # say -- only `add` landing does.
    confirmed = set(dict.fromkeys(desired_names)) - set(collided) - set(add)

    def _sync():
        if record is not None and allow_remove:
            record["groups"] = sorted(confirmed)
            if flush is not None:
                flush()

    _sync()
    for name in add:
        # A resend's duplicate answer is a collision, corroborated below.
        st, j = api("POST", "/groups", sid,
                    {"name": name, "comment": MANAGED, "enabled": True},
                    retry_dropped=True)
        if st not in (200, 201):
            # Same self-retry race add_entries corroborates: the create may
            # have landed with its ack lost, and the retried POST now bounces
            # off the group it made. A genuine mid-run name clash stays fatal.
            if is_collision(st, j) and _is_self_retried(
                    _fetch_by_key(sid, "/groups", "groups", "name"), name, MANAGED):
                changed["groups"] = True
                print(f"  + group {name}")
                confirmed.add(name)
                _sync()
                continue
            die(f"adding group {name!r} failed (HTTP {st}): {j}")
        changed["groups"] = True
        print(f"  + group {name}")
        confirmed.add(name)
        _sync()

    if remove and not allow_remove:
        print(f"  ~ skipping removal of {len(remove)} group(s) "
              "(a source failed to load; not removing to avoid data loss)",
              file=sys.stderr)
    else:
        for name in remove:
            st, j = api("DELETE", f"/groups/{urllib.parse.quote(name)}", sid,
                        retry_dropped=True)  # a resend's 404 is in _DELETED
            if st not in _DELETED:
                die(f"removing group {name!r} failed (HTTP {st}): {j}")
            changed["groups"] = True
            print(f"  - group {name}")

    return group_ids(sid), set(collided)


def apply_changes(sid, need):
    """Make FTL apply reconciled writes: `need` is apply_needed()'s answer.

    The gravity trigger does not retry a dropped connection: a lost ack may
    mean the rebuild already started, and a blind retry risks a second one
    running against the same database swap. It fails hard instead; main()
    then records the apply as pending, so the next run triggers it again.
    """
    if need == "gravity":
        print("Rebuilding gravity...")
        try:
            st, _ = api("POST", "/action/gravity", sid, retry_dropped=False)
        except OSError as e:
            if is_timeout(e):
                die(f"gravity rebuild failed: FTL did not respond in time ({e})")
            die(f"gravity rebuild failed: connection dropped before a response ({e})")
        if st != 200:
            die(f"gravity rebuild failed (HTTP {st})")
    elif need == "dns":
        print("Reloading DNS...")
        st, j = api("POST", "/action/restartdns", sid,
                    retry_dropped=True)  # 2 restarts = 1
        if st != 200:
            die(f"DNS reload failed (HTTP {st}): {j}")


def main():
    if config_root_missing(DIR):
        die(f"config root {DIR!r} does not exist; refusing to reconcile, since "
            "every managed entry would read as deleted")
    absent = missing_inputs(DIR)
    for name in absent:
        print(f"WARN: {name} is not in {DIR}; entries it would list are left "
              "alone rather than removed.", file=sys.stderr)
    groups_readable = not groups_root_missing(DIR)
    if not groups_readable:
        print(f"WARN: {GROUPS_DIR} is not there; groups, deny lists, clients "
              "and group-scoped adlists are left alone rather than removed.",
              file=sys.stderr)
    manifest_in = read_manifest(MANIFEST)
    # Seeded from what's already known, not empty: every write below must
    # only ever update the keys this run actually reconciled, never truncate
    # every other kind's last-known-good identities to nothing just because
    # this run has not (yet, or ever) touched them.
    manifest_out = dict(manifest_in) if manifest_in is not None else {}

    def flush():
        write_manifest(MANIFEST, manifest_out)

    pending = manifest_out.get(_APPLY_PENDING)
    applied = False
    sid = login()
    try:
        groups = discover_groups(GROUPS_DIR)
        name_to_id, collided_groups = reconcile_groups(
            sid, [name for name, _ in groups], allow_remove=groups_readable,
            known=known_identities(manifest_in, "groups", MANAGED),
            record=manifest_out, flush=flush)
        # A collided group's directory is not this run's to write into; its
        # config stays undeployed (drift) rather than landing in someone
        # else's group.
        groups = [(name, path) for name, path in groups
                 if name not in collided_groups]

        # Allowlists apply network-wide (default group only). Local and fetched
        # entries reconcile separately, under distinct comments: allow.list's
        # own entries must remove on their own say-so, not on whether a URL
        # elsewhere in allowlist-urls.txt happened to load this run, and the
        # two must never be able to mistake one set for the other's rows.
        local_allow_exact, allow_regex = split_allow(read_file("allow.list"))
        local_readable = "allow.list" not in absent
        reconcile_membership(
            sid, allow_kind("exact"), network_wide(local_allow_exact),
            allow_remove=local_readable, record=manifest_out, flush=flush,
            known=known_identities(manifest_in, "allow/exact", MANAGED))
        reconcile_membership(
            sid, allow_kind("regex"), network_wide(allow_regex),
            allow_remove=local_readable, record=manifest_out, flush=flush,
            known=known_identities(manifest_in, "allow/regex", MANAGED))

        fetched, fetched_ok = [], "allowlist-urls.txt" not in absent
        for url in read_file("allowlist-urls.txt"):
            domains, ok = fetch_domains(url)
            fetched += domains
            fetched_ok = fetched_ok and ok
        reconcile_membership(
            sid, allow_kind("exact"), network_wide(fetched),
            allow_remove=fetched_ok, comment=MANAGED_FETCHED, record=manifest_out,
            flush=flush,
            known=known_identities(manifest_in, "allow/exact", MANAGED_FETCHED))

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
        reconcile_membership(
            sid, ADLIST, desired["adlists"], record=manifest_out, flush=flush,
            allow_remove="adlists.txt" not in absent and groups_readable,
            known=known_identities(manifest_in, ADLIST.label, MANAGED))
        reconcile_membership(
            sid, deny_kind("exact"), desired["deny_exact"],
            allow_remove=groups_readable, record=manifest_out, flush=flush,
            known=known_identities(manifest_in, "deny/exact", MANAGED))
        reconcile_membership(
            sid, deny_kind("regex"), desired["deny_regex"],
            allow_remove=groups_readable, record=manifest_out, flush=flush,
            known=known_identities(manifest_in, "deny/regex", MANAGED))
        reconcile_membership(
            sid, CLIENT, desired["clients"], record=manifest_out, flush=flush,
            allow_remove=groups_readable,
            known=known_identities(manifest_in, CLIENT.label, MANAGED))

        apply_changes(sid, apply_needed(changed, pending))
        applied = True

        print("CHANGED" if any(changed.values()) or pending else "no changes")
    finally:
        # Whatever stopped this run -- a failed apply, or a later reconcile
        # step dying after earlier writes landed -- leaves those writes on the
        # box unapplied, and the next run would see no drift to act on.
        need = None if applied else apply_needed(changed, pending)
        if need != pending:
            if need:
                manifest_out[_APPLY_PENDING] = need
            else:
                manifest_out.pop(_APPLY_PENDING, None)
            flush()
        logout(sid)

    # Everything appliable has been applied; fail loudly so a hand-added collision
    # isn't left silently unmanaged.
    if collisions:
        print(f"ERROR: {len(collisions)} entr{'y' if len(collisions) == 1 else 'ies'} "
              "skipped due to hand-added collisions (see warnings above)",
              file=sys.stderr)
        sys.exit(1)


# Thin shell around group_paths_to_prune for main.yml's group-prune task: the
# two file lists come from two separate `find` results (one local, one on the
# box) that Ansible already has in memory, so this reads them off stdin as
# JSON rather than re-discovering them, and hands back the prune list the
# same way.
def _prune_groups_cli():
    payload = json.load(sys.stdin)
    result = group_paths_to_prune(
        payload["source"], payload["deployed"],
        payload["source_root"], payload["deployed_root"])
    json.dump(result, sys.stdout)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "prune-groups":
        _prune_groups_cli()
    else:
        main()
