#!/usr/bin/env python3
"""Mirror what Pi-hole is holding back into the config files as code.

The reconciler (pihole_deploy.py) pushes config files into Pi-hole and
deliberately leaves entries added by hand in the admin UI alone. Those entries
are real configuration that no file records, so a rebuild from a fresh SD card
loses them. Mirroring closes that loop: it reads live state through the FTL API
and works out which config file each entry belongs in, so the change becomes
reviewable in `git diff` and survives the next rebuild.

Mirror, not gather: a file this owns ends up listing what the box holds, so an
entry deleted in the admin UI leaves the file too. Nothing else would take it
out, and the next reconcile would put it back from the file that still named
it — which is how deleting in the UI used to mean editing a file by hand.

Faithfulness is the rule an entry has to pass to be routed: reconciling from the
file it would land in reproduces that entry's current group set exactly. The
config format cannot say everything the UI can — an allowlist entry scoped to
one group, a device outside the default group, a disabled row — and routing
those anyway would change what Pi-hole blocks. They are reported instead, named
with the reason, so the decision stays with the person reading the report.

Shares MANAGED, DEFAULT_GROUP and normalize_groups with the reconciler by
importing them: the two scripts are halves of one ownership contract, and a
second definition of "managed" could drift out of agreement with the first.

Structure: plan_mirror and the helpers below are pure and unit-tested;
everything touching the network or filesystem is the thin shell beneath them.
"""
import argparse
import json
import os
import sys
from enum import Enum
from typing import NamedTuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pihole_deploy as deploy  # noqa: E402
from pihole_deploy import (  # noqa: E402
    DEFAULT_GROUP,
    MANAGED,
    clean_lines,
    is_regex,
    normalize_groups,
)


class Kind(str, Enum):
    """Every kind of row the config format knows a rule for.

    Closed on purpose. Routing used to dispatch on substrings of a plain string
    and reach the device rule by falling off the end, so a domain type a later
    FTL adds was written into a group's clients.txt as if it were a device. A
    kind outside this set now has no branch to fall into and is reported.

    A str mixin so a Kind is its own wire format: it survives the JSON round
    trip between --plan-adopt and --adopt and compares equal to the string it
    comes back as. __str__ and __format__ are pinned to the value because a
    plain Enum spells itself "Kind.ADLIST" in an f-string, and these names end
    up in the report a person reads.
    """
    ADLIST = "adlist"
    ALLOW_ADLIST = "allow adlist"
    ALLOW_EXACT = "allow/exact"
    ALLOW_REGEX = "allow/regex"
    DENY_EXACT = "deny/exact"
    DENY_REGEX = "deny/regex"
    CLIENT = "client"

    def __str__(self):
        return self.value

    __format__ = str.__format__


# The shape a domain kind claims. The config files carry no exact/regex marker,
# so this is what an entry's own text has to agree with to round-trip.
_SHAPE = {Kind.ALLOW_EXACT: "exact", Kind.ALLOW_REGEX: "regex",
          Kind.DENY_EXACT: "exact", Kind.DENY_REGEX: "regex"}

# How the reconciler addresses one row of each kind. Borrowed rather than
# rebuilt, so the two cannot disagree about a URL. Allow adlists are absent:
# the config has no file for them, so one is never routed and never adopted.
_ITEM_PATH = {Kind.ADLIST: deploy.ADLIST,
              Kind.CLIENT: deploy.CLIENT,
              Kind.ALLOW_EXACT: deploy.allow_kind("exact"),
              Kind.ALLOW_REGEX: deploy.allow_kind("regex"),
              Kind.DENY_EXACT: deploy.deny_kind("exact"),
              Kind.DENY_REGEX: deploy.deny_kind("regex")}


class Entry(NamedTuple):
    """A live Pi-hole row reduced to what ownership turns on.

    Identity (kind, entry) plus every field a config file asserts about the
    row. Adoption re-checks the whole record against live state, so a field
    named here is re-checked without anyone remembering to compare it — which
    is what comparing the group set by hand failed to do for `enabled`. A field
    added here is covered by that check the moment it exists.

    groups is a sorted tuple rather than a set so a record compares by value
    and survives the JSON round trip between deciding and doing.
    """
    kind: str
    entry: str
    groups: tuple
    enabled: bool


class Plan(NamedTuple):
    """What mirroring live state would write.

    files:      config path (relative to the config root) -> the entries the box
                holds for that path, which is what the file should end up
                listing: every live row it routes, whoever added them
    group_dirs: group directories the config tree needs, sorted
    unroutable: (entry label, why the config format cannot express it)
    routed:     (Entry, config paths) per hand-added entry — what adoption needs,
                and what `files` alone cannot say, since two entries of
                different kinds can share a name across files
    protected:  entries the box holds that no file rule places. They exist, so a
                line carrying one is never pruned wherever it already sits.
    """
    files: dict
    group_dirs: list
    unroutable: list
    routed: list
    # Defaults describe a plan that knows of nothing to protect, so a caller
    # building one by hand cannot delete by omission.
    protected: frozenset = frozenset()


_UNUSABLE_GROUP_NAMES = {"", ".", ".."}


def is_group_dir_name(name):
    """True if a group name can be the directory the config represents it as.

    The admin UI takes free text for a group name, while the config gives each
    group a directory under groups/. A name carrying a path separator would put
    the file outside the config root entirely, and one the reconciler could
    never rediscover, since it only enumerates top-level directories there.
    """
    return name not in _UNUSABLE_GROUP_NAMES and not set(name) & {"/", "\\"}


def round_trips(entry):
    """True if a config file can carry this entry and give it back unchanged.

    The files use '#' for comments and ignore surrounding whitespace, so an
    entry containing either comes back as something else — and, because
    presence is judged after that stripping, would be appended afresh by every
    mirror run while the reconciler pushed the truncated form.
    """
    return clean_lines(entry) == [entry]


def shape_matches(kind, entry):
    """True if the config file would give a domain entry back as the same kind.

    allow.list and block.list carry no exact/regex marker: the reconciler
    re-derives it from the text. A regex without metacharacters ("doubleclick")
    would come back as an exact match that no longer covers subdomains, and an
    exact entry that reads as a pattern would come back as a regex.
    """
    return _SHAPE[kind] == ("regex" if is_regex(entry) else "exact")


def _paths_for(e, id_to_name):
    """(config paths, reason) for one live entry.

    Exactly one of the two is meaningful: a reason means the entry is not
    routable and no path is returned. The per-kind rules mirror what
    assemble_desired builds, which is what makes a routed entry faithful.
    """
    kind, entry, gids = e.kind, e.entry, e.groups
    if not isinstance(kind, Kind):
        return [], (f"the config format has no rule for a {kind} entry, so "
                    "there is no file this mirror could put it in")
    if kind is Kind.ALLOW_ADLIST:
        return [], ("the config has no file for allow adlists; "
                    "allowlist-urls.txt fetches domains to allow, which is a "
                    "different mechanism")
    unknown = sorted(g for g in gids if g not in id_to_name)
    if unknown:
        return [], (f"belongs to group id {unknown[0]}, which no longer exists; "
                    "delete the entry or recreate the group")
    unusable = sorted(id_to_name[g] for g in gids
                      if g != DEFAULT_GROUP and not is_group_dir_name(id_to_name[g]))
    if unusable:
        return [], ("it is in " + ", ".join(repr(n) for n in unusable)
                    + ", which cannot be a directory name")
    named = sorted(id_to_name[g] for g in gids if g != DEFAULT_GROUP)
    in_default = DEFAULT_GROUP in gids

    if kind in _SHAPE and not shape_matches(kind, entry):
        derived = "regex" if is_regex(entry) else "exact"
        return [], (f"the config files carry no exact/regex marker and this "
                    f"{_SHAPE[kind]} entry reads as {derived}, so the "
                    f"reconciler would push it back as {derived}")

    if kind is Kind.ADLIST:
        paths = ["adlists.txt"] if in_default else []
        return paths + [f"groups/{n}/adlists.txt" for n in named], None

    if kind in (Kind.ALLOW_EXACT, Kind.ALLOW_REGEX):
        if named:
            return [], ("allowlists in the config apply network-wide, and this one "
                        + ("is also in " if in_default else "is scoped to ")
                        + ", ".join(named))
        return ["allow.list"], None

    if kind in (Kind.DENY_EXACT, Kind.DENY_REGEX):
        if in_default and named:
            return [], ("this blocks network-wide as well as for "
                        + ", ".join(named) + ", and the config blocks domains per "
                        "group; recording it would stop blocking it for everyone else")
        if in_default:
            return [], ("the config blocks domains per group and has no "
                        "network-wide blocklist; add the domain to each group that "
                        "should block it, or leave it to the adlists")
        return [f"groups/{n}/block.list" for n in named], None

    # Kind.CLIENT — the only one left, because the enum is closed.
    if not in_default:
        return [], ("the config puts a device in its group and the default group; "
                    "this one is outside the default group, so recording it would "
                    "add the default group's blocklists to it")
    if not named:
        return [], ("the config describes a device only by the group it joins, and "
                    "this one is in the default group alone")
    return [f"groups/{n}/clients.txt" for n in named], None


def _rows(state):
    """(Entry, whether the reconciler already owns it) for every live row.

    The one place the raw API shape is read, so the record every later decision
    compares is built the same way whether it came from a mirror run or from the
    second look adoption takes.
    """
    def make(kind, field, row):
        return (Entry(kind, row[field],
                      tuple(sorted(normalize_groups(row.get("groups", [])))),
                      bool(row.get("enabled", True))),
                row.get("comment") == MANAGED)

    for row in state.get("lists", []):
        yield make(Kind.ADLIST, "address", row)
    for row in state.get("allow_lists", []):
        yield make(Kind.ALLOW_ADLIST, "address", row)
    for row in state.get("domains", []):
        yield make(_domain_kind(row), "domain", row)
    for row in state.get("clients", []):
        yield make(Kind.CLIENT, "client", row)


def _domain_kind(row):
    """The Kind of a domain row, or FTL's own words for it if there is no rule.

    Returned as the plain string it arrived as rather than coerced into a Kind
    it does not match, so routing reports it instead of falling into whichever
    rule happens to be reached last.
    """
    described = f"{row['type']}/{row['kind']}"
    try:
        return Kind(described)
    except ValueError:
        return described


def plan_mirror(state):
    """Route every live entry to the config file that should list it (pure).

    `state` is the raw API shape: {"groups", "lists", "domains", "clients"}.

    Every live row is routed, not just the hand-added ones, because the files
    are meant to say what the box holds — so an entry deleted in the admin UI
    has to leave the file it was in, or the next reconcile would put it straight
    back. Rows the reconciler already owns are routed silently: they came from
    these files, and site.yml is what corrects them. Only the hand-added ones
    are reported when they cannot be expressed, since those are the ones whose
    author is still waiting to hear whether their change was captured.
    """
    id_to_name = {g["id"]: g["name"] for g in state.get("groups", [])}
    files, unroutable, routed, touched = {}, [], [], set()
    protected = set()

    for e, managed in _rows(state):
        if managed:
            paths, reason = _paths_for(e, id_to_name)
            # It exists, so whatever the files say about it, nothing may delete
            # the line that carries it on the strength of it being absent.
            if reason:
                protected.add(e.entry)
            else:
                for path in paths:
                    files.setdefault(path, set()).add(e.entry)
            continue
        label = f"{e.kind} {e.entry}"
        if not e.enabled:
            protected.add(e.entry)
            unroutable.append((label, "it is disabled, and the config adds every "
                                      "entry enabled"))
            continue
        if not round_trips(e.entry):
            protected.add(e.entry)
            unroutable.append((label, "a config file cannot carry it unchanged: "
                                      "'#' starts a comment there and surrounding "
                                      "whitespace is stripped"))
            continue
        paths, reason = _paths_for(e, id_to_name)
        if reason:
            protected.add(e.entry)
            unroutable.append((label, reason))
            continue
        for path in paths:
            files.setdefault(path, set()).add(e.entry)
        routed.append((e, sorted(paths)))
        touched |= {id_to_name[g] for g in e.groups if g != DEFAULT_GROUP}

    # A group made by hand needs a directory too, even with nothing in it yet:
    # it is configuration the files don't record either. One whose name cannot
    # be a directory is reported instead, whether or not anything is in it.
    for group in state.get("groups", []):
        name = group["name"]
        if group["id"] == DEFAULT_GROUP:
            continue
        if not is_group_dir_name(name):
            unroutable.append((f"group {name!r}",
                               "it cannot be a directory name, and the config "
                               "gives each group a directory under groups/"))
        elif group.get("comment") != MANAGED:
            touched.add(name)
    return Plan(files={p: sorted(v) for p, v in files.items()},
                group_dirs=sorted(touched), unroutable=unroutable, routed=routed,
                protected=protected)


def merge_lines(existing, wanted, prune=False):
    """Config file text listing `wanted`, or None if it already did.

    Comments, blank lines and the file's own ordering survive byte for byte —
    they carry the instructions a person reads when editing by hand, and the
    order is theirs to choose — so new entries append at the end and the rest
    stay where they are. What counts as an entry is judged the way the
    reconciler reads the file (clean_lines), so a commented-out example is not
    one: it is neither already present nor a candidate for removal.

    With prune, a line carrying an entry the box no longer holds is dropped —
    which is how deleting something in the admin UI reaches the files instead of
    being undone by the next reconcile. Returning None for an unchanged file
    keeps a mirror run that found nothing out of `git diff`.
    """
    wanted_set = set(wanted)
    kept, present, dropped = [], set(), False
    for line in existing.splitlines():
        entries = clean_lines(line)
        if not entries:  # a comment or a blank: not an entry, so not ours to cut
            kept.append(line)
            continue
        if prune and entries[0] not in wanted_set:
            dropped = True
            continue
        kept.append(line)
        present.add(entries[0])

    add = [ln for ln in dict.fromkeys(wanted) if ln not in present]
    if not add and not dropped:
        return None
    return "".join(ln + "\n" for ln in kept + add)


def plan_adopt(routed, present):
    """The entries the reconciler can safely be given ownership of.

    Adoption is what ends the collision a captured entry still causes: the row
    keeps its groups and its place in Pi-hole and only changes hands. The
    condition is that every config file the entry routed into already lists it —
    a half-recorded entry handed over would be reconciled down to what the files
    do say, silently narrowing its group set, or deleted outright when no file
    asks for it at all. The whole record travels with the decision so that
    whoever carries it out can tell the row has not changed since.
    """
    return sorted(e for e, paths in routed
                  if all(e.entry in present.get(path, ()) for path in paths))


class Skipped(NamedTuple):
    """A planned entry that was not handed over, and whether that is a problem.

    stale says the plan no longer describes the box, which is what makes the run
    exit non-zero and asks for another mirror run. A row the reconciler already
    owns is not stale — that is a repeat run finding its work done. Carried as a
    field because the exit status once turned on a substring of `reason`, so
    rewording the sentence would have failed every repeat `just adopt`.
    """
    entry: Entry
    reason: str
    stale: bool


def adoptable_now(planned, state):
    """(ready, [Skipped]) for the plan against a second look at live state.

    Deciding and doing are separated by a round trip, and the admin UI stays
    open throughout. A row edited in between no longer matches the config files
    the decision was made from, so handing it over would misrepresent it exactly
    as plan_adopt refuses to: regrouped, it would be reconciled down to the
    file's group set; switched off, it would be stamped as the reconciler's
    while off. Whole-record equality covers both, and whatever Entry gains next.

    What was left alone is returned with it rather than dropped, so a run that
    handed over nothing it planned cannot look like one that worked.
    """
    live, owned = {}, set()
    for e, managed in _rows(state):
        live[(e.kind, e.entry)] = e
        if managed:
            owned.add((e.kind, e.entry))

    ready, skipped = [], []
    for e in planned:
        key = (e.kind, e.entry)
        if key in owned:
            skipped.append(Skipped(e, "the reconciler already owns it", False))
        elif key not in live:
            skipped.append(Skipped(e, "it is no longer on the box", True))
        elif live[key] != e:
            skipped.append(Skipped(e, "it has changed since the plan was made "
                                      f"(live state is groups {list(live[key].groups)}, "
                                      f"enabled {live[key].enabled})", True))
        else:
            ready.append(e)
    return ready, skipped


# ── I/O shell ───────────────────────────────────────────────────────────────
# Each API collection is keyed in the response by the same name we store it
# under, so one table drives both the fetch and the shape plan_mirror reads.
# (state key, API path, key in the response). Block and allow adlists share one
# response key, so the state key has to differ from it for the two to coexist.
COLLECTIONS = (("groups", "/groups", "groups"),
               ("lists", "/lists?type=block", "lists"),
               ("allow_lists", "/lists?type=allow", "lists"),
               ("domains", "/domains", "domains"),
               ("clients", "/clients", "clients"))


def _fetch(sid):
    state = {}
    for key, path, response_key in COLLECTIONS:
        st, body = deploy.api("GET", path, sid)
        if st != 200:
            deploy.die(f"GET {path} failed (HTTP {st}): {body}")
        state[key] = body.get(response_key, [])
    return state


def export_state():
    """Live FTL state as the four raw API collections.

    Exporting raw state rather than a finished plan keeps the routing rules on
    the controller, in the repo: changing how an entry is captured is then a
    repo edit, not a redeploy of the box's copy of this script. It also gives
    the drift check the managed entries, which a plan drops.
    """
    sid = deploy.login()
    try:
        return _fetch(sid)
    finally:
        deploy.logout(sid)


def _item_path(e):
    """The single-entry API path for one row, as the reconciler addresses it."""
    return _ITEM_PATH[e.kind].item_path(e.entry)


def adopt_entries(planned):
    """Hand the planned rows over; return (handed over, [(entry, why not)]).

    Ownership changes by rewriting the comment, not by deleting and re-adding:
    the row stays where it is, so there is no window in which a blocked domain
    resolves and no gravity rebuild to sit through. Groups and enabled state go
    back as the plan recorded them — the owner is the only thing that moves, and
    adoptable_now has just confirmed live state still says the same. Which rows
    qualify is decided against a fresh look at live state, so this is safe to
    repeat and safe to run against a box edited since the plan.
    """
    sid = deploy.login()
    try:
        adopted = []
        ready, skipped = adoptable_now(planned, _fetch(sid))
        for e in ready:
            body = {"comment": MANAGED, "groups": list(e.groups)}
            if e.kind is not Kind.CLIENT:  # clients carry no enabled column
                body["enabled"] = e.enabled
            st, resp = deploy.api("PUT", _item_path(e), sid, body)
            if st not in (200, 201, 204):
                deploy.die(f"adopting {e.kind} {e.entry!r} failed (HTTP {st}): {resp}")
            adopted.append(e)
        return adopted, skipped
    finally:
        deploy.logout(sid)


def entries_to_json(entries):
    """Entry records as JSON-ready dicts, for --plan-adopt to hand to --adopt.

    Kept next to entries_from_json: the two are one boundary, and a plan that
    cannot be read back is a plan that adopts nothing while reporting success.
    """
    return [e._asdict() for e in entries]


def entries_from_json(data):
    """Entry records from the JSON --plan-adopt wrote.

    Rebuilt as the types it was written from, not merely as things that compare
    equal to them: group ids come back as a list, which no record would match,
    and the kind comes back as a bare string, which answers no to the `is` the
    shell asks of it. Named fields rather than position so a plan written by an
    older copy of this script fails loudly here instead of landing its fields in
    the wrong slots — as does a kind this script has no rule for.
    """
    return [Entry(**{**d, "kind": Kind(d["kind"]), "groups": tuple(d["groups"])})
            for d in data]


def read_json(source):
    """JSON from a file, or from stdin when source is '-'."""
    if source == "-":
        return json.load(sys.stdin)
    with open(source, encoding="utf-8") as f:
        return json.load(f)


def read_present(root, paths):
    """path -> the entries each config file records, read as the reconciler does.

    A commented-out line is not an entry, here or there; agreeing on that is
    what makes "the file already records it" mean the same thing to both.
    """
    present = {}
    for path in paths:
        full = os.path.join(root, path)
        text = ""
        if os.path.exists(full):
            with open(full, encoding="utf-8") as f:
                text = f.read()
        present[path] = set(clean_lines(text))
    return present


# The config files the mirror routes live entries into, and so the only ones it may
# prune. allowlist-urls.txt is deliberately absent: it names remote lists to
# fetch rather than entries Pi-hole holds, so no live row corresponds to a line
# in it and every one of them would look deleted.
_OWNED_FILES = ("adlists.txt", "allow.list")
_OWNED_GROUP_FILES = ("adlists.txt", "block.list", "clients.txt")


def owned_config_files(root):
    """The existing config files the mirror both writes and prunes, sorted.

    Pruning has to visit a file even when live state routes nothing to it: a
    file whose every entry was deleted in the admin UI is exactly the one with
    no live entries left, and skipping it would make the last deletion the one
    that never gets captured.
    """
    found = [n for n in _OWNED_FILES if os.path.isfile(os.path.join(root, n))]
    groups_dir = os.path.join(root, "groups")
    if os.path.isdir(groups_dir):
        for name in sorted(os.listdir(groups_dir)):
            found += [rel for rel in (f"groups/{name}/{f}"
                                      for f in _OWNED_GROUP_FILES)
                      if os.path.isfile(os.path.join(root, rel))]
    return sorted(found)


def box_holds_any_of(plan, path, listed):
    """True if the box still holds at least one entry this config file lists.

    An entry a file lists and the box does not hold means one of two opposite
    things — someone deleted it, or this box was never given it — and reading
    the second as the first is what empties a config in one run. The two look
    identical entry by entry, but not file by file: a box that ever took this
    file still holds something from it, while a box that never did holds none
    of it. Ownership is deliberately not consulted, because the comment that
    records it is free text an operator can type in the admin UI.
    """
    return bool(set(plan.files.get(path, ())) & listed)


def removed_counts(root, pending):
    """path -> how many entries the new text drops, read before it is written.

    Comments and blank lines survive a prune untouched, so a section that has
    lost every entry keeps its heading and goes on describing what is no longer
    below it. The file cannot say that; the report can, and a reviewer reading
    `git diff` has the number rather than having to count the minus lines.
    """
    counts = {}
    for path, text in pending:
        full = os.path.join(root, path)
        old = set()
        if os.path.exists(full):
            with open(full, encoding="utf-8") as f:
                old = set(clean_lines(f.read()))
        gone = len(old - set(clean_lines(text)))
        if gone:
            counts[path] = gone
    return counts


def refused_prunes(root, plan):
    """[(path, how many entries)] for each file whose deletions were declined.

    Named rather than passed over in silence: the operator is owed the
    difference between "the files now match the box" and "the files claim
    things this box has never been told about", and only one of those is
    fixed by committing the diff.
    """
    refused = []
    for path in sorted(set(plan.files) | set(owned_config_files(root))):
        full = os.path.join(root, path)
        if not os.path.exists(full):
            continue
        with open(full, encoding="utf-8") as f:
            listed = set(clean_lines(f.read()))
        if box_holds_any_of(plan, path, listed):
            continue
        absent = listed - set(plan.files.get(path, ())) - plan.protected
        if absent:
            refused.append((path, len(absent)))
    return refused


def pending_changes(root, plan, force_prune=False):
    """[(path, new text)] for every config file the plan would alter.

    Deciding and writing are separate so the drift check can ask what a mirror
    would capture while leaving the working tree exactly as it found it. A file
    that already lists exactly what the box holds is absent from the result,
    which is what keeps an unchanged mirror run out of `git diff`.
    """
    pending = []
    for path in sorted(set(plan.files) | set(owned_config_files(root))):
        full = os.path.join(root, path)
        existing = ""
        if os.path.exists(full):
            with open(full, encoding="utf-8") as f:
                existing = f.read()
        # A protected entry stays only where it already is: it exists on the box
        # but no rule places it, so keeping the line is right and adding one
        # would be inventing a placement the routing declined to choose.
        listed = set(clean_lines(existing))
        wanted = set(plan.files.get(path, ()))
        wanted |= plan.protected & listed
        merged = merge_lines(existing, sorted(wanted),
                             prune=force_prune
                             or box_holds_any_of(plan, path, listed))
        if merged is not None:
            pending.append((path, merged))
    return pending


def write_changes(root, pending):
    """Write pending changes out; return the paths written."""
    for path, text in pending:
        full = os.path.join(root, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(text)
    return [path for path, _ in pending]


def groups_without_config(root, plan):
    """Group names the config tree says nothing about, sorted.

    A group earns a directory by having a file in it, and git does not track an
    empty directory — so a group with nothing to write is named in the report
    rather than turned into a directory git would drop. Asking the plan what it
    is about to write, not the disk what exists, keeps the answer the same
    whether or not the caller goes on to write.
    """
    with_files = {path.split("/")[1] for path in plan.files
                  if path.startswith("groups/")}
    return [n for n in plan.group_dirs if n not in with_files
            and not os.path.isdir(os.path.join(root, "groups", n))]


# Exit statuses. A verdict and a run that never got started have to be different
# values: gating on "did it say DRIFT" let a check that crashed read as a clean
# one, since both leave the same empty stdout. The low numbers are left to the
# ways this script can fail before deciding anything — 1 is Python's own
# uncaught-error status and 2 is argparse's usage error — so no verdict can be
# mistaken for one of them, or one of them for a verdict.
OK = 0            # nothing left unrecorded
DRIFT = 3         # settings a mirror run would capture are missing from the files
UNRECORDABLE = 4  # what is left is only what the config format cannot express
UNPRUNED = 5      # a file lists entries, and the box holds none of them


def report(root, plan, paths, dry_run, refused=(), removed=None):
    """Print what was captured (or would be) and what needs a human decision.

    `refused` comes from the caller because it has to be read before anything
    is written: once a file has gained the entries this run captured, the box
    holds one of the lines in it and the evidence reads the other way.

    Returns the exit status (OK / DRIFT / UNRECORDABLE / UNPRUNED above). The non-zero
    ones are kept apart because they call for different things: drift has a fix
    — run a mirror — while a setting the config cannot express has none, and a
    check that stays red for something unfixable is one people learn to ignore.
    Under dry_run an uncaptured change is drift; capturing it is a success.
    """
    removed = removed or {}
    for path in paths:
        gone = removed.get(path)
        tail = f" ({gone} removed)" if gone else ""
        print(("  ! " if dry_run else "  ~ ") + path + tail)

    for label, reason in plan.unroutable:
        print(f"WARN: {label} was not captured: {reason}.", file=sys.stderr)

    for path, count in refused:
        print(f"WARN: {path} lists {count} entr"
              f"{'y' if count == 1 else 'ies'} this Pi-hole does not hold, and "
              "holds nothing else this file lists — so they were never deleted "
              "here, and were left alone. Deploy first, or pass --force-prune "
              "if you did delete them all.", file=sys.stderr)

    empty = groups_without_config(root, plan)
    for name in empty:
        print(f"WARN: group {name!r} exists in Pi-hole but has no config; add "
              f"groups/{name}/ with a block.list and clients.txt to manage it.",
              file=sys.stderr)

    if dry_run:
        print("DRIFT" if paths else "in sync")
    else:
        print("CHANGED" if paths else "no changes")
    unrecordable = len(plan.unroutable) + len(empty)
    # Counted apart because they are different things: one is a number of files
    # a mirror run would write, the other a number of settings it cannot.
    parts = []
    if dry_run and paths:
        parts.append(f"{len(paths)} config file(s) a mirror run would write")
    if unrecordable:
        parts.append(f"{unrecordable} setting(s) no config file can record")
    if parts:
        # ERROR only when the status says so. Settings the config cannot express
        # exit UNRECORDABLE, which verify passes on deliberately — calling that
        # an error is how a green check ends up printing one, which is the habit
        # of ignoring the check, taught.
        level = "ERROR" if (dry_run and paths) else "WARN"
        print(f"{level}: " + ", and ".join(parts) + " (see warnings above)",
              file=sys.stderr)
    if dry_run and paths:
        return DRIFT
    if unrecordable:
        return UNRECORDABLE
    return UNPRUNED if refused else OK


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--export", action="store_true",
                      help="print live Pi-hole state as JSON (run on the Pi-hole host)")
    mode.add_argument("--merge", metavar="STATE",
                      help="capture the state in this JSON file ('-' for stdin) "
                           "into the config files under --dir")
    mode.add_argument("--check", metavar="STATE",
                      help="report what capturing this state would change, "
                           "without writing anything")
    mode.add_argument("--plan-adopt", metavar="STATE",
                      help="print the entries in this state that the config files "
                           "under --dir already record, as JSON")
    mode.add_argument("--adopt", metavar="ENTRIES",
                      help="hand the entries in this JSON file ('-' for stdin) to "
                           "the reconciler (run on the Pi-hole host)")
    parser.add_argument("--force-prune", action="store_true",
                        help="drop entries the box does not hold even from files "
                             "it holds nothing of (use when everything in a file "
                             "really was deleted in the admin UI)")
    parser.add_argument("--dir", default=".", metavar="DIR",
                        help="config root to write into (default: current directory)")
    args = parser.parse_args(argv)

    if args.export:
        json.dump(export_state(), sys.stdout)
        print()
        return OK
    if args.adopt:
        adopted, skipped = adopt_entries(entries_from_json(read_json(args.adopt)))
        for e in adopted:
            print(f"  ~ {e.kind} {e.entry}")
        for s in skipped:
            print(f"WARN: {s.entry.kind} {s.entry.entry} was not handed over: "
                  f"{s.reason}.", file=sys.stderr)
        print("CHANGED" if adopted else "no changes")
        stale = [s for s in skipped if s.stale]
        if stale:
            print(f"ERROR: {len(stale)} planned entr"
                  f"{'y' if len(stale) == 1 else 'ies'} no longer match the box; "
                  "run `just mirror` again", file=sys.stderr)
        return DRIFT if stale else OK
    plan = plan_mirror(read_json(args.merge or args.check or args.plan_adopt))
    if args.plan_adopt:
        paths = {path for _, paths in plan.routed for path in paths}
        planned = plan_adopt(plan.routed, read_present(args.dir, paths))
        json.dump(entries_to_json(planned), sys.stdout)
        print()
        return OK
    pending = pending_changes(args.dir, plan, force_prune=args.force_prune)
    refused = () if args.force_prune else refused_prunes(args.dir, plan)
    removed = removed_counts(args.dir, pending)
    if args.check:
        return report(args.dir, plan, [path for path, _ in pending],
                      dry_run=True, refused=refused, removed=removed)
    return report(args.dir, plan, write_changes(args.dir, pending),
                  dry_run=False, refused=refused, removed=removed)


if __name__ == "__main__":
    sys.exit(main())
