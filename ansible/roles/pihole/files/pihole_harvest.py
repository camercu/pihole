#!/usr/bin/env python3
"""Capture hand-made Pi-hole changes back into the config files as code.

The reconciler (pihole_sync_lists.py) pushes config files into Pi-hole and
deliberately leaves entries added by hand in the admin UI alone. Those entries
are real configuration that no file records, so a rebuild from a fresh SD card
loses them. Harvest closes that loop: it reads live state through the FTL API
and works out which config file each hand-added entry belongs in, so the change
becomes reviewable in `git diff` and survives the next rebuild.

Faithfulness is the rule an entry has to pass to be routed: reconciling from the
file it would land in reproduces that entry's current group set exactly. The
config format cannot say everything the UI can — an allowlist entry scoped to
one group, a device outside the default group, a disabled row — and routing
those anyway would change what Pi-hole blocks. They are reported instead, named
with the reason, so the decision stays with the person reading the report.

Shares MANAGED, DEFAULT_GROUP and normalize_groups with the reconciler by
importing them: the two scripts are halves of one ownership contract, and a
second definition of "managed" could drift out of agreement with the first.

Structure: plan_harvest and the helpers below are pure and unit-tested;
everything touching the network or filesystem is the thin shell beneath them.
"""
import argparse
import json
import os
import sys
from typing import NamedTuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pihole_sync_lists as sync  # noqa: E402
from pihole_sync_lists import (  # noqa: E402
    DEFAULT_GROUP,
    MANAGED,
    clean_lines,
    is_regex,
    normalize_groups,
)


class Plan(NamedTuple):
    """What harvesting live state would write.

    files:      config path (relative to the config root) -> lines to ensure present
    group_dirs: group directories the config tree needs, sorted
    unroutable: (entry label, why the config format cannot express it)
    routed:     (kind, entry, config paths, group ids) per captured entry — what
                adoption needs, and what `files` alone cannot say, since two
                entries of different kinds can share a name across files
    """
    files: dict
    group_dirs: list
    unroutable: list
    routed: list


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
    harvest while the reconciler pushed the truncated form.
    """
    return clean_lines(entry) == [entry]


def shape_matches(kind, entry):
    """True if the config file would give a domain entry back as the same kind.

    allow.list and block.list carry no exact/regex marker: the reconciler
    re-derives it from the text. A regex without metacharacters ("doubleclick")
    would come back as an exact match that no longer covers subdomains, and an
    exact entry that reads as a pattern would come back as a regex.
    """
    return kind.split("/")[1] == ("regex" if is_regex(entry) else "exact")


def _paths_for(kind, entry, gids, id_to_name):
    """(config paths, reason) for `entry` of `kind` in group ids `gids`.

    Exactly one of the two is meaningful: a reason means the entry is not
    routable and no path is returned. The per-kind rules mirror what
    assemble_desired builds, which is what makes a routed entry faithful.
    """
    if kind == "allow adlist":
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

    if "/" in kind and not shape_matches(kind, entry):
        derived = "regex" if is_regex(entry) else "exact"
        return [], (f"the config files carry no exact/regex marker and this "
                    f"{kind.split('/')[1]} entry reads as {derived}, so the "
                    f"reconciler would push it back as {derived}")

    if kind == "adlist":
        paths = ["adlists.txt"] if in_default else []
        return paths + [f"groups/{n}/adlists.txt" for n in named], None

    if kind.startswith("allow/"):
        if named:
            return [], ("allowlists in the config apply network-wide, and this one "
                        + ("is also in " if in_default else "is scoped to ")
                        + ", ".join(named))
        return ["allow.list"], None

    if kind.startswith("deny/"):
        if in_default and named:
            return [], ("this blocks network-wide as well as for "
                        + ", ".join(named) + ", and the config blocks domains per "
                        "group; recording it would stop blocking it for everyone else")
        if in_default:
            return [], ("the config blocks domains per group and has no "
                        "network-wide blocklist; add the domain to each group that "
                        "should block it, or leave it to the adlists")
        return [f"groups/{n}/block.list" for n in named], None

    if not in_default:
        return [], ("the config puts a device in its group and the default group; "
                    "this one is outside the default group, so recording it would "
                    "add the default group's blocklists to it")
    if not named:
        return [], ("the config describes a device only by the group it joins, and "
                    "this one is in the default group alone")
    return [f"groups/{n}/clients.txt" for n in named], None


def _rows(state):
    """(kind, label, entry, groups, enabled) for every entry in live state."""
    for row in state.get("lists", []):
        yield "adlist", row["address"], row
    for row in state.get("allow_lists", []):
        yield "allow adlist", row["address"], row
    for row in state.get("domains", []):
        yield f"{row['type']}/{row['kind']}", row["domain"], row
    for row in state.get("clients", []):
        yield "client", row["client"], row


def plan_harvest(state):
    """Route every hand-added entry in live FTL state to a config file (pure).

    `state` is the raw API shape: {"groups", "lists", "domains", "clients"}.
    Entries the reconciler already owns (comment == MANAGED) are skipped — they
    are in the files already, and writing them again would duplicate lines.
    """
    id_to_name = {g["id"]: g["name"] for g in state.get("groups", [])}
    files, unroutable, routed, touched = {}, [], [], set()

    for kind, entry, row in _rows(state):
        if row.get("comment") == MANAGED:
            continue
        label = f"{kind} {entry}"
        if not row.get("enabled", True):
            unroutable.append((label, "it is disabled, and the config adds every "
                                      "entry enabled"))
            continue
        if not round_trips(entry):
            unroutable.append((label, "a config file cannot carry it unchanged: "
                                      "'#' starts a comment there and surrounding "
                                      "whitespace is stripped"))
            continue
        gids = normalize_groups(row.get("groups", []))
        paths, reason = _paths_for(kind, entry, gids, id_to_name)
        if reason:
            unroutable.append((label, reason))
            continue
        for path in paths:
            files.setdefault(path, set()).add(entry)
        routed.append((kind, entry, sorted(paths), sorted(gids)))
        touched |= {id_to_name[g] for g in gids if g != DEFAULT_GROUP}

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
                group_dirs=sorted(touched), unroutable=unroutable, routed=routed)


def merge_lines(existing, new_lines):
    """Config file text with `new_lines` present, or None if it already was.

    Existing content is kept byte for byte — comments carry the instructions a
    person reads when editing the file by hand, and the file's own ordering is
    theirs to choose — so entries append at the end. Presence is judged the way
    the reconciler reads the file (clean_lines), which means a commented-out
    example does not count as present: a device really added in the UI has to
    become a live line. Returning None for an unchanged file keeps a harvest
    that found nothing out of `git diff`.
    """
    present = set(clean_lines(existing))
    add = [ln for ln in dict.fromkeys(new_lines) if ln not in present]
    if not add:
        return None
    prefix = existing if not existing or existing.endswith("\n") else existing + "\n"
    return prefix + "".join(ln + "\n" for ln in add)


def plan_adopt(routed, present):
    """(kind, entry, groups) the reconciler can safely be given ownership of.

    Adoption is what ends the collision a captured entry still causes: the row
    keeps its groups and its place in Pi-hole and only changes hands. The
    condition is that every config file the entry routed into already lists it —
    a half-recorded entry handed over would be reconciled down to what the files
    do say, silently narrowing its group set, or deleted outright when no file
    asks for it at all. The group set travels with the decision so that whoever
    carries it out can tell the entry has not moved since.
    """
    return sorted((kind, entry, groups) for kind, entry, paths, groups in routed
                  if all(entry in present.get(path, ()) for path in paths))


def adoptable_now(pairs, state):
    """(kind, entry, row) for planned entries that live state still matches.

    Deciding and doing are separated by a round trip, and the admin UI stays
    open throughout. An entry regrouped in between no longer matches the config
    files the decision was made from, so handing it over would narrow it exactly
    as plan_adopt refuses to — and one already owned needs nothing done.
    """
    planned = {(kind, entry): sorted(groups) for kind, entry, groups in pairs}
    ready = []
    for kind, entry, row in _rows(state):
        groups = planned.get((kind, entry))
        if groups is None or row.get("comment") == MANAGED:
            continue
        if sorted(normalize_groups(row.get("groups", []))) == groups:
            ready.append((kind, entry, row))
    return ready


# ── I/O shell ───────────────────────────────────────────────────────────────
# Each API collection is keyed in the response by the same name we store it
# under, so one table drives both the fetch and the shape plan_harvest reads.
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
        st, body = sync.api("GET", path, sid)
        if st != 200:
            sync.die(f"GET {path} failed (HTTP {st}): {body}")
        state[key] = body.get(response_key, [])
    return state


def export_state():
    """Live FTL state as the four raw API collections.

    Exporting raw state rather than a finished plan keeps the routing rules on
    the controller, in the repo: changing how an entry is captured is then a
    repo edit, not a redeploy of the box's copy of this script. It also gives
    the drift check the managed entries, which a plan drops.
    """
    sid = sync.login()
    try:
        return _fetch(sid)
    finally:
        sync.logout(sid)


def _item_path(kind, entry):
    """The single-entry API path for one row, as the reconciler addresses it."""
    if kind == "adlist":
        return sync.ADLIST.item_path(entry)
    if kind == "client":
        return sync.CLIENT.item_path(entry)
    type_, domain_kind = kind.split("/")
    build = sync.allow_kind if type_ == "allow" else sync.deny_kind
    return build(domain_kind).item_path(entry)


def adopt_entries(pairs):
    """Hand each (kind, entry) row to the reconciler; return the ones handed over.

    Ownership changes by rewriting the comment, not by deleting and re-adding:
    the row stays where it is, so there is no window in which a blocked domain
    resolves and no gravity rebuild to sit through. Groups and enabled state go
    back unchanged — the owner is the only thing that moves. Which rows qualify
    is decided against a fresh look at live state (see adoptable_now), so this
    is safe to repeat and safe to run against a box edited since the plan.
    """
    sid = sync.login()
    try:
        adopted = []
        for kind, entry, row in adoptable_now(pairs, _fetch(sid)):
            body = {"comment": MANAGED,
                    "groups": sorted(normalize_groups(row.get("groups", [])))}
            if kind != "client":
                body["enabled"] = row.get("enabled", True)
            st, resp = sync.api("PUT", _item_path(kind, entry), sid, body)
            if st not in (200, 201, 204):
                sync.die(f"adopting {kind} {entry!r} failed (HTTP {st}): {resp}")
            adopted.append((kind, entry))
        return adopted
    finally:
        sync.logout(sid)


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


def pending_changes(root, plan):
    """[(path, new text)] for every config file the plan would alter.

    Deciding and writing are separate so the drift check can ask what a harvest
    would capture while leaving the working tree exactly as it found it. A file
    whose entries are all recorded already is absent from the result, which is
    what keeps an unchanged harvest out of `git diff`.
    """
    pending = []
    for path in sorted(plan.files):
        full = os.path.join(root, path)
        existing = ""
        if os.path.exists(full):
            with open(full, encoding="utf-8") as f:
                existing = f.read()
        merged = merge_lines(existing, plan.files[path])
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


def report(root, plan, paths, dry_run):
    """Print what was captured (or would be) and what needs a human decision.

    Returns the exit status: non-zero while anything is left unrecorded, so an
    entry the config cannot express is noticed rather than quietly lost at the
    next rebuild. Under dry_run an uncaptured change counts as unrecorded too —
    that is the whole point of the check — whereas capturing it is a success.
    """
    for path in paths:
        print(("  ! " if dry_run else "  ~ ") + path)

    for label, reason in plan.unroutable:
        print(f"WARN: {label} was not captured: {reason}.", file=sys.stderr)

    empty = groups_without_config(root, plan)
    for name in empty:
        print(f"WARN: group {name!r} exists in Pi-hole but has no config; add "
              f"groups/{name}/ with a block.list and clients.txt to manage it.",
              file=sys.stderr)

    if dry_run:
        print("DRIFT" if paths else "in sync")
    else:
        print("CHANGED" if paths else "no changes")
    outstanding = len(plan.unroutable) + len(empty) + (len(paths) if dry_run else 0)
    if outstanding:
        print(f"ERROR: {outstanding} item(s) still unrecorded (see warnings above)",
              file=sys.stderr)
    return 1 if outstanding else 0


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
    parser.add_argument("--dir", default=".", metavar="DIR",
                        help="config root to write into (default: current directory)")
    args = parser.parse_args(argv)

    if args.export:
        json.dump(export_state(), sys.stdout)
        print()
        return 0
    if args.adopt:
        adopted = adopt_entries(read_json(args.adopt))
        for kind, entry in adopted:
            print(f"  ~ {kind} {entry}")
        print("CHANGED" if adopted else "no changes")
        return 0
    plan = plan_harvest(read_json(args.merge or args.check or args.plan_adopt))
    if args.plan_adopt:
        paths = {path for _, _, paths, _ in plan.routed for path in paths}
        json.dump(plan_adopt(plan.routed, read_present(args.dir, paths)), sys.stdout)
        print()
        return 0
    pending = pending_changes(args.dir, plan)
    if args.check:
        return report(args.dir, plan, [path for path, _ in pending], dry_run=True)
    return report(args.dir, plan, write_changes(args.dir, pending), dry_run=False)


if __name__ == "__main__":
    sys.exit(main())
