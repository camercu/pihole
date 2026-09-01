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
    normalize_groups,
)


class Plan(NamedTuple):
    """What harvesting live state would write.

    files:      config path (relative to the config root) -> lines to ensure present
    group_dirs: group directories the config tree needs, sorted
    unroutable: (entry label, why the config format cannot express it)
    """
    files: dict
    group_dirs: list
    unroutable: list


def _paths_for(kind, gids, id_to_name):
    """(config paths, reason) for an entry of `kind` in group ids `gids`.

    Exactly one of the two is meaningful: a reason means the entry is not
    routable and no path is returned. The per-kind rules mirror what
    assemble_desired builds, which is what makes a routed entry faithful.
    """
    unknown = sorted(g for g in gids if g not in id_to_name)
    if unknown:
        return [], (f"belongs to group id {unknown[0]}, which no longer exists; "
                    "delete the entry or recreate the group")
    named = sorted(id_to_name[g] for g in gids if g != DEFAULT_GROUP)
    in_default = DEFAULT_GROUP in gids

    if kind == "adlist":
        paths = ["adlists.txt"] if in_default else []
        return paths + [f"groups/{n}/adlists.txt" for n in named], None

    if kind.startswith("allow/"):
        if named:
            return [], ("allowlists in the config apply network-wide; this one is "
                        "scoped to " + ", ".join(named))
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
    files, unroutable, touched = {}, [], set()

    for kind, entry, row in _rows(state):
        if row.get("comment") == MANAGED:
            continue
        label = f"{kind} {entry}"
        if not row.get("enabled", True):
            unroutable.append((label, "it is disabled, and the config adds every "
                                      "entry enabled"))
            continue
        gids = normalize_groups(row.get("groups", []))
        paths, reason = _paths_for(kind, gids, id_to_name)
        if reason:
            unroutable.append((label, reason))
            continue
        for path in paths:
            files.setdefault(path, set()).add(entry)
        touched |= {id_to_name[g] for g in gids if g != DEFAULT_GROUP}

    # A group made by hand needs a directory too, even with nothing in it yet:
    # it is configuration the files don't record either.
    touched |= {g["name"] for g in state.get("groups", [])
                if g["id"] != DEFAULT_GROUP and g.get("comment") != MANAGED}
    return Plan(files={p: sorted(v) for p, v in files.items()},
                group_dirs=sorted(touched), unroutable=unroutable)


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


# ── I/O shell ───────────────────────────────────────────────────────────────
# Each API collection is keyed in the response by the same name we store it
# under, so one table drives both the fetch and the shape plan_harvest reads.
COLLECTIONS = (("groups", "/groups"), ("lists", "/lists?type=block"),
               ("domains", "/domains"), ("clients", "/clients"))


def export_state():
    """Live FTL state as the four raw API collections.

    Exporting raw state rather than a finished plan keeps the routing rules on
    the controller, in the repo: changing how an entry is captured is then a
    repo edit, not a redeploy of the box's copy of this script. It also gives
    the drift check the managed entries, which a plan drops.
    """
    sid = sync.login()
    try:
        state = {}
        for key, path in COLLECTIONS:
            st, body = sync.api("GET", path, sid)
            if st != 200:
                sync.die(f"GET {path} failed (HTTP {st}): {body}")
            state[key] = body.get(key, [])
        return state
    finally:
        sync.logout(sid)


def read_state(source):
    """Exported state from a file, or from stdin when source is '-'."""
    if source == "-":
        return json.load(sys.stdin)
    with open(source, encoding="utf-8") as f:
        return json.load(f)


def apply_plan(root, plan):
    """Write the plan into the config tree at root; return the paths changed.

    A file is only rewritten when merging actually adds something, so a harvest
    with nothing new to record leaves the tree untouched.
    """
    written = []
    for path in sorted(plan.files):
        full = os.path.join(root, path)
        existing = ""
        if os.path.exists(full):
            with open(full, encoding="utf-8") as f:
                existing = f.read()
        merged = merge_lines(existing, plan.files[path])
        if merged is None:
            continue
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as f:
            f.write(merged)
        written.append(path)
    return written


def report(root, plan, written):
    """Print what was captured and what needs a human decision.

    Returns the exit status: non-zero while anything is left unrecorded, so an
    entry the config cannot express is noticed rather than quietly lost at the
    next rebuild.
    """
    for path in written:
        print(f"  ~ {path}")

    for label, reason in plan.unroutable:
        print(f"WARN: {label} was not captured: {reason}.", file=sys.stderr)

    # A group with no entries has no file to write, and git does not track an
    # empty directory — so name it instead of leaving a directory git will drop.
    empty = [n for n in plan.group_dirs
             if not os.path.isdir(os.path.join(root, "groups", n))]
    for name in empty:
        print(f"WARN: group {name!r} exists in Pi-hole but has no config; add "
              f"groups/{name}/ with a block.list and clients.txt to manage it.",
              file=sys.stderr)

    print("CHANGED" if written else "no changes")
    outstanding = len(plan.unroutable) + len(empty)
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
    parser.add_argument("--dir", default=".", metavar="DIR",
                        help="config root to write into (default: current directory)")
    args = parser.parse_args(argv)

    if args.export:
        json.dump(export_state(), sys.stdout)
        print()
        return 0
    plan = plan_harvest(read_state(args.merge))
    return report(args.dir, plan, apply_plan(args.dir, plan))


if __name__ == "__main__":
    sys.exit(main())
