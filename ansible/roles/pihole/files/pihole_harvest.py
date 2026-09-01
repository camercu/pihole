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
import os
import sys
from typing import NamedTuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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
        if in_default:
            return [], ("the config blocks domains per group, and this one also "
                        "blocks network-wide; recording it would stop blocking it "
                        "for everyone outside " + (", ".join(named) or "any group"))
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
