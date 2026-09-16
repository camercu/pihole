"""End-to-end test: the pihole role's group-prune task against real ansible-playbook.

Every other integration test here drives pihole_deploy.py/pihole_mirror.py
directly, never the Ansible wiring around them. The group-tree diff-and-remove
task in main.yml (tags: pihole_group_prune) is destructive and has no other
automated coverage anywhere in the pipeline -- ansible-lint only checks its
syntax. This runs the actual task, via the actual ansible-playbook binary,
against throwaway directories standing in for role_path/files/groups and
/etc/pihole/managed/groups, and asserts the resulting file set. Needs no
container -- these tasks touch only the filesystem -- so unlike its neighbors
it is not gated behind PIHOLE_IT, only skipped if ansible-playbook itself is
missing (e.g. running bare `pytest` outside the repo's nix-shell).
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("ansible-playbook") is None,
    reason="needs ansible-playbook (nix-shell provides it)")

_ROOT = Path(__file__).resolve().parents[2]
ROLES_PATH = _ROOT / "ansible/roles"
PLAYBOOK = Path(__file__).resolve().parent / "fixtures/group_prune.yml"


def _tree(root, files):
    """Materialise {relpath: contents} under root; return the set of relpaths present."""
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _relpaths(root):
    """Every file/dir under root, relative to root, as a set of str."""
    if not root.exists():
        return set()
    return {str(p.relative_to(root)) for p in root.rglob("*")}


def _run(source_dir, deployed_dir):
    env = {**os.environ, "ANSIBLE_ROLES_PATH": str(ROLES_PATH)}
    return subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "--tags", "pihole_group_prune",
         "-e", f"pihole_group_source_dir={source_dir}",
         "-e", f"pihole_group_deployed_dir={deployed_dir}",
         "-e", f"ansible_python_interpreter={sys.executable}",
         str(PLAYBOOK)],
        env=env, capture_output=True, text=True, timeout=60)


def test_a_group_removed_from_the_repo_is_pruned_but_a_kept_one_is_untouched(tmp_path):
    source = _tree(tmp_path / "source", {"kids/block.list": "bad.example\n"})
    deployed = _tree(tmp_path / "deployed", {
        "kids/block.list": "bad.example\n",
        "teens/block.list": "other.example\n",
        "teens/clients.txt": "10.0.0.9\n",
    })

    r = _run(source, deployed)

    assert r.returncode == 0, r.stdout + r.stderr
    assert _relpaths(deployed) == {"kids", "kids/block.list"}
    assert (deployed / "kids/block.list").read_text() == "bad.example\n"


def test_a_repo_describing_zero_groups_prunes_every_deployed_group(tmp_path):
    # Regression test for d03b423: git tracks no empty directory, so the last
    # group ever deleted from the repo can leave source_dir absent, not just
    # empty of subdirectories -- this exercises exactly that shape.
    source = tmp_path / "source"  # never created; the role must create it empty
    deployed = _tree(tmp_path / "deployed", {"kids/block.list": "bad.example\n"})

    r = _run(source, deployed)

    assert r.returncode == 0, r.stdout + r.stderr
    assert _relpaths(deployed) == set()


def test_a_source_tree_that_cannot_be_read_prunes_nothing(tmp_path):
    source = _tree(tmp_path / "source", {"kids/block.list": "bad.example\n"})
    deployed = _tree(tmp_path / "deployed", {
        "kids/block.list": "bad.example\n",
        "teens/block.list": "other.example\n",
    })
    unreadable = source / "kids"
    unreadable.chmod(0o000)
    try:
        r = _run(source, deployed)
    finally:
        unreadable.chmod(0o755)

    assert r.returncode != 0, r.stdout + r.stderr
    assert "could not be read" in r.stdout + r.stderr
    assert _relpaths(deployed) == {"kids", "kids/block.list",
                                    "teens", "teens/block.list"}


def test_prune_is_idempotent(tmp_path):
    source = _tree(tmp_path / "source", {"kids/block.list": "bad.example\n"})
    deployed = _tree(tmp_path / "deployed", {
        "kids/block.list": "bad.example\n",
        "teens/block.list": "other.example\n",
    })

    first = _run(source, deployed)
    assert first.returncode == 0, first.stdout + first.stderr
    assert _relpaths(deployed) == {"kids", "kids/block.list"}

    second = _run(source, deployed)
    assert second.returncode == 0, second.stdout + second.stderr
    assert "changed=0" in second.stdout
    assert _relpaths(deployed) == {"kids", "kids/block.list"}
