"""Make the deployed helper scripts importable by the tests.

The scripts live in their roles' files/ dirs (so Ansible deploys them) rather
than an installable package, so add those dirs to the import path here.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
for _d in ("ansible/roles/pihole/files", "ansible/roles/backup/files"):
    sys.path.insert(0, str(_ROOT / _d))
