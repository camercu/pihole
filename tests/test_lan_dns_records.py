"""Rendered unbound records: each lan_hosts name and each lan_zones zone."""

import json
import os
import subprocess
from pathlib import Path

TEMPLATE = (Path(__file__).resolve().parent.parent
            / "ansible/roles/unbound/templates/custom-dns-records.conf.j2")


def render(tmp_path, lan_hosts, lan_zones):
    """Render the records template as the unbound role does; return its lines."""
    out = tmp_path / "custom-dns-records.conf"
    extra = tmp_path / "vars.json"
    extra.write_text(json.dumps({"lan_hosts": lan_hosts, "lan_zones": lan_zones}))
    subprocess.run(
        ["ansible", "localhost", "-c", "local", "-m", "ansible.builtin.template",
         "-a", f"src={TEMPLATE} dest={out}", "-e", f"@{extra}",
         "-e", "ansible_python_interpreter=auto_silent"],
        check=True, capture_output=True, cwd=tmp_path,
        env={**os.environ, "ANSIBLE_NOCOLOR": "1"},
    )
    return [line.strip() for line in out.read_text().splitlines()]


def test_zone_answers_every_name_under_it_with_one_address(tmp_path):
    # GIVEN homelab's subzone, served by the Pi at 192.168.0.10
    lines = render(tmp_path, [], [{"name": "lab.example.com", "ip": "192.168.0.10"}])
    # WHEN unbound reads the records THEN the zone redirects every subname to
    # its apex, and the apex holds the address
    assert lines[-2:] == ['local-zone: "lab.example.com." redirect',
                          'local-data: "lab.example.com. A 192.168.0.10"']


def test_host_gets_one_record_per_name(tmp_path):
    # GIVEN a host with two names
    lines = render(tmp_path, [{"names": ["nas.lan", "files.lan"], "ip": "192.168.0.5"}], [])
    # WHEN rendered THEN each name has its own A record
    assert lines[-2:] == ['local-data: "nas.lan A 192.168.0.5"',
                          'local-data: "files.lan A 192.168.0.5"']
