"""The deploy-key wrapper gives one command a private agent holding only the
Pi's deploy key, or runs it as-is when no 1Password token is set up."""

import os
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "with-deploy-key.sh"


def wrapper_env(tmp_path, token="ops_token"):
    """Env whose security prints token (none: no keychain entry) and whose op
    prints a fresh key; returns (env, key fingerprint)."""
    key = tmp_path / "deploy"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
    fingerprint = subprocess.run(
        ["ssh-keygen", "-l", "-f", key], check=True, capture_output=True, text=True
    ).stdout.split()[1]
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    security = f"echo {token}" if token else "exit 44"
    (bin_dir / "security").write_text(f"#!/bin/sh\n{security}\n")
    (bin_dir / "op").write_text(f"#!/bin/sh\ncat {key}\n")
    for tool in ("security", "op"):
        (bin_dir / tool).chmod(0o755)
    env = {k: v for k, v in os.environ.items()
           if k not in ("SSH_AUTH_SOCK", "SSH_AGENT_PID", "ANSIBLE_SSH_COMMON_ARGS")}
    env["PATH"] = f"{bin_dir}:{env['PATH']}"
    env["ANSIBLE_VAULT_PASSWORD_FILE"] = str(tmp_path / "vault-pass")
    return env, fingerprint


def test_command_sees_only_the_deploy_key(tmp_path):
    # GIVEN a keychain token, and 1Password holding the deploy key
    env, fingerprint = wrapper_env(tmp_path)
    # WHEN a command runs under the wrapper
    result = subprocess.run([SCRIPT, "ssh-add", "-l"], env=env, capture_output=True, text=True)
    # THEN its agent lists the deploy key and nothing else
    assert [line.split()[1] for line in result.stdout.splitlines()] == [fingerprint]


def test_ansible_ssh_uses_the_private_agent(tmp_path):
    # GIVEN a keychain token, and an ~/.ssh/config that may name another agent
    env, _ = wrapper_env(tmp_path)
    # WHEN a command reads the ssh flags Ansible will pass, and its own agent
    result = subprocess.run(
        [SCRIPT, "sh", "-c", 'echo "$ANSIBLE_SSH_COMMON_ARGS|$SSH_AUTH_SOCK"'],
        env=env, capture_output=True, text=True,
    )
    args, sock = result.stdout.strip().split("|")
    # THEN the flags point ssh at that agent, which beats the config
    assert f"-o IdentityAgent={sock}" in args, result.stdout


def test_agent_stops_when_the_command_exits(tmp_path):
    # GIVEN a command that reports its agent's PID
    env, _ = wrapper_env(tmp_path)
    result = subprocess.run(
        [SCRIPT, "sh", "-c", "echo $SSH_AGENT_PID"], env=env, capture_output=True, text=True
    )
    # WHEN the wrapper returns THEN that agent no longer runs
    alive = subprocess.run(["kill", "-0", result.stdout.strip()], capture_output=True)
    assert alive.returncode != 0


def test_failing_command_fails_the_wrapper(tmp_path):
    # GIVEN a command that fails, as a failed deploy does
    env, _ = wrapper_env(tmp_path)
    # WHEN it runs under the wrapper THEN its exit status comes back
    assert subprocess.run([SCRIPT, "sh", "-c", "exit 3"], env=env).returncode == 3


def test_command_does_not_run_without_the_key(tmp_path):
    # GIVEN a token, but op cannot read the deploy key
    env, _ = wrapper_env(tmp_path)
    (Path(env["PATH"].split(":")[0]) / "op").write_text("#!/bin/sh\nexit 1\n")
    marker = tmp_path / "ran"
    # WHEN a command runs under the wrapper
    subprocess.run([SCRIPT, "touch", marker], env=env, capture_output=True)
    # THEN the command never starts
    assert not marker.exists()


def test_without_a_token_the_command_keeps_the_callers_agent(tmp_path):
    # GIVEN no keychain token, and a caller with an agent of their own
    env, _ = wrapper_env(tmp_path, token=None)
    env["SSH_AUTH_SOCK"] = "/caller/agent.sock"
    # WHEN a command runs under the wrapper
    result = subprocess.run([SCRIPT, "sh", "-c", 'echo "$SSH_AUTH_SOCK"'],
                            env=env, capture_output=True, text=True)
    # THEN it runs as-is, with the caller's agent
    assert result.stdout.strip() == "/caller/agent.sock"
