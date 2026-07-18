#!/usr/bin/env bash
#
# One-command setup for a fresh Pi-hole box.
#
#   ./setup.sh
#
# On first run it asks for a vault passphrase, a Pi-hole admin password, and how
# to reach the Pi, stores them locally (never committed), then provisions the
# box. Re-runs reuse the saved answers and skip straight to provisioning.
#
# Toolchain: uses Nix if available (nix-shell), otherwise bootstraps `uv` and
# runs Ansible in an ephemeral uv environment — no Nix or manual pip needed.
#
set -euo pipefail
cd "$(dirname "$0")"

VAULT_PASS=ansible/.vault-pass
VAULT=ansible/group_vars/all/vault.yml
LOCAL=ansible/group_vars/all/local.yml

# --- toolchain -------------------------------------------------------------
# Pick a runner. Nix (if present) honours the repo's pinned env; otherwise uv
# manages an isolated Ansible install so a vanilla-Python Mac just works.
if command -v nix-shell >/dev/null 2>&1; then
  RUNNER=nix
else
  RUNNER=uv
fi

ensure_uv() {
  command -v uv >/dev/null 2>&1 && return
  command -v python3 >/dev/null 2>&1 || {
    echo "Python 3 is required (install Xcode Command Line Tools: xcode-select --install)" >&2
    exit 1
  }
  echo "Installing uv (Python package manager)..."
  python3 -m pip install --user --upgrade uv >/dev/null 2>&1 ||
    curl -LsSf https://astral.sh/uv/install.sh | sh
  local userbin
  userbin="$(python3 -m site --user-base)/bin"
  export PATH="$userbin:$HOME/.local/bin:$PATH"
  command -v uv >/dev/null 2>&1 || {
    echo "uv installation failed. See https://docs.astral.sh/uv/" >&2
    exit 1
  }
}

# Python deps for the uv-managed environment (paramiko added later for
# password login, since a vanilla Mac has no sshpass).
UV_WITH=(--with ansible)

# Run an ansible tool from the repo root (cwd = repo root).
arun() {
  if [ "$RUNNER" = nix ]; then
    nix-shell --run "$(printf '%q ' "$@")"
  else
    uv run --no-project "${UV_WITH[@]}" -- "$@"
  fi
}

# Run an ansible tool with cwd = ansible/ (needs ansible.cfg + inventory).
arun_ansible_dir() {
  if [ "$RUNNER" = nix ]; then
    nix-shell --run "cd ansible && $(printf '%q ' "$@")"
  else
    (cd ansible && uv run --no-project "${UV_WITH[@]}" -- "$@")
  fi
}

[ "$RUNNER" = uv ] && ensure_uv

# --- prompts ---------------------------------------------------------------
ask_secret() { # prompt -> echoes confirmed value on stdout, no terminal echo
  local prompt="$1" a b
  while :; do
    read -rsp "$prompt: " a </dev/tty && echo >/dev/tty
    read -rsp "Confirm: " b </dev/tty && echo >/dev/tty
    [ -n "$a" ] && [ "$a" = "$b" ] && {
      printf '%s' "$a"
      return
    }
    echo "Empty or mismatch — try again." >/dev/tty
  done
}

# 1. Vault passphrase (the key that encrypts your saved password).
if [ ! -f "$VAULT_PASS" ]; then
  echo "== Choose a vault passphrase (protects your saved passwords; keep it safe) =="
  ask_secret "Vault passphrase" >"$VAULT_PASS"
  chmod 600 "$VAULT_PASS"
fi
export ANSIBLE_VAULT_PASSWORD_FILE="$PWD/$VAULT_PASS"

# 2. Pi-hole admin/API password -> encrypted vault.yml.
if [ ! -f "$VAULT" ]; then
  echo "== Set your Pi-hole admin password (also used for the API) =="
  pw=$(ask_secret "Pi-hole admin password")
  esc=$(printf '%s' "$pw" | sed 's/\\/\\\\/g; s/"/\\"/g')
  unset pw
  printf 'vault_pihole_web_password: "%s"\n' "$esc" |
    arun ansible-vault encrypt --output="$VAULT" -
  unset esc
  echo "Encrypted -> $VAULT"
fi

# 3. Connection details -> gitignored local.yml.
if [ ! -f "$LOCAL" ]; then
  echo "== How do I reach your Pi? =="
  read -rp "Pi address [pihole.local]: " host </dev/tty
  host=${host:-pihole.local}
  read -rp "SSH username [pi]: " user </dev/tty
  user=${user:-pi}
  read -rp "SSH private key path (blank = password login): " keyfile </dev/tty
  read -rp "Path to a public key to authorise on the Pi (optional): " pubkey </dev/tty

  {
    echo "---"
    echo "ansible_host: $host"
    echo "ansible_user: $user"
    [ -n "$keyfile" ] && echo "ansible_ssh_private_key_file: $keyfile"
    if [ -n "$pubkey" ] && [ -f "$pubkey" ]; then
      echo "authorized_ssh_keys:"
      echo "  - \"$(cat "$pubkey")\""
    else
      echo "authorized_ssh_keys: []"
    fi
  } >"$LOCAL"
  echo "Wrote -> $LOCAL"
fi

# 4. Provision.
PLAY_ARGS=()
if ! grep -q '^ansible_ssh_private_key_file:' "$LOCAL"; then
  # Password login: prompt for the SSH password (-k). With uv there's no
  # sshpass, so use the pure-Python paramiko connection instead.
  PLAY_ARGS+=(-k)
  if [ "$RUNNER" = uv ]; then
    UV_WITH+=(--with paramiko)
    PLAY_ARGS+=(-c paramiko)
  fi
fi
echo "== Provisioning (this can take a while on a Pi) =="
export ANSIBLE_HOST_KEY_CHECKING=False
arun_ansible_dir ansible-playbook site.yml "${PLAY_ARGS[@]}"
