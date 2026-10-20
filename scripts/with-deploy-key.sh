#!/bin/sh
# Runs a command with a private ssh-agent that holds only the Pi's deploy key,
# for at most an hour, so unattended runs need no Touch ID prompt.
#
# The key comes from 1Password through a service account whose token sits in
# the macOS keychain (service PIHOLE_OP_TOKEN_SERVICE). With no such entry,
# the command runs as-is, with whatever agent the caller already has.
set -eu
# The vault passphrase, as .envrc loads it, so recipes also work under plain
# nix-shell. No file: leave the caller's setting alone.
vault_pass="$(cd "$(dirname "$0")/.." && pwd)/ansible/.vault-pass"
if [ -z "${ANSIBLE_VAULT_PASSWORD_FILE:-}" ] && [ -f "$vault_pass" ]; then
  export ANSIBLE_VAULT_PASSWORD_FILE="$vault_pass"
fi
token="$(security find-generic-password -a "$USER" -s "${PIHOLE_OP_TOKEN_SERVICE:-pihole-op-token}" -w 2>/dev/null || true)"
if [ -z "$token" ]; then
  exec "$@"
fi
eval "$(ssh-agent -s -t 3600)" >/dev/null
trap 'ssh-agent -k >/dev/null' EXIT
trap 'exit 130' INT TERM
OP_SERVICE_ACCOUNT_TOKEN="$token" \
  op read "${PIHOLE_OP_SSH_KEY:-op://Pihole/pihole-ssh/private key}?ssh-format=openssh" |
  ssh-add -q -
# ~/.ssh/config may name another agent and key for the Pi (IdentityAgent beats
# SSH_AUTH_SOCK, IdentitiesOnly hides unlisted keys). Flags beat the config.
ANSIBLE_SSH_COMMON_ARGS="-o IdentityAgent=$SSH_AUTH_SOCK -o IdentitiesOnly=no" \
  "$@"
