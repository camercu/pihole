#!/bin/sh
# Runs a command with a private ssh-agent that holds only the Pi's deploy key,
# for at most an hour, so unattended runs need no Touch ID prompt.
#
# The key comes from 1Password through a service account whose token sits in
# the macOS keychain (service PIHOLE_OP_TOKEN_SERVICE). With no such entry,
# the command runs as-is, with whatever agent the caller already has.
set -eu
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
"$@"
