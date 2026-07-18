#!/usr/bin/env bash
#
# Apply version-controlled adlists and allowlists into Pi-hole's gravity DB,
# then rebuild gravity. Idempotent: uses INSERT OR IGNORE against the stable
# gravity.db schema (works on Pi-hole v5 and v6), so re-running only adds new
# entries. Deployed and invoked by roles/pihole.
#
#   domainlist.type: 0=exact allow, 1=exact deny, 2=regex allow, 3=regex deny
#
set -euo pipefail

GRAVITY=/etc/pihole/gravity.db
ADLISTS=/etc/pihole/managed-adlists.txt
ALLOWLIST_LOCAL=/etc/pihole/managed-allow.list
ALLOWLIST_URLS=/etc/pihole/managed-allowlist-urls.txt
COMMENT='managed by ansible'

sql() { sqlite3 "$GRAVITY" "$1"; }
esc() { printf '%s' "$1" | sed "s/'/''/g"; } # escape single quotes for SQL

# Strip a trailing comment, leading "0.0.0.0"/"127.0.0.1" hosts-file prefix,
# and surrounding whitespace. Emits nothing for blank/comment-only lines.
clean() {
  local line="${1%%#*}"
  line="${line##*[[:space:]]}" # keep last field (drops "0.0.0.0 " prefixes)
  printf '%s' "$line" | tr -d '[:space:]'
}

add_adlist() {
  local url
  url=$(esc "$1")
  sql "INSERT OR IGNORE INTO adlist (address, comment) VALUES ('$url', '$COMMENT');"
}

add_allow() { # $1=domain-or-pattern  $2=type (0 exact / 2 regex)
  local d
  d=$(esc "$1")
  sql "INSERT OR IGNORE INTO domainlist (type, domain, comment) VALUES ($2, '$d', '$COMMENT');"
}

echo "==> adlists"
while IFS= read -r raw; do
  entry=$(clean "$raw") || true
  [ -n "$entry" ] || continue
  add_adlist "$entry"
done <"$ADLISTS"

echo "==> local allow entries"
while IFS= read -r raw; do
  # allow.list mixes exact domains with regex (e.g. (\.|^)twimg\.com$).
  stripped="${raw%%#*}"
  entry=$(printf '%s' "$stripped" | tr -d '[:space:]')
  [ -n "$entry" ] || continue
  if printf '%s' "$entry" | grep -qE '[][(){}|^$\\*+?]'; then
    add_allow "$entry" 2
  else
    add_allow "$entry" 0
  fi
done <"$ALLOWLIST_LOCAL"

if [ -s "$ALLOWLIST_URLS" ]; then
  echo "==> remote allowlist URLs"
  while IFS= read -r rawurl; do
    url=$(printf '%s' "${rawurl%%#*}" | tr -d '[:space:]')
    [ -n "$url" ] || continue
    curl -fsSL "$url" | while IFS= read -r rawdom; do
      dom=$(clean "$rawdom") || true
      [ -n "$dom" ] || continue
      add_allow "$dom" 0
    done
  done <"$ALLOWLIST_URLS"
fi

echo "==> rebuilding gravity"
pihole -g
