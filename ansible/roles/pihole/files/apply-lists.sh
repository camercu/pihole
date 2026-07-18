#!/usr/bin/env bash
#
# Apply version-controlled adlists and allowlists into Pi-hole's gravity DB,
# then rebuild gravity. Idempotent: uses INSERT OR IGNORE against the stable
# gravity.db schema (Pi-hole v5 and v6), so re-running only adds new entries.
# Deployed and invoked by roles/pihole.
#
#   domainlist.type: 0=exact allow, 1=exact deny, 2=regex allow, 3=regex deny
#
# Pi-hole v6's FTL keeps gravity.db open, so all writes go through a single
# transaction with a busy_timeout to wait out FTL's locks (avoids the
# "database is locked" SQLITE_BUSY error from many concurrent connections).
#
set -euo pipefail

GRAVITY=/etc/pihole/gravity.db
ADLISTS=/etc/pihole/managed-adlists.txt
ALLOWLIST_LOCAL=/etc/pihole/managed-allow.list
ALLOWLIST_URLS=/etc/pihole/managed-allowlist-urls.txt
COMMENT='managed by ansible'

esc() { printf '%s' "$1" | sed "s/'/''/g"; } # escape single quotes for SQL

SQL=$(mktemp)
trap 'rm -f "$SQL"' EXIT
{
  echo "PRAGMA busy_timeout=15000;"
  echo "BEGIN IMMEDIATE;"
} >>"$SQL"

emit_adlist() {
  printf "INSERT OR IGNORE INTO adlist (address, comment) VALUES ('%s','%s');\n" \
    "$(esc "$1")" "$COMMENT" >>"$SQL"
}
emit_allow() { # $1=domain-or-pattern  $2=type (0 exact / 2 regex)
  printf "INSERT OR IGNORE INTO domainlist (type, domain, comment) VALUES (%s,'%s','%s');\n" \
    "$2" "$(esc "$1")" "$COMMENT" >>"$SQL"
}

echo "==> adlists"
while IFS= read -r raw; do
  entry=$(printf '%s' "${raw%%#*}" | tr -d '[:space:]')
  [ -n "$entry" ] || continue
  emit_adlist "$entry"
done <"$ADLISTS"

echo "==> local allow entries"
while IFS= read -r raw; do
  # allow.list mixes exact domains with regex (e.g. (\.|^)twimg\.com$).
  entry=$(printf '%s' "${raw%%#*}" | tr -d '[:space:]')
  [ -n "$entry" ] || continue
  if printf '%s' "$entry" | grep -qE '[][(){}|^$\\*+?]'; then
    emit_allow "$entry" 2
  else
    emit_allow "$entry" 0
  fi
done <"$ALLOWLIST_LOCAL"

if [ -s "$ALLOWLIST_URLS" ]; then
  echo "==> remote allowlist URLs"
  while IFS= read -r rawurl; do
    url=$(printf '%s' "${rawurl%%#*}" | tr -d '[:space:]')
    [ -n "$url" ] || continue
    while IFS= read -r rawdom; do
      # Drop trailing comment, keep last field (strips "0.0.0.0 " hosts prefix).
      dom="${rawdom%%#*}"
      dom="${dom##*[[:space:]]}"
      dom=$(printf '%s' "$dom" | tr -d '[:space:]')
      [ -n "$dom" ] || continue
      emit_allow "$dom" 0
    done < <(curl -fsSL "$url" || true)
  done <"$ALLOWLIST_URLS"
fi

echo "COMMIT;" >>"$SQL"

echo "==> applying $(grep -c INSERT "$SQL") entries to gravity.db"
sqlite3 "$GRAVITY" <"$SQL"

echo "==> rebuilding gravity"
pihole -g
