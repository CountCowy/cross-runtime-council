#!/bin/sh
# cross-runtime-council rollback.
# Restores the most recent (or a named) backup created by upgrade.sh.
# Usage: rollback.sh [backup-directory]
set -eu

TARGET="${HOME}/.claude/skills/council"
STATE="${HOME}/.claude/peer-consults"

fail() { printf 'rollback: %s\n' "$1" >&2; exit 1; }

check_broker_socket() {
  sock="${STATE}/broker.sock"
  [ -S "$sock" ] || return 0
  if python3 -c 'import socket,sys
s = socket.socket(socket.AF_UNIX); s.settimeout(1.0)
try: s.connect(sys.argv[1])
except OSError: raise SystemExit(1)
raise SystemExit(0)' "$sock" 2>/dev/null; then
    fail "a LIVE broker is listening at ${sock}; finish or cancel active dialogues and quit the owning runtime first"
  else
    fail "a STALE broker socket exists at ${sock} (nothing is listening; likely an unclean shutdown). Remove it with: rm '${sock}' — or start and then quit a Council runtime so a fresh broker reclaims it. Then re-run this script."
  fi
}

[ -n "${HOME:-}" ] || fail "HOME is not set"

backup_root="$(dirname "$TARGET")/.council-backups"
if [ -n "${1:-}" ]; then
  backup="$1"
else
  backup="$(ls -d "${backup_root}"/backup-* 2>/dev/null | sort | tail -1 || true)"
fi
[ -n "${backup:-}" ] || fail "no backup found matching ${backup_root}/backup-*; nothing to roll back to"
[ -d "$backup" ] || fail "backup '$backup' is not a directory"
[ -f "${backup}/SKILL.md" ] || fail "'$backup' does not look like a Council backup (no SKILL.md); refusing"
check_broker_socket

stamp="$(date -u +%Y%m%dT%H%M%SZ)"
if [ -e "$TARGET" ]; then
  aside="${backup_root}/rolledback-${stamp}"
  mkdir -p "$backup_root" || fail "cannot create ${backup_root}"
  mv "$TARGET" "$aside"
  printf 'rollback: current install set aside at %s\n' "$aside"
fi
mv "$backup" "$TARGET"
printf 'rollback: restored %s -> %s\n' "$backup" "$TARGET"
printf 'rollback: user state at %s untouched.\n' "$STATE"
