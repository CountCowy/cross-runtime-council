#!/bin/sh
# cross-runtime-council uninstaller.
# Removes the installed payload only. User state (~/.claude/peer-consults:
# dialogues, audit logs, registrations) is PRESERVED by default; pass
# --purge-state to remove it too after an explicit confirmation.
set -eu

TARGET="${HOME}/.claude/skills/council"
STATE="${HOME}/.claude/peer-consults"
PURGE=0
[ "${1:-}" = "--purge-state" ] && PURGE=1

fail() { printf 'uninstall: %s\n' "$1" >&2; exit 1; }

[ -n "${HOME:-}" ] || fail "HOME is not set"
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

if [ ! -e "$TARGET" ]; then
  printf 'uninstall: %s is not present; nothing to remove.\n' "$TARGET"
else
  [ -f "${TARGET}/SKILL.md" ] || fail "$TARGET does not look like a Council install (no SKILL.md); refusing to remove it"
  check_broker_socket
  if [ -d "${TARGET}/.git" ]; then
    printf 'uninstall: %s is a git clone (clone-into-place install); removing it deletes the repository, including any local commits or uncommitted changes.\n' "$TARGET"
    printf 'Type "delete-clone" to confirm: '
    read -r answer
    [ "$answer" = "delete-clone" ] || fail "confirmation not given; nothing removed"
  fi
  rm -rf "$TARGET"
  printf 'uninstall: removed %s\n' "$TARGET"
fi

if [ "$PURGE" -eq 1 ] && [ -e "$STATE" ]; then
  printf 'uninstall: --purge-state will permanently delete %s (dialogue records, audit logs).\n' "$STATE"
  printf 'Type "purge" to confirm: '
  read -r answer
  [ "$answer" = "purge" ] || fail "confirmation not given; state preserved"
  rm -rf "$STATE"
  printf 'uninstall: state root removed.\n'
else
  [ -e "$STATE" ] && printf 'uninstall: state root %s preserved (use --purge-state to remove).\n' "$STATE"
fi
printf 'uninstall: any per-runtime registrations (MCP config entries, OpenCode plugin/tool files, pins) must be removed in those tools; see docs/install.md.\n'
