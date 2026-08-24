#!/bin/sh
# cross-runtime-council upgrade.
# Replaces the installed payload with this checkout's payload, keeping a
# versioned backup for rollback.sh. Preflight-first; the swap is two renames.
set -eu

TARGET="${HOME}/.claude/skills/council"
STATE="${HOME}/.claude/peer-consults"
REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PAYLOAD="SKILL.md LICENSE NOTICE agents evals references scripts"

fail() { printf 'upgrade: %s\n' "$1" >&2; exit 1; }

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

# ---- preflight (no mutation past this block) --------------------------------
[ "$(uname -s)" = "Darwin" ] || fail "unsupported OS '$(uname -s)' (see docs/compatibility.md)"
[ -n "${HOME:-}" ] || fail "HOME is not set"
[ -e "$TARGET" ] || fail "$TARGET is not installed; use install/install.sh"
[ -f "${TARGET}/SKILL.md" ] || fail "$TARGET does not look like a Council install; refusing"
[ "$REPO_ROOT" = "$TARGET" ] && fail "repository is cloned in place; upgrade with 'git -C $TARGET pull' instead"
for item in $PAYLOAD; do
  [ -e "${REPO_ROOT}/${item}" ] || fail "payload item '${item}' missing from ${REPO_ROOT}"
done
check_broker_socket
parent="$(dirname "$TARGET")"
[ -w "$parent" ] || fail "${parent} is not writable"

# ---- stage, backup, swap ------------------------------------------------------
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
# Backups live under a dot-prefixed sibling: skill discovery scans
# ~/.claude/skills/ for SKILL.md directories, so a plain sibling backup
# would surface as a second "council" skill.
backup_root="${parent}/.council-backups"
backup="${backup_root}/backup-${stamp}"
staging="$(mktemp -d "${parent}/.council-upgrade.XXXXXX")" || fail "cannot create staging directory"
trap 'rm -rf "$staging"' EXIT
for item in $PAYLOAD; do
  cp -R "${REPO_ROOT}/${item}" "${staging}/${item}"
done
mkdir -p "$backup_root" || fail "cannot create ${backup_root}"
mv "$TARGET" "$backup"
mv "$staging" "$TARGET"
trap - EXIT

printf 'upgrade: installed new payload at %s\n' "$TARGET"
printf 'upgrade: previous install preserved at %s (install/rollback.sh restores it)\n' "$backup"
printf 'upgrade: user state at %s untouched.\n' "$STATE"
printf 'upgrade: if the OpenCode CLI binary also changed, renew its offline pin and restart OpenCode.\n'
