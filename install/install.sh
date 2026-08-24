#!/bin/sh
# cross-runtime-council installer (fixed layout).
# Preflight-first: any unsupported condition is rejected BEFORE any file or
# state mutation, with an exact diagnostic. Safe to re-run; refuses to clobber
# an existing install (use upgrade.sh for that).
set -eu

TARGET="${HOME}/.claude/skills/council"
REPO_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PAYLOAD="SKILL.md LICENSE NOTICE agents evals references scripts"

fail() { printf 'install: %s\n' "$1" >&2; exit 1; }

# ---- preflight (no mutation past this block) --------------------------------
[ "$(uname -s)" = "Darwin" ] || fail "unsupported OS '$(uname -s)': Council's trust anchors are macOS-specific (see docs/compatibility.md)"
[ -n "${HOME:-}" ] || fail "HOME is not set"
command -v python3 >/dev/null 2>&1 || fail "python3 not found on PATH (Python 3.9+ required)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || fail "python3 is older than 3.9 ($(python3 --version 2>&1)); 3.9+ required"
for item in $PAYLOAD; do
  [ -e "${REPO_ROOT}/${item}" ] || fail "payload item '${item}' missing from ${REPO_ROOT}; run from a complete checkout"
done
if [ -e "$TARGET" ]; then
  if [ "$REPO_ROOT" = "$TARGET" ]; then
    printf 'install: repository is already cloned in place at %s; nothing to do.\n' "$TARGET"
    exit 0
  fi
  fail "$TARGET already exists; use install/upgrade.sh to replace it (keeps a versioned backup)"
fi
parent="${HOME}/.claude/skills"
probe="$parent"
while [ ! -d "$probe" ]; do probe="$(dirname "$probe")"; done
[ -w "$probe" ] || fail "cannot create ${TARGET}: ${probe} is not writable"

# ---- install (first mutation happens below this line) ------------------------
mkdir -p "$parent" || fail "cannot create ${parent}"
staging="$(mktemp -d "${parent}/.council-install.XXXXXX")" || fail "cannot create staging directory under ${parent}"
trap 'rm -rf "$staging"' EXIT
for item in $PAYLOAD; do
  cp -R "${REPO_ROOT}/${item}" "${staging}/${item}"
done
mv "$staging" "$TARGET"
trap - EXIT

printf 'install: payload installed at %s\n' "$TARGET"
printf 'install: state root %s is created on demand by the runtimes (0700).\n' "${HOME}/.claude/peer-consults"
cat <<'EOF'
Next steps (per runtime, see docs/install.md for detail):
  Claude Code : the skill is now discoverable; enable cross-session inbound
                messages for the session you plan to bind.
  Codex       : register the MCP adapter per agents/openai.yaml.
  OpenCode CLI: register the plugin/tool files and record the offline
                executable pin, then restart OpenCode.
EOF
