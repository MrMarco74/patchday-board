#!/bin/bash
# Pushes the current HEAD to the public GitHub mirror after a local safety scan.
# Triggered automatically by the pre-push hook (scripts/install-git-hooks.sh) or can be run manually.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_NAME="patchday-board"
LOG_PREFIX="[mirror_to_github]"
cd "$REPO_ROOT"

BEGIN_PATTERN="BEGIN (RSA |OPENSSH |PGP )?PRIVATE KEY"
END_PATTERN="END (RSA |OPENSSH |PGP )?PRIVATE KEY"
DENYLIST='dzbank|steinbrecher|familie-frischkorn\.de|highantdev\.de|fritz\.box'
SCAN_EXCLUDES=(':(exclude)scripts/mirror_to_github.sh' ':(exclude).gitlab-ci.yml')

# Check for private keys
_begin_files="$(git grep -lIE "$BEGIN_PATTERN" HEAD -- . "${SCAN_EXCLUDES[@]}" 2>/dev/null || true)"
_real_key_hit=""
for f in $_begin_files; do
    if git grep -qIE "$END_PATTERN" HEAD -- "$f" 2>/dev/null; then
        _real_key_hit="1"
        echo "$LOG_PREFIX private key material found in HEAD: $f" >&2
    fi
done
if [ -n "$_real_key_hit" ]; then
    echo "$LOG_PREFIX sync aborted." >&2
    exit 1
fi

# Check for denylisted internal keywords / domains
if git grep -rIlE "$DENYLIST" HEAD -- . "${SCAN_EXCLUDES[@]}" >/dev/null 2>&1; then
    echo "$LOG_PREFIX denylisted term found in HEAD, sync aborted:" >&2
    git grep -lE "$DENYLIST" HEAD -- . "${SCAN_EXCLUDES[@]}" >&2
    exit 1
fi

# Guard against hook recursion
export PATCHDAY_MIRROR_RUNNING=1
git push https://github.com/MrMarco74/"$REPO_NAME".git HEAD:main
echo "$LOG_PREFIX pushed to github.com/MrMarco74/$REPO_NAME"
