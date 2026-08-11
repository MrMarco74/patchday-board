#!/bin/bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOOKS_DIR="$REPO_ROOT/.git/hooks"

if [ ! -d "$HOOKS_DIR" ]; then
    echo "Error: .git/hooks directory not found." >&2
    exit 1
fi

cat << 'HOOK_EOF' > "$HOOKS_DIR/pre-push"
#!/bin/bash
# Auto-installed by scripts/install-git-hooks.sh

if [ -n "${PATCHDAY_MIRROR_RUNNING:-}" ]; then
    exit 0
fi

REPO_ROOT="$(git rev-parse --show-toplevel)"
nohup "$REPO_ROOT/scripts/mirror_to_github.sh" >> "$REPO_ROOT/.git/mirror.log" 2>&1 &
disown
exit 0
HOOK_EOF

chmod +x "$HOOKS_DIR/pre-push"
chmod +x "$REPO_ROOT/scripts/mirror_to_github.sh"
echo "Git pre-push hook for GitHub auto-sync installed."
