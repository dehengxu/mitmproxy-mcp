#!/usr/bin/env bash
# Restore the GitHub Actions workflow.
#
# The workflow is kept out of git because pushing .github/workflows/* requires
# a token with the 'workflow' scope. Without it GitHub rejects the push:
#   ! [remote rejected] HEAD -> main (refusing to allow a Personal Access Token
#     to create or update workflow `.github/workflows/ci.yml` without `workflow` scope)
#
# Usage:
#   gh auth refresh -h github.com -s workflow    # one-time, grants the scope
#   ./scripts/enable-ci.sh                       # restore and push the workflow
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKFLOW=".github/workflows/ci.yml"
SOURCE="$REPO_ROOT/scripts/ci.yml"

say() { printf "\033[1;34m==\033[0m %s\n" "$*"; }
ok()  { printf "  \033[0;32m\xe2\x9c\x93\033[0m %s\n" "$*"; }
die() { printf "  \033[0x31m\xe2\x9c\x97\033[0m %s\n" "$*" >&2; exit 1; }

say "checking token scope"
if ! gh auth status 2>&1 | grep -q "workflow"; then
  die "token is missing the workflow scope. Run: gh auth refresh -h github.com -s workflow"
fi
ok "token has workflow scope"

say "restoring workflow"
mkdir -p "$REPO_ROOT/.github/workflows"
cp "$SOURCE" "$REPO_ROOT/$WORKFLOW"
ok "copied $SOURCE -> $WORKFLOW"

say "committing and pushing"
cd "$REPO_ROOT"
git add "$WORKFLOW"
git commit -m "ci: add GitHub Actions workflow"
git push
ok "pushed"
