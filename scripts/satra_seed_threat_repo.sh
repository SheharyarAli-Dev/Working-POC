#!/usr/bin/env bash
set -euo pipefail

target="${1:?usage: satra_seed_threat_repo.sh <path-to-local-Threat-Repository-clone>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
seed="$here/satra_seed"
scenarios=(idor-bypass weakened-test sqli-fstring path-traversal docs-only secure-refactor)

cd "$target"
git rev-parse --is-inside-work-tree >/dev/null
if [ -n "$(git status --porcelain)" ]; then
  echo "refusing: working tree is not clean" >&2
  exit 1
fi
if [ -z "$(git config user.email || true)" ] && [ -z "${GIT_AUTHOR_EMAIL:-}" ]; then
  echo "refusing: no git identity configured (set user.name/user.email or GIT_AUTHOR_*/GIT_COMMITTER_*)" >&2
  exit 1
fi
for name in "${scenarios[@]}"; do
  if git show-ref --verify --quiet "refs/heads/scenario/$name"; then
    echo "refusing: branch scenario/$name already exists" >&2
    exit 1
  fi
done

git checkout -q main
cp -R "$seed/baseline/." .
git add -A
git commit -q -m "feat(invoice-api): secure baseline invoice API with its own tests"

for name in "${scenarios[@]}"; do
  git checkout -q -b "scenario/$name" main
  message="$(python3 "$seed/apply_scenario.py" "$name" .)"
  git add -A
  git commit -q -m "$message"
  git checkout -q main
done

echo "Local branches created (nothing was pushed):"
git branch --list
git log --oneline --all --decorate -n 12
