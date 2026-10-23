#!/usr/bin/env bash
# Count unique outside contributors with merged pull requests in the last
# 12 months. Used to track progress during community contribution sprints.
#
# Usage: scripts/count-contributors.sh [owner/repo] [maintainer ...]
# Needs the GitHub CLI (gh) logged in.
set -euo pipefail

REPO="${1:-theleetsec/LeetSec-Tools}"
shift || true
MAINTAINERS=("$@")
[ "${#MAINTAINERS[@]}" -eq 0 ] && MAINTAINERS=(sudo-a-man)

SINCE=$(date -u -v-12m +%Y-%m-%d 2>/dev/null || date -u -d '12 months ago' +%Y-%m-%d)

authors=$(gh pr list -R "$REPO" --state merged --limit 1000 \
  --search "merged:>=${SINCE}" --json author --jq '.[].author.login' | sort -u)

outside=$(printf '%s\n' "$authors" | grep -v -x -F -f <(printf '%s\n' "${MAINTAINERS[@]}") \
  | grep -v -E '\[bot\]$|^dependabot|^github-actions' | grep -v '^$' || true)

count=$(printf '%s\n' "$outside" | grep -c . || true)

printf 'Repo:   %s\n' "$REPO"
printf 'Since:  %s\n' "$SINCE"
printf 'Outside contributors with merged PRs: %s / 20\n\n' "$count"
[ -n "$outside" ] && printf '%s\n' "$outside" | sed 's/^/  @/'
