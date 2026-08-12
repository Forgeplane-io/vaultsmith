#!/usr/bin/env bash
set -euo pipefail

: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${SOURCE_SHA:?SOURCE_SHA is required}"
: "${GH_TOKEN:?GH_TOKEN is required}"

if [[ ! "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'release acceptance: SOURCE_SHA must be a full lowercase commit SHA\n' >&2
  exit 2
fi

required_jobs=(
  frontend
  backend
  api-contract
  compatibility
  helm
  helm-kind
  smoke
  native-integration
  container
  release-snapshot
)
for job in "${required_jobs[@]}"; do
  if ! grep -Eq "^  ${job}:$" .github/workflows/ci.yml; then
    printf 'release acceptance: required CI job is absent: %s\n' "$job" >&2
    exit 1
  fi
done

attempts="${RELEASE_CI_ATTEMPTS:-30}"
interval="${RELEASE_CI_INTERVAL_SECONDS:-20}"
if [[ ! "$attempts" =~ ^[1-9][0-9]*$ || ! "$interval" =~ ^[1-9][0-9]*$ ]]; then
  printf 'release acceptance: poll attempts and interval must be positive integers\n' >&2
  exit 2
fi

for ((attempt = 1; attempt <= attempts; attempt++)); do
  runs="$(gh api --method GET \
    "repos/${GITHUB_REPOSITORY}/actions/workflows/ci.yml/runs" \
    -f "head_sha=${SOURCE_SHA}" \
    -f status=success \
    -f per_page=100)"
  run_url="$(jq -r --arg sha "$SOURCE_SHA" '
    [.workflow_runs[] | select(
      .head_sha == $sha
      and .conclusion == "success"
      and (.event == "push" or .event == "workflow_dispatch")
    )]
    | sort_by(.run_number)
    | last
    | .html_url // empty
  ' <<<"$runs")"
  if [[ -n "$run_url" ]]; then
    printf 'release acceptance: exact-source CI passed: %s\n' "$run_url"
    exit 0
  fi
  printf 'release acceptance: waiting for successful CI at %s (%d/%d)\n' "$SOURCE_SHA" "$attempt" "$attempts"
  if (( attempt < attempts )); then
    sleep "$interval"
  fi
done

printf 'release acceptance: no successful CI workflow found for exact source %s\n' "$SOURCE_SHA" >&2
printf 'Run the full CI workflow for this commit and retry the release.\n' >&2
exit 1
