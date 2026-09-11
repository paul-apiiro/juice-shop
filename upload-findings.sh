#!/usr/bin/env bash
set -euo pipefail

# NOTE: the exact request shape for uploading external findings is defined at
# https://docs.apiiro.com/api (auth-gated, not verified in this session).
# Confirm the path/payload against that reference before relying on this in CI.

TRIVY_FILE="${1:?usage: upload-findings.sh <trivy.json> <gitleaks.json> <commit-sha>}"
GITLEAKS_FILE="${2:?usage: upload-findings.sh <trivy.json> <gitleaks.json> <commit-sha>}"
COMMIT_SHA="${3:?usage: upload-findings.sh <trivy.json> <gitleaks.json> <commit-sha>}"

payload=$(jq -n \
  --arg sha "$COMMIT_SHA" \
  --slurpfile trivy "$TRIVY_FILE" \
  --slurpfile gitleaks "$GITLEAKS_FILE" \
  '{commitSha: $sha, trivy: $trivy[0], gitleaks: $gitleaks[0]}')

echo "$payload" | apiiro api "/rest-api/v1/diffScans/findings" -X POST -d @-
