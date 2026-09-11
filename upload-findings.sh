#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: upload-findings.sh <head-sha> <head-trivy.json> <head-gitleaks.json> [<base-sha> <base-trivy.json> <base-gitleaks.json>]" >&2
  exit 1
}

[ $# -eq 3 ] || [ $# -eq 6 ] || usage

HEAD_SHA="$1"; HEAD_TRIVY="$2"; HEAD_GITLEAKS="$3"
BASE_SHA="${4:-}"; BASE_TRIVY="${5:-}"; BASE_GITLEAKS="${6:-}"

# Tags each finding with the commit it came from, so Apiiro can tell new
# findings (on the candidate commit) from pre-existing ones (on the baseline).
extract_trivy() {
  jq -c --arg sha "$2" '
    (.Results // [])[] as $r
    | (($r.Vulnerabilities // [])[] | {source: "trivy-vuln", commitSha: $sha} + .),
      (($r.Secrets // [])[] | {source: "trivy-secret", commitSha: $sha} + .)
  ' "$1" 2>/dev/null
}

extract_gitleaks() {
  jq -c --arg sha "$2" '(. // [])[] | {source: "gitleaks", commitSha: $sha} + .' "$1" 2>/dev/null
}

findings=$(
  {
    extract_trivy "$HEAD_TRIVY" "$HEAD_SHA"
    extract_gitleaks "$HEAD_GITLEAKS" "$HEAD_SHA"
    if [ -n "$BASE_SHA" ]; then
      extract_trivy "$BASE_TRIVY" "$BASE_SHA"
      extract_gitleaks "$BASE_GITLEAKS" "$BASE_SHA"
    fi
  } | jq -s '.'
)

echo "$findings" | apiiro api /rest-api/v1/uploadFindings -X POST -d @-
