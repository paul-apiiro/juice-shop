#!/usr/bin/env bash
set -euo pipefail

# Payload shape is Lim.RestAPI.FindingsReportBody (see apiiro/lim
# src/Lim.RestAPI/Entities/FindingsReportBody.cs and FindingBody.cs).
# One report per (commit x tool-category): mixing findings from different
# commits in a single report fails FindingsReportBody.CheckValidity()
# ("More than one source control values").

usage() {
  echo "usage: upload-findings.sh <head-sha> <head-branch> <head-trivy.json> <head-gitleaks.json> [<base-sha> <base-branch> <base-trivy.json> <base-gitleaks.json>]" >&2
  exit 1
}

: "${REPOSITORY_KEY:?REPOSITORY_KEY env var is required}"
: "${REPOSITORY_CLONE_URL:?REPOSITORY_CLONE_URL env var is required}"
: "${RUN_ID:?RUN_ID env var is required}"
SCAN_PROJECT_NAME="${SCAN_PROJECT_NAME:-security-gate}"

[ $# -eq 4 ] || [ $# -eq 8 ] || usage

HEAD_SHA="$1"; HEAD_BRANCH="$2"; HEAD_TRIVY="$3"; HEAD_GITLEAKS="$4"
BASE_SHA="${5:-}"; BASE_BRANCH="${6:-}"; BASE_TRIVY="${7:-}"; BASE_GITLEAKS="${8:-}"

MAPSEV='def mapsev:
  if . == "CRITICAL" then "Critical"
  elif . == "HIGH" then "High"
  elif . == "MEDIUM" then "Medium"
  elif . == "LOW" then "Low"
  else "Unknown" end;'

trivy_vuln_findings() {
  jq -c "$MAPSEV"'
    [ (.Results // [])[] as $r
      | ($r.Vulnerabilities // [])[]
      | {
          FindingId: (.VulnerabilityID + ":" + .PkgName),
          FindingType: "Sca",
          FindingName: (.Title // .VulnerabilityID),
          Description: (.Description // ""),
          ProviderSeverity: .Severity,
          FindingSeverity: (.Severity | mapsev),
          References: {
            CodeReferences: [{
              RelativeFilePath: $r.Target,
              LineNumber: 0,
              LastLineInFile: 0,
              SourceControl: {RepositoryCloneUrl: $cloneUrl, CommitSha: $sha, BranchName: $branch}
            }]
          }
        }
    ]' --arg sha "$2" --arg branch "$3" --arg cloneUrl "$REPOSITORY_CLONE_URL" "$1" 2>/dev/null || echo "[]"
}

trivy_secret_findings() {
  jq -c "$MAPSEV"'
    [ (.Results // [])[] as $r
      | ($r.Secrets // [])[]
      | {
          FindingId: (.RuleID + ":" + $r.Target + ":" + (.StartLine | tostring)),
          FindingType: "SecretDetection",
          FindingName: (.Title // .RuleID),
          Description: (.Category // .RuleID),
          ProviderSeverity: .Severity,
          FindingSeverity: (.Severity | mapsev),
          Evidence: [{Type: "Secret", Value: {(.Match): ""}}],
          References: {
            CodeReferences: [{
              RelativeFilePath: $r.Target,
              LineNumber: .StartLine,
              LastLineInFile: .EndLine,
              SourceControl: {RepositoryCloneUrl: $cloneUrl, CommitSha: $sha, BranchName: $branch}
            }]
          }
        }
    ]' --arg sha "$2" --arg branch "$3" --arg cloneUrl "$REPOSITORY_CLONE_URL" "$1" 2>/dev/null || echo "[]"
}

gitleaks_findings() {
  jq -c '
    [ (. // [])[]
      | {
          FindingId: .Fingerprint,
          FindingType: "SecretDetection",
          FindingName: .RuleID,
          Description: (.Description // .RuleID),
          ProviderSeverity: null,
          FindingSeverity: "High",
          Evidence: [{Type: "Secret", Value: {(.Secret): ""}}],
          References: {
            CodeReferences: [{
              RelativeFilePath: .File,
              LineNumber: .StartLine,
              LastLineInFile: .EndLine,
              SourceControl: {RepositoryCloneUrl: $cloneUrl, CommitSha: $sha, BranchName: $branch}
            }]
          }
        }
    ]' --arg sha "$2" --arg branch "$3" --arg cloneUrl "$REPOSITORY_CLONE_URL" "$1" 2>/dev/null || echo "[]"
}

upload_report() {
  local scan_type="$1" provider_name="$2" provider_id="$3" scan_id_suffix="$4" sha="$5" findings_json="$6"
  local scan_id=$(( RUN_ID * 100 + scan_id_suffix ))

  jq -n \
    --argjson scanId "$scan_id" \
    --arg scanProjectName "$SCAN_PROJECT_NAME" \
    --arg providerName "$provider_name" \
    --arg providerId "$provider_id" \
    --arg scanType "$scan_type" \
    --arg repositoryKey "$REPOSITORY_KEY" \
    --arg commitSha "$sha" \
    --argjson findings "$findings_json" \
    '{
      ScanId: $scanId,
      ScanProjectName: $scanProjectName,
      ProviderName: $providerName,
      ProviderId: $providerId,
      ScanType: $scanType,
      IsTransient: true,
      RepositoryKey: $repositoryKey,
      CommitSha: $commitSha,
      Findings: $findings
    }' | apiiro api /rest-api/v1/uploadFindings -X POST -d @-
}

upload_report "Sca"             "Trivy"     "trivy-fs"       0 "$HEAD_SHA" "$(trivy_vuln_findings "$HEAD_TRIVY" "$HEAD_SHA" "$HEAD_BRANCH")"
upload_report "SecretDetection" "Trivy"     "trivy-fs"       1 "$HEAD_SHA" "$(trivy_secret_findings "$HEAD_TRIVY" "$HEAD_SHA" "$HEAD_BRANCH")"
upload_report "SecretDetection" "Gitleaks"  "gitleaks"       2 "$HEAD_SHA" "$(gitleaks_findings "$HEAD_GITLEAKS" "$HEAD_SHA" "$HEAD_BRANCH")"

if [ -n "$BASE_SHA" ]; then
  upload_report "Sca"             "Trivy"    "trivy-fs"      3 "$BASE_SHA" "$(trivy_vuln_findings "$BASE_TRIVY" "$BASE_SHA" "$BASE_BRANCH")"
  upload_report "SecretDetection" "Trivy"    "trivy-fs"      4 "$BASE_SHA" "$(trivy_secret_findings "$BASE_TRIVY" "$BASE_SHA" "$BASE_BRANCH")"
  upload_report "SecretDetection" "Gitleaks" "gitleaks"      5 "$BASE_SHA" "$(gitleaks_findings "$BASE_GITLEAKS" "$BASE_SHA" "$BASE_BRANCH")"
fi
