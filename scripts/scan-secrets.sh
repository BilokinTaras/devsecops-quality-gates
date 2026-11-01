#!/bin/sh
# Secrets: Gitleaks over the FULL git history of this repository and of the sibling portfolio
# repositories that exist next to it. Reports: reports/gitleaks-<repo>.json (gate) and .sarif (code scanning).
# Usage: scripts/scan-secrets.sh            # this repo + siblings
#        SCAN_SIBLINGS=0 scripts/scan-secrets.sh   # this repo only (CI)
. "$(dirname "$0")/lib.sh"

SIBLINGS="shop-sut shop-e2e-playwright shop-api-pytest shop-performance-k6"
repos="$ROOT"
if [ "${SCAN_SIBLINGS:-1}" = "1" ]; then
  for name in $SIBLINGS; do
    [ -d "$ROOT/../$name/.git" ] && repos="$repos $ROOT/../$name"
  done
fi

for repo in $repos; do
  name=$(basename "$(cd "$repo" && pwd)")
  commits=$(cd "$repo" && git rev-list --all --count)
  log "gitleaks: $name ($commits commits, all branches)"
  for fmt in json sarif; do
    # The repository is mounted read-only; safe.directory is set for the container's git only.
    docker run --rm \
      -v "$(abs "$repo"):/repo:ro" -v "$(abs "$ROOT"):/cfg:ro" -v "$(abs "$REPORTS"):/out" \
      -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
      "$GITLEAKS_IMAGE" git /repo --log-opts=--all --config /cfg/.gitleaks.toml --redact --no-banner \
      --exit-code 0 --report-format "$fmt" --report-path "/out/gitleaks-$name.$fmt"
  done
  printf '%s: %s leak(s)\n' "$name" "$(jq length < "$REPORTS/gitleaks-$name.json")"
done
