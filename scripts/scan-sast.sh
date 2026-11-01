#!/bin/sh
# SAST with Semgrep (community rule packs from the Semgrep registry, metrics off).
#   own   — this repository's code: reports/semgrep.sarif + .json, input of the quality gate;
#   crapi — crAPI source at the stand's release tag: reports/semgrep-crapi.sarif + .json, a report only
#           (crAPI is a third-party target; its findings are triaged in docs/findings-static.md).
# Usage: scripts/scan-sast.sh [own|crapi|all]   (default: all)
. "$(dirname "$0")/lib.sh"
TARGET=${1:-all}

semgrep() {
  src=$1; shift
  docker run --rm -v "$(abs "$src"):/src" -v "$(abs "$REPORTS"):/out" -w /src \
    -e GIT_CONFIG_COUNT=1 -e GIT_CONFIG_KEY_0=safe.directory -e GIT_CONFIG_VALUE_0='*' \
    "$SEMGREP_IMAGE" semgrep scan --metrics off --disable-version-check --quiet "$@"
}

if [ "$TARGET" = own ] || [ "$TARGET" = all ]; then
  log "semgrep: own code"
  semgrep "$ROOT" \
    --config p/python --config p/security-audit --config p/secrets \
    --config p/dockerfile --config p/docker-compose \
    --exclude .cache --exclude reports \
    --sarif-output /out/semgrep.sarif --json-output /out/semgrep.json
  printf 'own code: %s finding(s)\n' "$(jq '.results | length' < "$REPORTS/semgrep.json")"
fi

if [ "$TARGET" = crapi ] || [ "$TARGET" = all ]; then
  src="$CACHE/crapi-src"
  if [ ! -d "$src/.git" ]; then
    log "cloning crAPI $CRAPI_TAG (shallow, read-only use)"
    (cd "$CACHE" && git clone --quiet --depth 1 --branch "$CRAPI_TAG" "$CRAPI_REPO" crapi-src)
  fi
  log "semgrep: crAPI $CRAPI_TAG services"
  semgrep "$src" \
    --config p/security-audit --config p/owasp-top-ten --config p/jwt \
    --config p/java --config p/golang --config p/python --config p/django \
    --sarif-output /out/semgrep-crapi.sarif --json-output /out/semgrep-crapi.json \
    services
  printf 'crAPI: %s finding(s)\n' "$(jq '.results | length' < "$REPORTS/semgrep-crapi.json")"
fi
