#!/bin/sh
# DAST against the local crAPI stand: ZAP Automation Framework (authenticated, OpenAPI-driven) and Nuclei.
# Both tools run as containers attached to qa-crapi-net and address the stand by container name, so no
# port is published to the host and no other host can be reached (rules of engagement, guardrail 1).
# Usage: scripts/scan-dast.sh [zap|nuclei|all]   (default: all)
. "$(dirname "$0")/lib.sh"
TARGET=${1:-all}
NET=qa-crapi-net
OUT="$REPORTS/zap"
mkdir -p "$OUT"

docker network inspect "$NET" >/dev/null 2>&1 || {
  echo "scan-dast: $NET is missing — start the stand: make stand-up" >&2
  exit 2
}

# A session token for the scanners, created through the seeded user.
JWT=$(cd "$ROOT" && uv run python -c "
from security_tests.client import ALICE, CrapiClient
print(CrapiClient().login(ALICE))")
[ -n "$JWT" ] || { echo "scan-dast: could not obtain a token — run make seed" >&2; exit 2; }

if [ "$TARGET" = zap ] || [ "$TARGET" = all ]; then
  log "ZAP Automation Framework (budget: ~20 min)"
  # /zap/wrk holds the plan, the OpenAPI file and the output directory.
  docker run --rm --network "$NET" \
    -v "$(abs "$ROOT/stand"):/zap/wrk:ro" -v "$(abs "$OUT"):/zap/wrk/out" \
    -e ZAP_JWT="$JWT" \
    "$ZAP_IMAGE" zap.sh -cmd -autorun /zap/wrk/zap-plan.yaml || echo "zap: exit $?" >&2
  ls -l "$OUT"
fi

if [ "$TARGET" = nuclei ] || [ "$TARGET" = all ]; then
  log "Nuclei (misconfiguration, exposure, tech; rate limited)"
  docker run --rm --network "$NET" \
    -v "$(abs "$REPORTS"):/out" -v "$(abs "$CACHE"):/root/.config/nuclei" \
    "$NUCLEI_IMAGE" \
    -target http://crapi-web/ -target http://crapi-web/identity/api/ -target http://crapi-web/workshop/api/ \
    -tags misconfig,exposure,tech,default-login \
    -header "Authorization: Bearer $JWT" \
    -rate-limit 20 -timeout 10 -retries 1 -no-interactsh \
    -jsonl -output /out/nuclei.jsonl -stats -silent || echo "nuclei: exit $?" >&2
  printf 'nuclei findings: %s\n' "$(wc -l < "$REPORTS/nuclei.jsonl" 2>/dev/null || echo 0)"
fi
