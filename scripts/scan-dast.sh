#!/bin/sh
# DAST against the local crAPI stand: ZAP Automation Framework (authenticated, OpenAPI-driven) and Nuclei.
# Both tools run as containers attached to qa-crapi-net and address the stand by container name, so no
# port is published to the host and no other host can be reached (rules of engagement, guardrail 1).
# Usage: scripts/scan-dast.sh [zap|nuclei|all]   (default: all)
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
TARGET=${1:-all}
NET=qa-crapi-net
OUT="$REPORTS/zap"
mkdir -p "$OUT"
# The ZAP image runs as its own user (zap, uid 1000). On Docker Desktop bind mounts are writable by any
# container user; on a Linux CI runner they keep the host owner, and ZAP fails to write its report with
# AccessDeniedException. The directory holds only generated reports.
chmod 777 "$OUT"

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
  # The plan and the OpenAPI file are read-only; reports go to a separate mount, because a writable
  # directory cannot be mounted inside a read-only one.
  docker run --rm --network "$NET" \
    -v "$(abs "$ROOT/stand"):/zap/plan:ro" -v "$(abs "$OUT"):/zap/out" \
    -e ZAP_JWT="$JWT" \
    "$ZAP_IMAGE" zap.sh -cmd -autorun /zap/plan/zap-plan.yaml || echo "zap: exit $?" >&2
  ls -l "$OUT"
fi

if [ "$TARGET" = nuclei ] || [ "$TARGET" = all ]; then
  # Two passes into the same file: the tag selection, and one template that must match on any plain-HTTP
  # host. The second pass is a self-check — an empty result from the first pass means "nothing matched",
  # not "the scanner never reached the target", which is a mistake this project already made once.
  # -system-resolvers is required: nuclei's own resolvers cannot see Docker's internal DNS.
  : > "$REPORTS/nuclei.jsonl"
  for pass in "-tags misconfig,exposure,tech,default-login" "-id http-missing-security-headers"; do
    log "Nuclei: $pass"
    # shellcheck disable=SC2086
    docker run --rm --network "$NET" \
      -v "$(abs "$REPORTS"):/out" -v "$(abs "$CACHE"):/root/.config/nuclei" \
      "$NUCLEI_IMAGE" \
      -target http://crapi-web/ -target http://crapi-web/identity/api/ -target http://crapi-web/workshop/api/ \
      $pass \
      -header "Authorization: Bearer $JWT" \
      -rate-limit 20 -timeout 10 -retries 1 -no-interactsh -system-resolvers \
      -jsonl -output /out/nuclei-pass.jsonl -stats -silent || echo "nuclei: exit $?" >&2
    cat "$REPORTS/nuclei-pass.jsonl" >> "$REPORTS/nuclei.jsonl" 2>/dev/null
    rm -f "$REPORTS/nuclei-pass.jsonl"
  done
  printf 'nuclei findings: %s\n' "$(wc -l < "$REPORTS/nuclei.jsonl" 2>/dev/null || echo 0)"
fi
