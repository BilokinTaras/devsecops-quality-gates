#!/bin/sh
# SCA, misconfiguration and SBOM.
#   repo   — Trivy over this repository: dependencies (uv.lock), IaC/compose misconfigurations, secrets.
#            reports/trivy-repo.json (gate input) and .sarif.
#   images — crAPI service images (the digests pinned in stand/compose.yaml, linux/amd64):
#            Trivy vulnerabilities, Syft SBOM (CycloneDX), Grype from that SBOM for comparison.
#            Third-party target: report only, summarised by tools/sca_summary.py.
# Images are read straight from the registry (no Docker socket is mounted into any tool).
# Usage: scripts/scan-sca.sh [repo|images|all]   (default: all)
# shellcheck source=lib.sh
. "$(dirname "$0")/lib.sh"
TARGET=${1:-all}
PLATFORM=${SCAN_PLATFORM:-linux/amd64}

trivy() {
  docker run --rm -v "$TRIVY_CACHE_VOLUME:/trivy-cache" -v "$(abs "$ROOT"):/src:ro" -v "$(abs "$REPORTS"):/out" \
    "$TRIVY_IMAGE" --cache-dir /trivy-cache --quiet "$@"
}

if [ "$TARGET" = repo ] || [ "$TARGET" = all ]; then
  log "trivy: repository"
  trivy fs --scanners vuln,misconfig,secret --skip-dirs .cache,reports,.venv \
    --format json --output /out/trivy-repo.json /src
  trivy convert --format sarif --output /out/trivy-repo.sarif /out/trivy-repo.json
fi

if [ "$TARGET" = images ] || [ "$TARGET" = all ]; then
  crapi_images | while read -r svc image; do
    ref="docker.io/$image"
    log "trivy + syft + grype: $svc"
    trivy image --image-src remote --platform "$PLATFORM" --scanners vuln \
      --format json --output "/out/trivy-image-$svc.json" "$ref"
    docker run --rm -v "$(abs "$REPORTS"):/out" "$SYFT_IMAGE" scan "registry:$ref" \
      --platform "$PLATFORM" --quiet -o "cyclonedx-json=/out/sbom-$svc.cdx.json"
    docker run --rm -v "$GRYPE_CACHE_VOLUME:/grype-cache" -v "$(abs "$REPORTS"):/out" \
      -e GRYPE_DB_CACHE_DIR=/grype-cache "$GRYPE_IMAGE" "sbom:/out/sbom-$svc.cdx.json" \
      --quiet -o json --file "/out/grype-$svc.json"
  done
fi
