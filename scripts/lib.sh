# shellcheck shell=sh
# Shared settings for the scan scripts (sourced, not executed).
# The variables are used by the scripts that source this file, not here.
# shellcheck disable=SC2034
# Every tool runs as a container pinned by tag AND multi-arch digest, so the same bytes run on
# Linux amd64 and Apple Silicon. No tool is installed on the host.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
REPORTS="$ROOT/reports"
CACHE="$ROOT/.cache"
mkdir -p "$REPORTS" "$CACHE"

GITLEAKS_IMAGE=zricethezav/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f
SEMGREP_IMAGE=semgrep/semgrep:1.183.0@sha256:2e45517a85e13a9cca14a2a00df6bb48affd66b8ebfae1b0991cd57578362fb0
TRIVY_IMAGE=aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c
SYFT_IMAGE=anchore/syft:v1.55.0@sha256:4cc92b64ca74ffca4c94d4c8fcc01f217731375300be14d0b6eeb2e82eaa110a
GRYPE_IMAGE=anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea
ZAP_IMAGE=ghcr.io/zaproxy/zaproxy:2.17.0@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238
NUCLEI_IMAGE=projectdiscovery/nuclei:v3.11.1@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb

# crAPI source for the SAST report: the same release as the stand's images.
CRAPI_REPO=https://github.com/OWASP/crAPI.git
CRAPI_TAG=v1.1.6

# Docker named volumes that cache vulnerability databases between runs (project prefix qa-).
TRIVY_CACHE_VOLUME=qa-devsecops-trivy-cache
GRYPE_CACHE_VOLUME=qa-devsecops-grype-cache

# Absolute host path in the form Docker accepts on Linux, macOS and Windows (Git Bash).
abs() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }

# crAPI service images, read from the stand's compose file: "<service> <image@digest>" per line.
crapi_images() {
  awk '/^  [a-z.-]+:$/ { svc = $1; sub(":", "", svc) }
       /^    image: crapi\// { print svc, $2 }' "$ROOT/stand/compose.yaml"
}

log() { printf '\n==> %s\n' "$*" >&2; }
