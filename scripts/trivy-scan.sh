#!/usr/bin/env bash
#
# Build both teabay images and run trivy against them. Exits non-zero on
# the first HIGH or CRITICAL finding. Intended to be runnable both
# locally (operator has `docker` and `trivy` on PATH) and from CI (the
# `.github/workflows/ci.yml :: container-scan` job invokes equivalent
# steps directly so it can use the official aquasecurity/trivy-action).
#
# Env knobs:
#   TEABAY_SERVER_IMAGE_REF  default: teabay-server:local
#   TEABAY_ADMIN_IMAGE_REF   default: teabay-admin:local
#   ARKRET_SDK_CONTEXT      default: ../arkret-rust-sdk
#   TRIVY_SEVERITY           default: HIGH,CRITICAL
#   TRIVY_EXIT_CODE          default: 1
set -euo pipefail

server_image_ref="${TEABAY_SERVER_IMAGE_REF:-teabay-server:local}"
admin_image_ref="${TEABAY_ADMIN_IMAGE_REF:-teabay-admin:local}"
sdk_context="${ARKRET_SDK_CONTEXT:-../arkret-rust-sdk}"
severity="${TRIVY_SEVERITY:-HIGH,CRITICAL}"
exit_code="${TRIVY_EXIT_CODE:-1}"

if ! command -v trivy >/dev/null 2>&1; then
  echo "trivy not found on PATH." >&2
  echo "  install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/" >&2
  echo "  or rely on the CI 'container-scan' job which uses aquasecurity/trivy-action." >&2
  exit 2
fi

echo "==> building ${server_image_ref}"
docker build \
  --build-context "arkret-rust-sdk=${sdk_context}" \
  -f Dockerfile.server \
  -t "${server_image_ref}" \
  .

echo "==> building ${admin_image_ref}"
docker build \
  --build-context "arkret-rust-sdk=${sdk_context}" \
  -f Dockerfile.admin \
  -t "${admin_image_ref}" \
  .

scan_image() {
  local image_ref="$1"
  echo "==> trivy scan ${image_ref}"
  trivy image \
    --ignore-unfixed \
    --vuln-type os,library \
    --severity "${severity}" \
    --exit-code "${exit_code}" \
    "${image_ref}"
}

scan_image "${server_image_ref}"
scan_image "${admin_image_ref}"
