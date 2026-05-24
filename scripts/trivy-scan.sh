#!/usr/bin/env bash
set -euo pipefail

image_ref="${TEABAY_IMAGE_REF:-teabay:local}"
sdk_context="${CONTRIX_SDK_CONTEXT:-../contrix-rust-sdk}"
severity="${TRIVY_SEVERITY:-HIGH,CRITICAL}"
exit_code="${TRIVY_EXIT_CODE:-1}"

docker build \
  --build-context "contrix-rust-sdk=${sdk_context}" \
  -t "${image_ref}" \
  .

trivy image \
  --ignore-unfixed \
  --vuln-type os,library \
  --severity "${severity}" \
  --exit-code "${exit_code}" \
  "${image_ref}"
