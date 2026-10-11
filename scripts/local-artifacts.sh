#!/usr/bin/env bash
set -euo pipefail

image_ref="${FLAGON_IMAGE_REF:-flagon:local}"
out_dir="${FLAGON_ARTIFACT_DIR:-artifacts}"
sdk_context="${ARKRET_SDK_CONTEXT:-../arkret-rust-sdk}"

mkdir -p "${out_dir}"

if [[ "${FLAGON_BUILD_IMAGE:-0}" == "1" ]]; then
  docker build \
    --build-context "arkret-rust-sdk=${sdk_context}" \
    -t "${image_ref}" \
    .
fi

syft "${image_ref}" -o "spdx-json=${out_dir}/flagon-image.spdx.json"
syft dir:. -o "spdx-json=${out_dir}/flagon-source.spdx.json"

if [[ -n "${COSIGN_KEY:-}" ]]; then
  cosign sign-blob \
    --yes \
    --tlog-upload=false \
    --key "${COSIGN_KEY}" \
    --bundle "${out_dir}/flagon-image.spdx.json.bundle" \
    "${out_dir}/flagon-image.spdx.json"
  cosign sign-blob \
    --yes \
    --tlog-upload=false \
    --key "${COSIGN_KEY}" \
    --bundle "${out_dir}/flagon-source.spdx.json.bundle" \
    "${out_dir}/flagon-source.spdx.json"
else
  cat <<'MSG'
SBOM files were written locally. Set COSIGN_KEY to sign them with cosign:
  COSIGN_KEY=cosign.key scripts/local-artifacts.sh
MSG
fi

cat <<MSG
Local artifacts are in ${out_dir}.
This script does not push images, create git tags, or publish crates.
MSG
