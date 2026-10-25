# Tag releases

Pushing a `v*` tag builds and publishes a GitHub Release after every required
build succeeds. `workflow_dispatch` builds the same artifacts without publishing
a release; use it before tagging. Existing source versions are not changed.

Sibling checkout revisions in the workflow are part of the release source set.
Before tagging, update those pins to a compatible tested set and commit any
required Cargo.lock changes. Do not replace pinned revisions with `main`. Each
archive includes `build-info.json` with the source commits and lockfile hash,
and a companion SHA-256 file. Verify it from the download directory with
`sha256sum --check ./*.sha256`.

Cross-repository private dependencies require `CI_REPO_TOKEN` with read access;
`GITHUB_TOKEN` only supplies the current repository's permissions. Publishing
uses the release job's `contents: write` permission.

Artifacts contain `flagon` (the server executable) and `flagon-index` for Linux
x64/ARM64, Windows x64 and macOS ARM64. Configure PostgreSQL and service
identity as described in README.md. Linux builds target Ubuntu 24.04
(glibc 2.39 or newer).

The release workflow also builds a static Glory/Sapid WASM audit-console
archive. Its Cargo target/web directory is produced by scripts/build-admin-web.py
and packaged with --target wasm32-unknown-unknown --web. UI checkout pins live in
.ci/checkout-ui-dependencies.sh; the Docker images consume equivalent named
contexts so their Cargo workspace can resolve the same local paths.
