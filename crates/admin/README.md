# Flagon audit console

Glory and Sapid render the original read-only operator audit screen. The API
base and bearer token stay in memory; Load fetches the typed audit feed and
Verify checks its append-only digest chain. The console cannot modify the
public Realm index.

Build from the repository root with the sibling SDK and local UI checkouts:

```powershell
$bindgenVersion = python scripts/build-admin-web.py --print-bindgen-version
cargo install wasm-bindgen-cli --version $bindgenVersion --locked
python scripts/build-admin-web.py --release
$metadata = cargo metadata --no-deps --format-version 1 | ConvertFrom-Json
python scripts/serve-admin.py --dir (Join-Path $metadata.target_directory "web") --port 8080
```

The wasm-bindgen CLI must match the version locked in Cargo.lock. The build
script inherits the calling environment and asks Cargo for its target directory. Fresh CI checkouts use .ci/checkout-ui-dependencies.sh; existing UI
checkouts are reused.

Point API base at the service (usually http://localhost:7781) and enter its
operator bearer token. API origin, authorization, Since, Limit, loading/error
states, Unicode detail truncation and successful/failed verification are
covered by the actual browser tests:

```powershell
$env:FLAGON_E2E_WEB_DIR = Join-Path $metadata.target_directory 'web'
$env:FLAGON_E2E_CHANNEL='msedge'
npm ci
npm run test:admin
```

Migration references are original Dioxus source and actual original WASM/DOM
screenshots at d8b3161. The old CLI failed in its metadata bootstrap, so the
reference used cargo build and matching wasm-bindgen, with the original CSS
linked by the static host. Original and migrated snapshots use the same
non-empty HTTP-contract data and viewports. Raw artifacts are ignored under
artifacts/glory-migration; no live backend authorization or Docker run is
implied by those browser checks.

Local migration validation: 4 native unit/contract tests, native and WASM
Clippy, release WASM, 5 Edge browser cases, 12 original/migrated layout
comparisons, 2 Compose parser cases, static syntax and web release packaging
passed. Layout measurements have no geometry/typography differences above 1 px;
the source font weight is explicitly retained after the Glory host reset.
