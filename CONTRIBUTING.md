# Contributing

## Pre-commit hook setup

After cloning, enable the project's pre-commit hooks:

```sh
git config core.hooksPath .githooks
```

The hook runs `cargo +nightly fmt --all -- --check` and
`cargo clippy --no-deps -- -D warnings` on staged Rust changes. If
`.githooks/pre-commit` is missing, copy it from
[`arkret-rust-sdk`](https://github.com/arkret-org/arkret-rust-sdk) and
adapt to your local toolchain.

## Scope

flagon is the reference Arkret Directory Service. Keep changes focused on this
repository and preserve the Directory Service boundary: source Stations
remain authoritative for identity, authorization, membership, and source event
state.

## Local Setup

Prerequisites:

- Rust 1.98 or newer.
- PostgreSQL 14 or newer.
- `diesel_cli` with Postgres support.
- A sibling `../arkret-rust-sdk` checkout matching the version required by
  `Cargo.toml`.
- Local Glory/Sapid checkouts in `../../glory-rs/`, Python 3.11+, and a
  wasm-bindgen CLI matching Cargo.lock for the admin SPA.

Local service bootstrap:

```bash
scripts/dev-up.sh
```

Manual bootstrap:

```bash
cargo install diesel_cli --no-default-features --features postgres
createdb flagon
cp .env.example .env
diesel setup
cargo run -p server
```

## Admin SPA

The Glory/Sapid audit console lives in `crates/admin/`. Build it from the
repository root:

```bash
python scripts/build-admin-web.py --release
```

See [admin setup](crates/admin/README.md) for the static server, Windows D:
build paths, and the browser checks.

Use `FLAGON_ADMIN_TOKEN` as the bearer token in the console. The API base is
usually `http://localhost:7781` for local development.

## Validation

Run the checks that match the files you changed:

```bash
cargo +nightly fmt --all -- --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --workspace
cargo check --locked --manifest-path crates/admin/Cargo.toml --target wasm32-unknown-unknown
typos --config typos.toml .
cargo deny check
cargo audit --ignore RUSTSEC-2025-0111 --ignore RUSTSEC-2025-0134
```

The fresh-schema Docker-backed test is `#[ignore]`, so the workspace test
reports it as ignored. Run it explicitly; a missing Docker daemon fails the
run instead of skipping it:

```bash
cargo test --locked -p server --lib fresh_schema_has_only_empty_public_realm_index -- --include-ignored --nocapture
```

## Documentation

Update `docs/` when changing:

- architecture or route topology
- deployment configuration
- operator audit and fresh-schema checks
- public Realm read behavior
- admin console workflows

## Commit Hygiene

Use concise commit subjects. For local flagon task slices, prefer:

```text
flagon: describe the change
```

Do not commit unrelated dirty files. In particular, do not include `Cargo.lock`
unless the dependency graph changed as part of the task.
