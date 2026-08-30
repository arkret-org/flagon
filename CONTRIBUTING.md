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

teabay is the reference Arkret Directory Service. Keep changes focused on this
repository and preserve the Directory Service boundary: source Stations
remain authoritative for identity, authorization, membership, and source event
state.

## Local Setup

Prerequisites:

- Rust 1.88 or newer.
- PostgreSQL 14 or newer.
- `diesel_cli` with Postgres support.
- A sibling `../arkret-rust-sdk` checkout matching the version required by
  `Cargo.toml`.
- Dioxus CLI 0.7.9 or newer for the admin SPA.

Local service bootstrap:

```bash
scripts/dev-up.sh
```

Manual bootstrap:

```bash
cargo install diesel_cli --no-default-features --features postgres
createdb teabay
cp .env.example .env
diesel setup
cargo run -p server
```

## Admin SPA

The Dioxus admin console lives in `crates/admin/`.

```bash
cd crates/admin
dx serve --platform web --port 8080
```

Use `TEABAY_ADMIN_TOKEN` as the bearer token in the console. The API base is
usually `http://localhost:7781` for local development.

## Validation

Run the checks that match the files you changed:

```bash
cargo +nightly fmt --all -- --check
cargo check --locked --all-targets
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked
cargo check --locked --manifest-path crates/admin/Cargo.toml --target wasm32-unknown-unknown
typos --config typos.toml .
cargo deny check
cargo audit --ignore RUSTSEC-2025-0111 --ignore RUSTSEC-2025-0134
```

Docker-backed conformance tests are opt-in:

```bash
TEABAY_RUN_DOCKER_TESTS=1 cargo test --locked -p server --test it -- --nocapture
```

## Documentation

Update `docs/` when changing:

- architecture or route topology
- deployment configuration
- operational runbooks
- freshness, TTL, stale, or divergence behavior
- anti-enumeration behavior
- admin console workflows

## Commit Hygiene

Use concise commit subjects. For local teabay task slices, prefer:

```text
teabay: describe the change
```

Do not commit unrelated dirty files. In particular, do not include `Cargo.lock`
unless the dependency graph changed as part of the task.
