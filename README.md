# Zolana

## In scope

| Path | Role |
|---|---|
| `programs/` | On-chain SPP programs, including `shielded-pool` |
| `program-libs/` | Shared Rust interface crate |
| `program-tests/` | Internal test crates and test-only SBF programs |
| `sdk-libs/` | Rust SDK, client, and indexer API crates |
| `cli/` | Zolana developer and operator CLI |
| `services/photon/` | Photon indexer, migrations, snapshots, and JSON-RPC service |
| `forester/` | Off-chain nullifier-tree maintenance skeleton |
| `prover/` | Go prover server + Rust prover client |
| `xtask/` | Workspace dev tooling |

## Build from a fresh clone (Ubuntu / Debian)

Install Rust with rustup, then run these commands from the repository root.
`build-essential` alone is enough for the default Rust build, but the full
workspace also compiles Go libraries and native dependencies.

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential ca-certificates git curl python3 \
  clang libclang-dev cmake pkg-config libssl-dev protobuf-compiler golang-go

# Load rustup's tools in this shell if you just installed Rust.
. "$HOME/.cargo/env"
rustup toolchain install   # uses rust-toolchain.toml (currently Rust 1.98.1)
cargo install just --locked

just build                # compile the default workspace members
just check-all            # type-check all workspace members and targets
just build-cli            # target/debug/zolana
just build-photon         # target/debug/photon
```

Use `apt` on Ubuntu / Debian; `apk` is Alpine's package manager. These steps
were checked on Ubuntu 24.04, not Alpine.

The Go modules require Go 1.27.1. With the default `GOTOOLCHAIN=auto`, the Go
package supplied by Ubuntu 24.04 downloads the required toolchain on first use.
If automatic toolchain downloads are disabled, install Go 1.27.1 or newer
separately. Go, Clang, and libclang are required by `just check-all`, because
Rust build scripts compile the example prover libraries and generate bindings.
Python 3 is used when `just` evaluates the root justfile.

The first build needs network access for Rust/Go toolchains and dependencies,
including Cargo git dependencies. `just build` uses the narrow default member
set; it does not build the CLI, Photon, or deployable Solana programs. For SBF
programs and tests, install the additional tools listed below.

Dependency updates retain the Solana/SBF compatibility constraints in
`Cargo.toml`. Keep gnark 0.15.0 and gnark-crypto 0.20.1 aligned across all Go
modules: upgrading to gnark 0.16.3 changes circuit fingerprints and requires a
coordinated proving-key rotation. `just prover-server-test` checks the committed
fingerprints; do not refresh them merely to accept a dependency update.

## Common entry points

All workflows go through `just`. Run `just` with no arguments for the full list.

```bash
just check-all         # cargo check across the workspace
just test-hermetic     # fast suite that needs nothing running
just test-all          # adds the prover-backed suites
just test-photon       # Photon unit and SQLite-backed integration tests
just build-photon      # Build the same Photon binary localnet tests execute
just verify-rust       # check + Rust tests
just verify            # verify-rust + prover/server go tests
```

## Fast versus full

Tests are split by what has to be running.

- `just test-hermetic` is the whole hermetic suite of SDK, ring, LiteSVM,
  Mollusk, and Photon tests. It needs no prover, no validator, no network, and no
  proving keys at test runtime. Building the suite first requires the tools
  below and may download dependencies and SBF platform tools. CI
  runs these same suites on every push.
- `just test-all` adds the prover-backed suites. They spawn a prover server and
  pull proving keys, up to 5.4 GB for the full set. Run them when you touch a
  circuit or a proof path.
- The validator suites are separate recipes, `just test-spp-validator` and
  friends. They start a local validator, Photon, and a prover.

Everything prover-backed is behind a Cargo feature, so a plain `cargo test -p
<crate>` never starts a prover. `zolana-client` uses `proofs`, and
`shielded-pool-tests` uses `proofs` and `localnet`.

The Cargo workspace's `default-members` is deliberately narrow — `forester`,
`program-libs/interface`, and `programs/shielded-pool` — so a bare `cargo check` from the root
hits the production-critical surface quickly. For full-workspace coverage use `just check-all`.

## Install the CLI

Install the `zolana` binary straight from the repository (builds from source, so
it pulls the workspace's git dependencies; not published to crates.io):

```bash
cargo install --git https://github.com/helius-labs/zolana --tag v0.1.0-alpha zolana-cli
```

`zolana dev start` then fetches a version-pinned, pre-initialized localnet
(programs, account snapshots, prover, and Photon) from the matching release. See
[`cli/README.md`](cli/README.md) for commands and the `--local` dev flow.

## CI

Workflows under `.github/workflows/`:

- `rust.yml` — fmt, clippy, machete, check-all, per-area unit tests
- `photon.yml` — Photon contract tests, migrations, schema drift, and service tests
- `publish-image.yml` — container smoke tests, and publishes photon, prover and forester images to ECR
- `forester.yml` — forester compile check
- `prover-server.yml` — Go test suite + xtask smoke
- `enforce-pr-only.yml` — fails direct pushes to `main`

Area-specific workflows use path filters where appropriate. The shared Rust setup lives in
`.github/actions/setup-rust` (toolchain + cache + just).

Direct push protection on `main` requires repo Settings → Branches → Branch protection rules.
The workflow is a backstop, not the enforcement.

## Local prerequisites

- Rust 1.98.1 (pinned by `rust-toolchain.toml`)
- Native build dependencies and Python 3 as installed above
- `just` — `cargo install just --locked`
- `cargo-nextest` for the Rust test recipes —
  `cargo install cargo-nextest --locked`
- Go 1.27.1 or newer (for full-workspace checks, example prover libraries,
  and `prover/server` builds/tests)
- PostgreSQL 16 for the Photon production-database migration smoke test
- Anza / Solana CLI 4.x providing `cargo build-sbf` for SBF program builds,
  including `just test-hermetic`; `just build-programs` pins platform tools to
  `v1.54` by default and downloads them on first use
- `just build-cli`, `just install-surfpool`,
  `just build-prover-server`, and `just build-programs` for local validator flows
- Go for `just xtask-create-verifying-keys-smoke`, which exports through the
  prover server. It fetches the one proving key it needs into `target/` and
  checks it against the lockfile sha256.
