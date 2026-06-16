# Zolana workspace
set dotenv-load

export RUST_BACKTRACE := env_var_or_default("RUST_BACKTRACE", "0")
sbf-tools-version := env_var_or_default("SBF_TOOLS_VERSION", "v1.54")
surfpool-release-tag := env_var_or_default("SURFPOOL_RELEASE_TAG", "v1.1.1-light")
surfpool-version := env_var_or_default("SURFPOOL_VERSION", "1.1.1")
localnet-rpc-port := env_var_or_default("ZOLANA_LOCALNET_RPC_PORT", "8899")
localnet-rpc-url := env_var_or_default("ZOLANA_LOCALNET_URL", "http://127.0.0.1:8899")

mod forester 'forester'
mod prover 'prover/server'

default:
    @just --list

# === Rust workspace ===

# Build default workspace members.
build:
    cargo build

build-release:
    cargo build --release

# Check default workspace members.
check:
    cargo check

# Check the entire workspace.
check-all:
    cargo check --workspace --all-targets

# Default test target.
test: test-shielded-pool test-sdk-libs

# Program/interface tests for the shielded-pool implementation.
# Depends on build-programs so the litesvm tests load a fresh .so and actually
# run (without it `program_test()` finds no .so and the suite skips).
test-shielded-pool: build-programs
    cargo test -p zolana-interface --features solana
    cargo test -p shielded-pool-program --lib --tests
    cargo test -p shielded-pool-tests
    cargo test -p zolana-user-registry --tests
    cargo test -p user-registry-tests --test wire_layout

# User-registry litesvm tests only (no Light fixture bundle required).
test-user-registry-litesvm: build-programs
    cargo test -p user-registry-tests

# Unit, BDD, and property tests for the client-side SDK crates.
test-sdk-libs:
    cargo test -p zolana-keypair
    cargo test -p zolana-transaction

# All zolana-client tests (lib unit tests, the `transaction` integration test,
# and the `transfer_2_3` BDD suite). The BDD scenario spawns the prover server
# (via the zolana CLI), which lazily downloads transfer proving keys from the
# transfer-keys-v1 GitHub release using `gh` -- so this needs `gh` on PATH with
# auth (local `gh auth login`, or GH_TOKEN in CI). Builds the go prover binary
# and the zolana CLI the spawned server/test rely on.
test-client-integration: build-prover-server build-cli
    cargo test -p zolana-client

# Program integration tests backed by LiteSVM.
test-programs: build-programs
    cargo test -p shielded-pool-tests

# Aggregate of all CI-runnable Rust tests.
test-all: test test-programs test-user-registry-litesvm

# Rust-only verification for machines without Go installed.
verify-rust: check test

# Full verification for the reduced workspace.
verify: verify-rust prover-server-test

# === CLI ===

cli *args:
    cargo run -p zolana-cli -- {{args}}

build-cli:
    cargo build -p zolana-cli

test-cli:
    cargo test -p zolana-cli

# === Local validator helpers ===

test-localnet-proofless: build-programs
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cargo run -p zolana-cli -- test-validator --skip-prover --no-use-surfpool --rpc-port {{localnet-rpc-port}} --sbf-program "$SHIELDED_POOL_PROGRAM_ID" target/deploy/shielded_pool_program.so --sbf-program "$ZONE_TEST_PROGRAM_ID" target/deploy/zone_test_program.so
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" cargo test -p shielded-pool-tests --features localnet --test localnet_proofless_shield -- --nocapture

install-surfpool:
    #!/usr/bin/env bash
    set -euo pipefail
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    case "$(uname -m)" in
        x86_64|amd64) arch=x64 ;;
        arm64|aarch64) arch=arm64 ;;
        *) echo "unsupported surfpool architecture: $(uname -m)" >&2; exit 1 ;;
    esac
    asset="surfpool-${os}-${arch}.tar.gz"
    url="https://github.com/Lightprotocol/surfpool/releases/download/{{surfpool-release-tag}}/${asset}"
    mkdir -p target/tools
    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT
    curl -sSfL "$url" -o "$tmpdir/$asset"
    tar -xzf "$tmpdir/$asset" -C "$tmpdir"
    surfpool_bin=$(find "$tmpdir" -type f -name surfpool -perm -111 | head -n 1)
    if [[ -z "$surfpool_bin" ]]; then
        surfpool_bin=$(find "$tmpdir" -type f -name surfpool | head -n 1)
    fi
    if [[ -z "$surfpool_bin" ]]; then
        echo "surfpool binary not found in $asset" >&2
        exit 1
    fi
    cp "$surfpool_bin" target/tools/surfpool
    chmod +x target/tools/surfpool
    target/tools/surfpool --version | grep "{{surfpool-version}}"

# Build local SBF programs into `target/deploy`.
build-programs:
    SBF_TOOLS_VERSION={{sbf-tools-version}} ./tools/build-programs.sh

build-prover-server:
    mkdir -p target
    cd prover/server && go build -o ../../target/prover-server .

# === Formatting and linting ===

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# === Prover server ===

prover-server-test:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v go >/dev/null 2>&1; then
        echo "go is not installed; cannot run prover/server tests" >&2
        exit 1
    fi
    cd prover/server
    # Runs every package except the redis-dependent `server` package:
    # ./circuits/... (gnark solve/prove tests), ./prover/..., and
    # ./prover-test/... (reference + integration tests). The circuit and
    # integration tests run real groth16 setup+prove -- TestCircuitProvesFor-
    # SupportedShapes alone proves every supported shape -- so the run can exceed
    # Go's default 10m; the generous timeout is a ceiling, not a floor.
    go test ./circuits/... ./prover/... ./prover-test/... -timeout 60m

[private]
xtask-create-verifying-keys:
    cargo run -p xtask -- create-verifying-keys

[private]
xtask-create-verifying-keys-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    keys_dir=prover/server/proving-keys
    if [[ ! -d "$keys_dir" ]] || [[ -z "$(ls -A "$keys_dir" 2>/dev/null)" ]]; then
        echo "$keys_dir is missing or empty; skipping xtask verifying-keys smoke."
        echo "Populate $keys_dir locally (e.g. from the upstream gnark keys) to run this for real."
        exit 0
    fi
    cargo run -p xtask -- create-verifying-keys --limit 1

# === Maintenance ===

metadata:
    cargo metadata --format-version 1 --no-deps

clean:
    cargo clean
