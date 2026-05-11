# Zolana reduced Light Protocol workspace
set dotenv-load

export RUST_BACKTRACE := env_var_or_default("RUST_BACKTRACE", "0")
export FORESTER_E2E_ITERATIONS := env_var_or_default("FORESTER_E2E_ITERATIONS", "100")
export FORESTER_E2E_EXPECTED_MIN_PROCESSED_ITEMS := env_var_or_default("FORESTER_E2E_EXPECTED_MIN_PROCESSED_ITEMS", "100")
export FORESTER_E2E_TIMEOUT_SECONDS := env_var_or_default("FORESTER_E2E_TIMEOUT_SECONDS", "900")
export FORESTER_E2E_SLOT_WARP_STEP := env_var_or_default("FORESTER_E2E_SLOT_WARP_STEP", "50")
export FORESTER_E2E_SLOT_WARP_INTERVAL_MS := env_var_or_default("FORESTER_E2E_SLOT_WARP_INTERVAL_MS", "2000")
light-cli-package := env_var_or_default("LIGHT_CLI_PACKAGE", "@lightprotocol/zk-compression-cli@0.28.4")

mod forester 'forester'
mod prover 'prover/server'

default:
    @just --list

# === Setup ===

init-submodules:
    git submodule update --init --recursive

submodule-status:
    git submodule status --recursive

# === Rust workspace ===

# Build default workspace members.
build:
    cargo build

build-release:
    cargo build --release

# Check default workspace members.
check:
    cargo check

# Check the workspace plus forester test targets. SBF fixture crates are checked
# as libraries in the same no-entrypoint shape used by forester tests.
check-all:
    cargo check --workspace --exclude csdk-anchor-full-derived-test --exclude create-address-test-program
    cargo check -p forester --all-targets
    cargo check -p csdk-anchor-full-derived-test --lib --features no-entrypoint
    cargo check -p create-address-test-program --lib --features no-entrypoint

# Compile all forester test binaries without running the integration suite.
test-forester-compile:
    cargo test -p forester --no-run

# Fast runtime smoke test that does not require local SBF services.
test-forester-smoke:
    cargo test -p forester --test metrics_contract_test

# Default test target keeps CI cheap while preserving forester test compilation.
test: test-forester-compile test-forester-smoke

# Cheap tests for the initial shielded-pool/interface/registry scaffold.
test-scaffold:
    cargo test -p zolana-interface --features solana
    cargo test -p shielded-pool-program --lib --tests
    cargo test -p shielded-pool-tests
    cargo test -p registry-tests

# Check photon-api's OpenAPI regeneration path against external/photon.
check-photon-generate:
    cargo check -p photon-api --features generate

# Rust-only verification for machines without Go installed.
verify-rust: check test check-photon-generate

# Full verification for the reduced workspace.
verify: verify-rust prover-server-test

# === Forester SBF test helpers ===

check-light-cli:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -n "${LIGHT_CLI_CMD:-}" ]]; then
        echo "Using LIGHT_CLI_CMD=$LIGHT_CLI_CMD"
    elif [[ -n "${LIGHT_CLI_BIN:-}" ]]; then
        test -x "$LIGHT_CLI_BIN"
        echo "Using LIGHT_CLI_BIN=$LIGHT_CLI_BIN"
    elif command -v light >/dev/null 2>&1; then
        echo "Using light from PATH: $(command -v light)"
    elif command -v npm >/dev/null 2>&1; then
        echo "Using npm exec --yes --package {{light-cli-package}} -- light"
    else
        echo "Light CLI not found. Install npm and @lightprotocol/zk-compression-cli, set LIGHT_CLI_BIN, or set LIGHT_CLI_CMD." >&2
        exit 1
    fi

install-light-cli:
    npm install -g {{light-cli-package}}

build-forester-test-deps:
    cargo build-sbf --manifest-path program-tests/create-address-test-program/Cargo.toml
    cargo build-sbf --manifest-path sdk-tests/csdk-anchor-full-derived-test/Cargo.toml

# Run the forester PDA integration test that deploys the local csdk SBF fixture.
test-forester-pda: check-light-cli build-forester-test-deps
    cargo test -p forester --test test_compressible_pda -- --nocapture

# Run a bounded local forester e2e smoke. The npm Light CLI local validator
# advances slots quickly and preloads V2 trees with 500/250 element ZKP batches,
# so this validates deterministic V1 state and compressible-account behavior.
test-forester-e2e: check-light-cli
    TEST_V1_ADDRESS=false TEST_V2_STATE=false TEST_V2_ADDRESS=false FORESTER_E2E_ITERATIONS=20 FORESTER_E2E_EXPECTED_MIN_PROCESSED_ITEMS=2 FORESTER_E2E_TIMEOUT_SECONDS=300 just forester::test

# Run the bounded local forester e2e smoke without rebuilding SBF dependencies.
test-forester-e2e-local: check-light-cli
    TEST_V1_ADDRESS=false TEST_V2_STATE=false TEST_V2_ADDRESS=false FORESTER_E2E_ITERATIONS=20 FORESTER_E2E_EXPECTED_MIN_PROCESSED_ITEMS=2 FORESTER_E2E_TIMEOUT_SECONDS=300 just forester::local

# Run the full forester e2e surface with all tree families enabled.
test-forester-e2e-full: check-light-cli
    just forester::test-full

# Run the full forester e2e surface without rebuilding SBF dependencies.
test-forester-e2e-full-local: check-light-cli
    just forester::local-full

# === Formatting and linting ===

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets --exclude csdk-anchor-full-derived-test --exclude create-address-test-program -- -D warnings
    cargo clippy -p csdk-anchor-full-derived-test --lib --features no-entrypoint -- -D warnings
    cargo clippy -p create-address-test-program --lib --features no-entrypoint -- -D warnings

# === Prover server ===

prover-server-test:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v go >/dev/null 2>&1; then
        echo "go is not installed; cannot run prover/server tests" >&2
        exit 1
    fi
    cd prover/server
    go test ./...

xtask-create-verifying-keys:
    cargo run -p xtask -- create-verifying-keys

xtask-create-verifying-keys-smoke:
    cargo run -p xtask -- create-verifying-keys --limit 1

# === Maintenance ===

metadata:
    cargo metadata --format-version 1 --no-deps

clean:
    cargo clean
