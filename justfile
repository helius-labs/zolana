# Zolana reduced Light Protocol workspace
set dotenv-load

export RUST_BACKTRACE := env_var_or_default("RUST_BACKTRACE", "0")
export FORESTER_E2E_ITERATIONS := env_var_or_default("FORESTER_E2E_ITERATIONS", "100")
export FORESTER_E2E_EXPECTED_MIN_PROCESSED_ITEMS := env_var_or_default("FORESTER_E2E_EXPECTED_MIN_PROCESSED_ITEMS", "100")
export FORESTER_E2E_TIMEOUT_SECONDS := env_var_or_default("FORESTER_E2E_TIMEOUT_SECONDS", "900")
export FORESTER_E2E_SLOT_WARP_STEP := env_var_or_default("FORESTER_E2E_SLOT_WARP_STEP", "50")
export FORESTER_E2E_SLOT_WARP_INTERVAL_MS := env_var_or_default("FORESTER_E2E_SLOT_WARP_INTERVAL_MS", "2000")
sbf-tools-version := env_var_or_default("SBF_TOOLS_VERSION", "v1.54")
surfpool-release-tag := env_var_or_default("SURFPOOL_RELEASE_TAG", "v1.1.1-light")
surfpool-version := env_var_or_default("SURFPOOL_VERSION", "1.1.1")

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

test-forester-smoke:
    cargo test -p forester --test metrics_contract_test
    cargo test -p forester --test test_nullify_state_v1_multi_tx_size
    cargo test -p forester --test priority_fee_test

# Default test target keeps CI cheap while preserving forester test compilation.
test: test-forester-compile test-forester-smoke

# Cheap tests for the initial shielded-pool/interface/registry scaffold.
test-scaffold:
    cargo test -p zolana-interface --features solana
    cargo test -p shielded-pool-program --lib --tests
    cargo test -p shielded-pool-tests
    cargo test -p registry-tests

# Unit and integration tests for the compressed-token program (lib + tests dir).
test-compressed-token:
    cargo test -p light-compressed-token --lib --tests

# SDK library tests that do not require a running validator or prover.
test-sdk-libs:
    cargo test -p light-event
    cargo test -p light-token
    cargo test -p light-compressed-token-sdk

# Aggregate of all CI-runnable rust tests except the forester e2e suite.
test-all: test-scaffold test-compressed-token test-sdk-libs test-forester-smoke

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
    if [[ -n "${ZOLANA_CLI_CMD:-}" ]]; then
        echo "Using ZOLANA_CLI_CMD=$ZOLANA_CLI_CMD"
    elif [[ -n "${LIGHT_CLI_CMD:-}" ]]; then
        echo "Using LIGHT_CLI_CMD=$LIGHT_CLI_CMD"
    elif [[ -n "${ZOLANA_CLI_BIN:-}" ]]; then
        test -x "$ZOLANA_CLI_BIN"
        echo "Using ZOLANA_CLI_BIN=$ZOLANA_CLI_BIN"
    elif [[ -n "${LIGHT_CLI_BIN:-}" ]]; then
        test -x "$LIGHT_CLI_BIN"
        echo "Using LIGHT_CLI_BIN=$LIGHT_CLI_BIN"
    elif [[ -x target/debug/zolana ]]; then
        echo "Using target/debug/zolana"
    elif [[ -x target/release/zolana ]]; then
        echo "Using target/release/zolana"
    elif command -v zolana >/dev/null 2>&1; then
        echo "Using zolana from PATH: $(command -v zolana)"
    else
        echo "zolana CLI not found. Run 'just build-zolana-cli', set ZOLANA_CLI_BIN, or set ZOLANA_CLI_CMD." >&2
        exit 1
    fi

build-zolana-cli:
    cargo build -p zolana-cli

# Download and verify the Light test-validator fixtures pinned in
# .fixtures-version into ${ZOLANA_CACHE_DIR:-$HOME/.cache/zolana}/fixtures/<tag>.
# Idempotent: no-op when the cache already has a verified bundle.
fetch-fixtures:
    #!/usr/bin/env bash
    set -euo pipefail
    tag=$(tr -d '[:space:]' < .fixtures-version)
    cache_root="${ZOLANA_CACHE_DIR:-$HOME/.cache/zolana}"
    dest="${cache_root}/fixtures/${tag}"
    if [[ -f "${dest}/SHA256SUMS" ]] && (cd "$dest" && shasum -a 256 -c SHA256SUMS >/dev/null 2>&1); then
        echo "fixtures ${tag} already cached at ${dest}"
        exit 0
    fi
    rm -rf "$dest"
    mkdir -p "$dest"
    url="https://github.com/helius-labs/zolana/releases/download/${tag}/light-fixtures.tar.gz"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    echo "fetching ${url}"
    curl -sSfL "$url" -o "$tmp/light-fixtures.tar.gz"
    tar -xzf "$tmp/light-fixtures.tar.gz" -C "$dest"
    cd "$dest" && shasum -a 256 -c SHA256SUMS
    echo "fixtures ${tag} ready at ${dest}"

# Back-compat alias; build-light-programs and CI used to invoke this.
verify-light-fixtures: fetch-fixtures

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

# Build the Photon indexer binary from the commit pinned in `external/photon`.
# Debug mode is enough for local validator tests and avoids the long release
# compile that `cargo install --git` would do in every CI forester job.
install-photon:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ! -e external/photon/.git ]]; then
        echo "external/photon submodule not initialized; run 'git submodule update --init --recursive'" >&2
        exit 1
    fi
    photon_rev=$(git -C external/photon rev-parse HEAD)
    echo "Building Photon indexer @ ${photon_rev} (from external/photon submodule)"
    cargo build --manifest-path external/photon/Cargo.toml --locked --bin photon
    mkdir -p target/tools
    cp external/photon/target/debug/photon target/tools/photon
    chmod +x target/tools/photon
    target/tools/photon --version
    if [[ "${CI:-}" == "true" ]]; then
        echo "Cleaning external/photon/target to leave disk for prover keys"
        rm -rf external/photon/target
    fi

build-light-programs: fetch-fixtures
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path programs/account-compression/Cargo.toml
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path programs/registry/Cargo.toml
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path programs/compressed-token/program/Cargo.toml
    mkdir -p target/deploy
    tag=$(tr -d '[:space:]' < .fixtures-version)
    fixtures="${ZOLANA_CACHE_DIR:-$HOME/.cache/zolana}/fixtures/${tag}"
    cp "${fixtures}/bin/spl_noop.so" target/deploy/spl_noop.so
    cp "${fixtures}/bin/light_system_program_pinocchio.so" target/deploy/light_system_program_pinocchio.so

build-forester-test-deps: build-light-programs
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path program-tests/create-address-test-program/Cargo.toml
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path sdk-tests/csdk-anchor-full-derived-test/Cargo.toml

build-prover-server:
    mkdir -p target
    cd prover/server && go build -o ../../target/prover-server .

# Run the forester PDA integration test that deploys the local csdk SBF fixture.
test-forester-pda: check-light-cli build-forester-test-deps
    cargo test -p forester --test test_compressible_pda -- --nocapture

# Run a bounded local forester e2e smoke. The zolana local validator launcher
# advances slots quickly and preloads V2 trees with 500/250 element ZKP batches,
# so this validates deterministic V1 state and compressible-account behavior.
test-forester-e2e: check-light-cli build-light-programs
    TEST_V1_ADDRESS=false TEST_V2_STATE=false TEST_V2_ADDRESS=false FORESTER_E2E_ITERATIONS=20 FORESTER_E2E_EXPECTED_MIN_PROCESSED_ITEMS=2 FORESTER_E2E_TIMEOUT_SECONDS=300 just forester::test

# Run the bounded local forester e2e smoke without rebuilding SBF dependencies.
test-forester-e2e-local: check-light-cli
    TEST_V1_ADDRESS=false TEST_V2_STATE=false TEST_V2_ADDRESS=false FORESTER_E2E_ITERATIONS=20 FORESTER_E2E_EXPECTED_MIN_PROCESSED_ITEMS=2 FORESTER_E2E_TIMEOUT_SECONDS=300 just forester::local

# Run the full forester e2e surface with all tree families enabled.
test-forester-e2e-full: check-light-cli build-light-programs
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
    # Scoped to ./prover/... (skips the redis-dependent `server` package tests)
    # and uses the upstream 60m timeout — TestCombined alone compiles ~672
    # groth16 circuits and exceeds Go's default 10m.
    go test ./prover/... -timeout 60m

xtask-create-verifying-keys:
    cargo run -p xtask -- create-verifying-keys

# Smoke-tests the xtask by hashing a single proving key. CI doesn't have the
# (gitignored, ~2.6GB) proving keys, so we skip cleanly when the directory is
# missing or empty rather than failing the build.
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
