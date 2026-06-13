# Zolana workspace
set dotenv-load

export RUST_BACKTRACE := env_var_or_default("RUST_BACKTRACE", "0")
sbf-tools-version := env_var_or_default("SBF_TOOLS_VERSION", "v1.54")
surfpool-release-tag := env_var_or_default("SURFPOOL_RELEASE_TAG", "v1.1.1-light")
surfpool-version := env_var_or_default("SURFPOOL_VERSION", "1.1.1")
localnet-rpc-port := env_var_or_default("ZOLANA_LOCALNET_RPC_PORT", "8899")
localnet-faucet-port := env_var_or_default("ZOLANA_LOCALNET_FAUCET_PORT", "9900")
localnet-state-dir := env_var_or_default("ZOLANA_LOCALNET_STATE_DIR", "target/localnet")
shielded-pool-program-id := "S7exd9VLhvwVWK9wqRGQrg87616fGnyYEvrsuA1D2LG"
zone-test-program-id := "9EwHno8C1T1vVGjasGnDH1GubiEu8qbgLX9qDjBshFhz"

mod prover 'prover/server'
mod forester 'forester'

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

# Default test target. Tests the shielded-pool implementation, SDKs, and Forester.
test: test-shielded-pool test-sdk-libs test-forester

# Program/interface tests for the shielded-pool implementation.
test-shielded-pool:
    cargo test -p zolana-interface --features solana
    cargo test -p shielded-pool-program --lib --tests

# Unit, BDD, and property tests for the client-side SDK crates.
test-sdk-libs:
    cargo test -p zolana-keypair
    cargo test -p zolana-transaction

test-forester:
    cargo test -p forester

# End-to-end litesvm tests for shielded-pool.
test-litesvm: build-program-test-sbf
    cargo test -p shielded-pool-tests

[private]
build-program-test-sbf:
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path programs/shielded-pool/Cargo.toml -- --features bpf-entrypoint
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path program-tests/zone-test-program/Cargo.toml

# Run one localnet test against a validator loaded with the real SBF programs.
test-localnet test="localnet_proofless_shield": start-localnet-validator
    @echo "localnet rpc: http://127.0.0.1:{{localnet-rpc-port}}"
    ZOLANA_LOCALNET_URL="http://127.0.0.1:{{localnet-rpc-port}}" cargo test -p shielded-pool-tests --features localnet --test {{replace(test, "test=", "")}} -- --nocapture

test-localnet-proofless:
    @just test-localnet localnet_proofless_shield

start-localnet: start-localnet-validator
    @echo "localnet rpc: http://127.0.0.1:{{localnet-rpc-port}}"

[private]
start-localnet-validator: build-program-test-sbf
    mkdir -p "{{localnet-state-dir}}"
    just cli test-validator \
        --no-use-surfpool \
        --skip-prover \
        --skip-system-accounts \
        --rpc-port {{localnet-rpc-port}} \
        --faucet-port {{localnet-faucet-port}} \
        --ledger "{{localnet-state-dir}}/ledger" \
        --log-dir "{{localnet-state-dir}}/logs" \
        --sbf-program {{shielded-pool-program-id}} target/deploy/shielded_pool_program.so \
        --sbf-program {{zone-test-program-id}} target/deploy/zone_test_program.so

stop-localnet:
    just cli test-validator --no-use-surfpool --skip-prover --rpc-port {{localnet-rpc-port}} --stop

stop-localnet-proofless:
    @just stop-localnet

# Aggregate of all CI-runnable Rust tests.
test-all: test test-litesvm

# Rust-only verification for machines without Go installed.
verify-rust: check test

# Full verification for the reduced workspace.
verify: verify-rust prover-server-test

# === CLI and Fixtures ===

cli *args:
    cargo run -p zolana-cli -- {{args}}

build-cli:
    cargo build -p zolana-cli

test-cli:
    cargo test -p zolana-cli

# Build account fixtures from an explicit source tree.
build-fixtures:
    ./tools/build-fixtures.sh

# Build fixtures and package them for manual distribution.
package-fixtures:
    ./tools/package-fixtures.sh "${FIXTURES_DIR:-target/fixtures/staging}"

# Verify the local fixture directory. Override with FIXTURES_DIR=/path.
verify-fixtures:
    ./tools/verify-fixtures.sh "${FIXTURES_DIR:-target/fixtures/staging}"

# Install verified local fixtures into the user cache.
install-fixtures:
    ./tools/install-fixtures.sh "${FIXTURES_DIR:-target/fixtures/staging}"

# Build local SBF programs into `target/deploy`.
build-programs:
    SBF_TOOLS_VERSION={{sbf-tools-version}} ./tools/build-programs.sh

# === Local validator helpers ===

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
    # Skip Redis-backed server tests; TestCombined needs more than Go's default 10m timeout.
    go test ./prover/... -timeout 60m

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
