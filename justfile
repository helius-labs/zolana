# Zolana workspace
set dotenv-load

export RUST_BACKTRACE := env_var_or_default("RUST_BACKTRACE", "0")
sbf-tools-version := env_var_or_default("SBF_TOOLS_VERSION", "v1.54")
surfpool-release-tag := env_var_or_default("SURFPOOL_RELEASE_TAG", "v1.1.1-light")
surfpool-version := env_var_or_default("SURFPOOL_VERSION", "1.1.1")

mod prover 'prover/server'
mod forester 'forester'

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

# Check the entire workspace.
check-all:
    cargo check --workspace --all-targets

# Default test target. Tests the shielded-pool implementation, SDKs, and Forester.
test: test-shielded-pool test-sdk-libs test-forester

# Program/interface tests for the shielded-pool implementation.
test-shielded-pool:
    cargo test -p zolana-interface --features solana
    cargo test -p shielded-pool-program --lib --tests
    cargo test -p shielded-pool-tests

# Unit, BDD, and property tests for the client-side SDK crates.
test-sdk-libs:
    cargo test -p zolana-keypair
    cargo test -p photon-api
    cargo test -p zolana-transaction

test-forester:
    cargo test -p forester

# End-to-end litesvm tests for shielded-pool.
test-litesvm:
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path programs/shielded-pool/Cargo.toml -- --features bpf-entrypoint
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path program-tests/zone-test-program/Cargo.toml
    cargo test -p zolana-program-test

# Run one localnet test against a validator loaded with the real SBF programs.
test-localnet test="localnet_proofless_shield":
    SBF_TOOLS_VERSION={{sbf-tools-version}} ./tools/localnet-test.sh run {{test}}

test-localnet-proofless:
    @just test-localnet localnet_proofless_shield

start-localnet:
    SBF_TOOLS_VERSION={{sbf-tools-version}} ./tools/localnet-test.sh start

stop-localnet:
    ./tools/localnet-test.sh stop

stop-localnet-proofless:
    @just stop-localnet

# Aggregate of all CI-runnable Rust tests.
test-all: test test-litesvm

# Rust-only verification for machines without Go installed.
verify-rust: check test

# Full verification for the reduced workspace.
verify: verify-rust prover-server-test

# === CLI and Fixtures ===

build-zolana-cli:
    cargo build -p zolana-cli

# Fetch pinned third-party SBF program artifacts.
fetch-vendor-programs:
    ./tools/fetch-vendor-programs.sh

# Verify pinned third-party SBF program artifacts.
verify-vendor-programs:
    ./tools/verify-vendor-programs.sh

# Build test-validator fixtures from an explicit source tree.
build-fixtures: fetch-vendor-programs
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

# Build local SBF programs and copy fixture programs into `target/deploy`.
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

# Build the Photon indexer binary from the pinned `external/photon` submodule.
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

[private]
render-diagrams:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v dot >/dev/null 2>&1; then
        echo "graphviz 'dot' not found; install with 'brew install graphviz'" >&2
        exit 1
    fi
    for src in docs/diagrams/*.dot; do
        base="${src%.dot}"
        dot -Tpng -Gdpi=144 "$src" -o "${base}.png"
        dot -Tsvg "$src" -o "${base}.svg"
        echo "rendered ${base}.png and ${base}.svg"
    done
