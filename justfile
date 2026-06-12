# Zolana workspace
set dotenv-load

export RUST_BACKTRACE := env_var_or_default("RUST_BACKTRACE", "0")
sbf-tools-version := env_var_or_default("SBF_TOOLS_VERSION", "v1.54")
surfpool-release-tag := env_var_or_default("SURFPOOL_RELEASE_TAG", "v1.1.1-light")
surfpool-version := env_var_or_default("SURFPOOL_VERSION", "1.1.1")

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
test-shielded-pool:
    cargo test -p zolana-interface --features solana
    cargo test -p shielded-pool-program --lib --tests
    cargo test -p shielded-pool-tests
    cargo test -p zolana-user-registry --lib

# User-registry litesvm tests only (no Light fixture bundle required).
test-user-registry-litesvm: build-programs
    cargo test -p light-program-test --test user_registry_bdd

# Unit, BDD, and property tests for the client-side SDK crates.
test-sdk-libs:
    cargo test -p zolana-keypair
    cargo test -p zolana-transaction

# End-to-end litesvm tests for shielded-pool.
test-litesvm: build-programs
    cargo test -p shielded-pool-tests

# Aggregate of all CI-runnable Rust tests.
test-all: test test-litesvm

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
    url="https://github.com/helius-labs/zolana/releases/download/${tag}/light-fixtures.tar.gz"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    echo "fetching ${url}"
    if curl -sSfL "$url" -o "$tmp/light-fixtures.tar.gz"; then
        rm -rf "$dest"
        mkdir -p "$dest"
        tar -xzf "$tmp/light-fixtures.tar.gz" -C "$dest"
        cd "$dest" && shasum -a 256 -c SHA256SUMS
        echo "fixtures ${tag} ready at ${dest}"
    else
        echo "GitHub release ${tag} missing; build the bundle manually." >&2
        echo "See README.md > 'Light fixtures (manual build)'." >&2
        exit 1
    fi

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
    # Scoped to ./prover/... (skips the redis-dependent `server` package tests)
    # and uses the upstream 60m timeout; TestCombined alone compiles ~672
    # groth16 circuits and exceeds Go's default 10m.
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

# === Maintenance ===

metadata:
    cargo metadata --format-version 1 --no-deps

clean:
    cargo clean
