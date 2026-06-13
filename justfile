# Zolana workspace
set dotenv-load

export RUST_BACKTRACE := env_var_or_default("RUST_BACKTRACE", "0")
sbf-tools-version := env_var_or_default("SBF_TOOLS_VERSION", "v1.54")
surfpool-release-tag := env_var_or_default("SURFPOOL_RELEASE_TAG", "v1.1.1-light")
surfpool-version := env_var_or_default("SURFPOOL_VERSION", "1.1.1")

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

# Check the entire workspace.
check-all:
    cargo check --workspace --all-targets

# Default test target. Tests the interface, shielded-pool program, SDKs, and Forester.
test: test-scaffold test-sdk-libs test-forester

# Cheap tests for the program/interface slice.
test-scaffold:
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

# Aggregate of all CI-runnable Rust tests.
test-all: test test-litesvm

# Rust-only verification for machines without Go installed.
verify-rust: check test

# Full verification for the reduced workspace.
verify: verify-rust prover-server-test

# === Local validator helpers ===

check-zolana-cli:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -n "${ZOLANA_CLI_CMD:-}" ]]; then
        echo "Using ZOLANA_CLI_CMD=$ZOLANA_CLI_CMD"
    elif [[ -n "${ZOLANA_CLI_BIN:-}" ]]; then
        test -x "$ZOLANA_CLI_BIN"
        echo "Using ZOLANA_CLI_BIN=$ZOLANA_CLI_BIN"
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

# Download and verify the pinned test-validator fixtures.
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
    archive="zolana-fixtures.tar.gz"
    url="https://github.com/helius-labs/zolana/releases/download/${tag}/${archive}"
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    echo "fetching ${url}"
    curl -sSfL "$url" -o "$tmp/${archive}"
    tar -xzf "$tmp/${archive}" -C "$dest"
    cd "$dest" && shasum -a 256 -c SHA256SUMS
    echo "fixtures ${tag} ready at ${dest}"

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

# Build local SBF programs and copy fixture programs into `target/deploy`.
build-programs: fetch-fixtures
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path programs/shielded-pool/Cargo.toml -- --features bpf-entrypoint
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path program-tests/zone-test-program/Cargo.toml
    mkdir -p target/deploy
    tag=$(tr -d '[:space:]' < .fixtures-version)
    fixtures="${ZOLANA_CACHE_DIR:-$HOME/.cache/zolana}/fixtures/${tag}"
    cp "${fixtures}/bin/spl_noop.so" target/deploy/spl_noop.so

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

# === Docs ===

# Regenerate docs/api/README.md from docs/api/openapi.yaml. Requires python3 + PyYAML.
gen-api-readme:
    ./docs/api/generate-readme.sh

# Build and open the OpenAPI HTML reference (Redoc). Requires npx.
api-docs:
    npx @redocly/cli build-docs docs/api/openapi.yaml -o /tmp/zolana-api-docs.html
    open /tmp/zolana-api-docs.html

# Re-render docs/diagrams/*.dot to PNG + SVG. Requires graphviz (`brew install graphviz`).
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

# === Maintenance ===

metadata:
    cargo metadata --format-version 1 --no-deps

clean:
    cargo clean
