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

# Check the entire workspace.
check-all:
    cargo check --workspace --all-targets

# Default test target. Tests for the surviving slice (interface, registry,
# shielded-pool program). Forester e2e tests will be reintroduced when the
# foresting logic is rebuilt against the new combined tree type.
test: test-scaffold

# Cheap tests for the initial shielded-pool/interface/registry scaffold.
test-scaffold:
    cargo test -p zolana-interface --features solana
    cargo test -p shielded-pool-program --lib --tests
    cargo test -p shielded-pool-tests

# End-to-end litesvm tests for shielded-pool + registry. Requires the SBF
# `.so`s under `target/deploy/`; run `just build-programs` first.
test-litesvm:
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path programs/shielded-pool/Cargo.toml -- --features bpf-entrypoint
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path programs/registry/Cargo.toml
    cargo test -p light-program-test

# Aggregate of all CI-runnable rust tests.
test-all: test-scaffold test-litesvm

# Rust-only verification for machines without Go installed.
verify-rust: check test

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
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path programs/shielded-pool/Cargo.toml
    cargo build-sbf --tools-version {{sbf-tools-version}} --manifest-path programs/registry/Cargo.toml
    mkdir -p target/deploy
    tag=$(tr -d '[:space:]' < .fixtures-version)
    fixtures="${ZOLANA_CACHE_DIR:-$HOME/.cache/zolana}/fixtures/${tag}"
    cp "${fixtures}/bin/spl_noop.so" target/deploy/spl_noop.so
    cp "${fixtures}/bin/light_system_program_pinocchio.so" target/deploy/light_system_program_pinocchio.so

build-prover-server:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target
    go_bin="${GO_BIN:-}"
    if [[ -z "$go_bin" ]] && command -v go >/dev/null 2>&1; then
        go_bin=go
    fi
    if [[ -z "$go_bin" ]]; then
        if [[ -x target/prover-server ]]; then
            echo "go not found; reusing existing target/prover-server"
            exit 0
        fi
        echo "go not found; install Go or set GO_BIN" >&2
        exit 127
    fi
    cd prover/server && "$go_bin" build -o ../../target/prover-server .

build-spp-keys: build-prover-server
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/spp
    if [[ ! -f target/spp/spp_1_2.key ]]; then
        target/prover-server spp setup --inputs 1 --outputs 2 --output target/spp/spp_1_2.key --output-vkey target/spp/spp_1_2.vkey
    fi

build-spp-spec-keys: build-prover-server
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/spp
    for shape in 2:2 1:2 3:3 5:3 1:8; do
        inputs="${shape%%:*}"
        outputs="${shape##*:}"
        stem="target/spp/spp_${inputs}_${outputs}"
        if [[ ! -f "${stem}.key" ]]; then
            target/prover-server spp setup --inputs "$inputs" --outputs "$outputs" --output "${stem}.key" --output-vkey "${stem}.vkey"
        fi
    done

# Regenerate transact vkeys + e2e fixtures after a transaction-circuit change
# (run from the tip branch). See the script header for what each arg means.
regen-spp-transact-fixtures:
    scripts/regen-spp-transact-fixtures.sh

# Regenerate the forester batch-update (address-append) e2e fixture.
regen-spp-batch-update-fixture:
    scripts/regen-spp-batch-update-fixture.sh

# === Demo ===

# Run the local pocket SOL demo: builds the CLI/prover/keys/SBF, boots a
# solana-test-validator, and runs shield -> private transfer -> unshield
# (Solana + P256 shielded wallets). Requires solana, solana-test-validator,
# lsof, go, and cargo-build-sbf on PATH.
demo:
    scripts/pocket-sol-demo.sh

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

# === Maintenance ===

metadata:
    cargo metadata --format-version 1 --no-deps

clean:
    cargo clean
