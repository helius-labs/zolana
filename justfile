# Zolana workspace
set dotenv-load

export RUST_BACKTRACE := env_var_or_default("RUST_BACKTRACE", "0")
sbf-tools-version := env_var_or_default("SBF_TOOLS_VERSION", "v1.54")
surfpool-release-tag := env_var_or_default("SURFPOOL_RELEASE_TAG", "v1.1.1-light")
surfpool-version := env_var_or_default("SURFPOOL_VERSION", "1.1.1")
# Per-clone port isolation: set ZOLANA_PORT_OFFSET in a local (gitignored) .env
# (auto-loaded above) to shift every service port by a fixed amount so concurrent
# checkouts never contend. Each individual port/URL var can still be overridden
# explicitly. See .env.example.
port-offset := env_var_or_default("ZOLANA_PORT_OFFSET", "0")
localnet-rpc-port := env_var_or_default("ZOLANA_LOCALNET_RPC_PORT", shell('echo $((8899 + ${1:-0}))', port-offset))
localnet-photon-port := env_var_or_default("ZOLANA_LOCALNET_PHOTON_PORT", shell('echo $((8784 + ${1:-0}))', port-offset))
localnet-prover-port := env_var_or_default("ZOLANA_LOCALNET_PROVER_PORT", shell('echo $((3001 + ${1:-0}))', port-offset))
localnet-rpc-url := env_var_or_default("ZOLANA_LOCALNET_URL", "http://127.0.0.1:" + localnet-rpc-port)
localnet-photon-url := env_var_or_default("ZOLANA_LOCALNET_PHOTON_URL", "http://127.0.0.1:" + localnet-photon-port)
localnet-prover-url := env_var_or_default("ZOLANA_PROVER_URL", "http://127.0.0.1:" + localnet-prover-port)
photon-bin := env_var_or_default("ZOLANA_PHOTON_BIN", "target/debug/photon")
spp-keys-dir := env_var_or_default("ZOLANA_SPP_KEYS_DIR", "prover/server/proving-keys")

# Exported so every `cargo test` recipe (and the prover the tests spawn) picks up
# the per-clone prover address without each recipe wiring it explicitly. The
# client both connects here and starts the spawned server on this URL's port, so
# this single var is the source of truth for the prover.
export ZOLANA_PROVER_URL := localnet-prover-url

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
test: test-shielded-pool test-sdk-libs test-photon

# Program/interface tests for the shielded-pool implementation.
# Depends on build-programs so the litesvm tests load a fresh .so and actually
# run (without it `program_test()` finds no .so and the suite skips). Builds
# the prover server and zolana CLI because transact tests spawn a local prover.
test-shielded-pool: build-programs build-prover-server build-cli
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
    cargo test -p zolana-client --lib --features indexer-api
    cargo test -p zolana-client --test transaction --features indexer-api
    cargo test -p zolana-client --test solana_rpc --features solana-rpc

# Photon unit and SQLite-backed integration tests. The Postgres migration smoke
# test runs in CI where a database service is available.
test-photon:
    cargo test -p photon-indexer

# All zolana-client tests (lib unit tests, the `transaction` integration test,
# and the `transfer_2_3` BDD suite). The BDD scenario spawns the prover server
# (via the zolana CLI), which lazily downloads proving keys from the
# transfer-keys-v12 GitHub release via the GitHub REST API using GH_TOKEN or
# GITHUB_TOKEN, or uses local keys verified by CHECKSUM. Builds the go prover
# binary and the zolana CLI the spawned server/test rely on.
test-client-integration: build-prover-server build-cli
    cargo test -p zolana-client --all-features

# One real transfer proof through Redis, TransferQueueWorker, and the Rust
# client's async /prove status polling. Requires a reachable Redis URL.
test-client-async-transfer-queue: build-prover-server build-cli
    #!/usr/bin/env bash
    set -euo pipefail
    : "${ZOLANA_PROVER_REDIS_URL:?set ZOLANA_PROVER_REDIS_URL to a reachable Redis instance}"
    ZOLANA_EXPECT_ASYNC_PROVER=true \
        cargo test -p zolana-client --test transfer_dummy dummy_transfer_2_3_proof_verifies -- --exact

# Program integration tests backed by LiteSVM. Transact tests spawn the prover
# through the zolana CLI.
test-programs: build-programs build-prover-server build-cli
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
    cargo build -p zolana-cli --target-dir target

test-cli:
    cargo test -p zolana-cli

# === Bench ===

# Regenerate bench/bloom-filter/CU_BENCHMARK.md. Builds the bench program with
# the profiling syscalls enabled, then runs the mollusk harness that profiles
# light-bloom-filter insert/contains.
bench-bloom-filter:
    cargo build-sbf --manifest-path bench/bloom-filter/Cargo.toml --features bench
    cargo test -p bloom-filter-bench --test bench_cu -- --ignored --nocapture

# Build the tree bench program with profiling enabled, then run the mollusk
# harness that profiles zolana-tree init/deserialize/append/nullifier-insert.
bench-tree:
    cargo build-sbf --manifest-path bench/tree/Cargo.toml --features bench
    cargo test -p tree-bench --test bench_cu -- --ignored --nocapture

# Profile the shielded-pool deposit instructions (SOL + SPL). litesvm builds the
# account state with the plain .so; mollusk replays one instruction against the
# profiling .so. Build the plain programs, stash the plain shielded-pool .so,
# then overwrite target/deploy with the profiling build before running. Clone the
# SPL Token program from mainnet so mollusk can run the SPL deposit's CPI.
bench-shielded-pool: build-programs
    cp target/deploy/shielded_pool_program.so target/deploy/shielded_pool_program_plain.so
    cargo build-sbf --tools-version {{sbf-tools-version}} \
        --sbf-out-dir target/deploy \
        --manifest-path programs/shielded-pool/Cargo.toml \
        -- --features bpf-entrypoint,profile-program
    test -f target/deploy/spl_token.so || \
        solana program dump TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA target/deploy/spl_token.so --url mainnet-beta
    cargo test -p shielded-pool-tests --test bench_cu -- --ignored --nocapture

# Profile the confidential swap create/fill/cancel instructions and record proving
# times. The bench builds the shielded-pool tree account directly and replays one
# swap instruction under mollusk. Only the swap program is built with profiling; the
# shielded-pool program is built plain so its `transact` CPI runs as an
# uninstrumented black box and its functions do not pollute the swap CU table.
# SOL-only, so no SPL Token clone is needed. Regenerates
# sdk-tests/zk-program-swap/BENCHMARK.md.
# Fetch the pinned swap proving keys from the swap-keys release and verify them
# against the committed manifest. groth16.Setup is non-deterministic, so the
# published keys are the only set matching the committed Rust verifying keys;
# regenerating locally (regen-swap-keys) requires publishing a new release and
# updating swap-keys.CHECKSUM plus the committed verifying keys together.
swap-keys-tag := "swap-keys-v3"

ensure-swap-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    base="sdk-tests/zk-program-swap"
    for c in make take cancel take_verifiable_encryption; do
        dir="$base/build/gnark/$c"
        for kind in pk vk; do
            if [ ! -f "$dir/$kind.bin" ]; then
                mkdir -p "$dir"
                gh release download "{{swap-keys-tag}}" --repo helius-labs/zolana \
                    --pattern "${c}_${kind}.bin" --output "$dir/$kind.bin" --clobber
            fi
            want=$(awk -v n="${c}_${kind}.bin" '$2==n {print $1}' "$base/swap-keys.CHECKSUM")
            got=$(shasum -a 256 "$dir/$kind.bin" | awk '{print $1}')
            if [ "$want" != "$got" ]; then
                echo "checksum mismatch for $dir/$kind.bin (want $want, got $got)" >&2
                echo "refresh from the {{swap-keys-tag}} release (delete the file and rerun)," >&2
                echo "or rotate keys with 'just regen-swap-keys' and publish a new release" >&2
                exit 1
            fi
        done
    done

# Rotate the swap proving keys: regenerate every circuit, rewriting the committed
# Rust verifying keys and the checksum manifest. Publish the new build/gnark
# key files to a fresh swap-keys release and bump swap-keys-tag afterwards.
regen-swap-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    base="sdk-tests/zk-program-swap"
    for c in make take cancel take_verifiable_encryption; do
        cargo run --release -p swap-prover --bin swap-prover-setup -- \
            "$c" "$base/build/gnark/$c" \
            --rust-vk "$base/program/src/verifying_keys/$c.rs"
    done
    : > "$base/swap-keys.CHECKSUM"
    for c in make take cancel take_verifiable_encryption; do
        for kind in pk vk; do
            shasum -a 256 "$base/build/gnark/$c/$kind.bin" \
                | awk -v n="${c}_${kind}.bin" '{print $1 "  " n}' >> "$base/swap-keys.CHECKSUM"
        done
    done

# The profiling swap build calls a profiler syscall that solana-test-validator
# does not register, so it must never land in target/deploy (validator/CI load
# the plain program from there). Build the bench programs into a dedicated dir,
# matching PROFILING_SBF_DIR in bench_cu.rs.
bench-swap: ensure-swap-keys
    cargo build-sbf --tools-version {{sbf-tools-version}} \
        --sbf-out-dir target/swap-bench \
        --manifest-path programs/shielded-pool/Cargo.toml \
        -- --features bpf-entrypoint
    cargo build-sbf --tools-version {{sbf-tools-version}} \
        --sbf-out-dir target/swap-bench \
        --manifest-path sdk-tests/zk-program-swap/program/Cargo.toml \
        -- --features bpf-entrypoint,profile-program
    cargo test -p swap-test-validator --test bench_cu -- --ignored --nocapture

# Verifies the committed escrow/withdraw proving and verifying keys against
# timelock-escrow-keys.CHECKSUM. Unlike the swap keys, these are not yet
# published to a GitHub release, so a missing or mismatched key must be
# regenerated locally with 'just regen-escrow-keys'.
ensure-escrow-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    base="sdk-tests/timelock-escrow"
    for c in escrow withdraw; do
        dir="$base/build/gnark/$c"
        for kind in pk vk; do
            if [ ! -f "$dir/$kind.bin" ]; then
                echo "$dir/$kind.bin missing -- run 'just regen-escrow-keys'" >&2
                exit 1
            fi
            want=$(awk -v n="${c}_${kind}.bin" '$2==n {print $1}' "$base/timelock-escrow-keys.CHECKSUM")
            got=$(shasum -a 256 "$dir/$kind.bin" | awk '{print $1}')
            if [ "$want" != "$got" ]; then
                echo "checksum mismatch for $dir/$kind.bin (want $want, got $got)" >&2
                echo "regenerate with 'just regen-escrow-keys', which also rewrites the checksum manifest" >&2
                exit 1
            fi
        done
    done

# Rotate the escrow/withdraw proving keys: regenerate both circuits, rewriting
# the committed Rust verifying keys and the checksum manifest.
regen-escrow-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    base="sdk-tests/timelock-escrow"
    for c in escrow withdraw; do
        cargo run --release -p timelock-escrow-prover --bin timelock-escrow-prover-setup -- \
            "$c" "$base/build/gnark/$c" \
            --rust-vk "$base/program/src/verifying_keys/$c.rs"
    done
    : > "$base/timelock-escrow-keys.CHECKSUM"
    for c in escrow withdraw; do
        for kind in pk vk; do
            shasum -a 256 "$base/build/gnark/$c/$kind.bin" \
                | awk -v n="${c}_${kind}.bin" '{print $1 "  " n}' >> "$base/timelock-escrow-keys.CHECKSUM"
        done
    done

# The profiling escrow build calls a profiler syscall that solana-test-validator
# does not register, so it must never land in target/deploy (validator/CI load
# the plain program from there). Build the bench programs into a dedicated dir,
# matching PROFILING_SBF_DIR in bench_cu.rs. Regenerates
# sdk-tests/timelock-escrow/BENCHMARK.md.
bench-escrow: ensure-escrow-keys
    cargo build-sbf --tools-version {{sbf-tools-version}} \
        --sbf-out-dir target/escrow-bench \
        --manifest-path programs/shielded-pool/Cargo.toml \
        -- --features bpf-entrypoint
    cargo build-sbf --tools-version {{sbf-tools-version}} \
        --sbf-out-dir target/escrow-bench \
        --manifest-path sdk-tests/timelock-escrow/program/Cargo.toml \
        -- --features bpf-entrypoint,profile-program
    cargo test -p timelock-escrow-test --test bench_cu -- --ignored --nocapture

# === Local validator helpers ===

# Local-validator end-to-end SOL cycle.
test-localnet-e2e: build-programs build-prover-server build-cli
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cargo run -p zolana-cli -- dev start --skip-prover --no-use-surfpool --rpc-port {{localnet-rpc-port}} --sbf-program "$SHIELDED_POOL_PROGRAM_ID" target/deploy/shielded_pool_program.so --sbf-program "$USER_REGISTRY_PROGRAM_ID" target/deploy/zolana_user_registry.so --sbf-program "$ZONE_TEST_PROGRAM_ID" target/deploy/zone_test_program.so
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" cargo test -p shielded-pool-tests --features localnet --test localnet_e2e -- --nocapture
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" cargo test -p shielded-pool-tests --features localnet --test localnet_deposit -- --nocapture

# Local-validator SOL cycle backed by a real Photon Zolana indexer. Each
# `#[serial]` test restarts a fresh validator + Photon via the `zolana` CLI,
# so the protocol-config singleton never collides across tests.
test-localnet-e2e-photon: build-programs build-prover-server build-cli ensure-photon ensure-smart-account
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    export SHIELDED_POOL_PROGRAM_ID
    export USER_REGISTRY_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo test -p shielded-pool-tests --features localnet --test localnet_photon_e2e -- --nocapture
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo test -p shielded-pool-tests --features localnet --test localnet_wallet_cli_e2e -- --nocapture

# BDD decrypt-and-spend lifecycle scenarios over a fresh validator + Photon per
# scenario (program-tests/spp-test-validator). The prover server persists; each
# cucumber scenario restarts the validator + Photon via the `zolana` CLI.
test-spp-validator: build-programs build-prover-server build-cli ensure-photon
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    export SHIELDED_POOL_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo test -p spp-test-validator --test lifecycle

# Run only the decode scenario from test-spp-validator, which prints the parsed
# `transact` instruction data, its named accounts, and the emitted event. The test
# binary has `harness = false`, so the prints reach the terminal directly.
test-spp-validator-decode: build-programs build-prover-server build-cli ensure-photon
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    export SHIELDED_POOL_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo test -p spp-test-validator --test lifecycle -- --name "instruction data and accounts decode"

# Run only the merge scenarios from test-spp-validator (the 1-8 consolidation
# outline plus the disabled-service negative). For debugging the merge flow without
# running the full lifecycle suite.
test-spp-validator-merge: build-programs build-prover-server build-cli ensure-photon
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    export SHIELDED_POOL_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo test -p spp-test-validator --test lifecycle -- --name "Merge service"

# Run only the randomized 500-transaction workload from test-spp-validator. This is
# intentionally isolated in CI because it is the longest and quietest scenario.
test-spp-validator-randomized: build-programs build-prover-server build-cli ensure-photon
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    export SHIELDED_POOL_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo test -p spp-test-validator --test lifecycle -- --name "Fifty randomized eddsa transactions"

# Run the non-merge, non-randomized spp-validator scenarios: eddsa signer, P256
# signer, mixed lifecycle, SOL lifecycle, and instruction/event decode.
test-spp-validator-lifecycle-decode: build-programs build-prover-server build-cli ensure-photon
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    export SHIELDED_POOL_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo test -p spp-test-validator --test lifecycle -- --name "authorizes SOL, SPL, and mixed transfers|Fifty mixed transactions|Transfer recipient and sender change|instruction data and accounts decode"

# Run only the mixed-lifecycle scenario from test-spp-validator (deposits,
# transfers, SOL withdrawals, and merges across three owners). For exercising the
# full instruction mix without running the rest of the lifecycle suite.
test-spp-validator-lifecycle: build-programs build-prover-server build-cli ensure-photon
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    export SHIELDED_POOL_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo test -p spp-test-validator --test lifecycle -- --name "Fifty mixed transactions"

# BDD zone lifecycle scenarios over a fresh validator + Photon per scenario
# (program-tests/zone-test-program). Mirrors test-spp-validator but loads the
# policy-zone fixture program (zone_test_program.so) and CPIs into SPP via its
# `zone_auth` PDA, so the recipe also exports ZONE_TEST_PROGRAM_ID and
# USER_REGISTRY_PROGRAM_ID. build-programs builds zone_test_program.so; the merge
# flow reads the user-registry record so that program must be co-loaded, and the
# zone deposits use the Squads smart account binary (ensure-smart-account). The
# prover server persists; each cucumber scenario restarts the validator + Photon
# via the `zolana` CLI.
test-zone-validator: build-programs build-prover-server build-cli ensure-photon ensure-smart-account
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    export SHIELDED_POOL_PROGRAM_ID
    export USER_REGISTRY_PROGRAM_ID
    export ZONE_TEST_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo test -p zone-test-program --test zone_lifecycle --release

# Fully-inlined create+fill and create+cancel swap flows over a fresh validator
# (sdk-tests/zk-program-swap/test/tests/{swap,cancel}.rs). Each test binary boots
# solana-test-validator via the `zolana` CLI with the swap program, the shielded
# pool, the user registry, and the Squads smart account loaded together, plus
# Photon and the persistent SPP prover -- mirroring test-spp-validator. Cargo
# runs the test binaries serially, so the second boots a fresh validator.
test-swap-validator: ensure-swap-keys build-programs build-prover-server build-cli ensure-photon ensure-smart-account
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    export SWAP_PROGRAM_ID
    export SHIELDED_POOL_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo test -p swap-test-validator --test swap --test cancel -- --nocapture

# Timelock escrow lifecycle on a local validator, driven against a real
# localnet (sdk-tests/timelock-escrow/test/tests/escrow.rs). Boots
# solana-test-validator via the `zolana` CLI with the timelock escrow program,
# the shielded pool, and the Squads smart account loaded together, plus Photon
# and the persistent SPP prover -- mirroring test-swap-validator.
test-escrow-validator: ensure-escrow-keys build-programs build-prover-server build-cli ensure-photon ensure-smart-account
    #!/usr/bin/env bash
    set -euo pipefail
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo test -p timelock-escrow-test --test escrow -- --nocapture

# Runs the swap and escrow lifecycle suites back to back in one CI job.
test-swap-and-escrow-validator: test-swap-validator test-escrow-validator

# Minimal zolana-client SDK example: deposit, shielded transfer, and withdrawal
# building the SPP instructions by hand and submitting them
# (sdk-tests/client/examples/deposit_transfer_withdraw.rs). Boots
# solana-test-validator via the `zolana` CLI with the shielded pool, the user
# registry, and the Squads smart account, plus Photon and the SPP prover --
# mirroring test-spp-validator.
test-client-example: build-programs build-prover-server build-cli ensure-photon ensure-smart-account
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    export SHIELDED_POOL_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo run -p client-example --example deposit_transfer_withdraw

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

# Deploy/upgrade programs to devnet using the local `solana` CLI config.
# Pass program names to deploy a subset, e.g. `just deploy-devnet shielded-pool`.
# Requires `just build-programs` first and that the local config keypair is
# the current upgrade authority. Set ZOLANA_DEVNET_KEYS_DIR to a
# `<dir>/program-id/<pubkey>.json` keys checkout for a program's first-ever
# deploy (only needed once per program's fixed address; upgrades work without
# it since only the pubkey is required after the account exists on-chain).
deploy-devnet *programs:
    ./tools/deploy-devnet.sh {{programs}}

# Download the Squads smart account program binary from mainnet into `target/deploy`.
# Run once before `test-spp-validator*` recipes; requires `solana` CLI and network access.
fetch-smart-account:
    mkdir -p target/deploy
    solana program dump SMRTzfY6DfH5ik3TKiyLFfXexV8uSG3d2UksSCYdunG \
        target/deploy/squads_smart_account_program.so \
        --url https://api.mainnet-beta.solana.com

ensure-smart-account:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ! -f target/deploy/squads_smart_account_program.so ]]; then
        just fetch-smart-account
    fi

build-prover-server:
    mkdir -p target
    cd prover/server && go build -o ../../target/prover-server .

build-spp-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    prover/server/scripts/generate_keys_transfer.sh "{{spp-keys-dir}}"
    prover/server/scripts/generate_keys_merge.sh "{{spp-keys-dir}}"
    prover/server/scripts/regenerate_all_vkeys.sh "$(pwd)/{{spp-keys-dir}}"

publish-spp-keys-release:
    prover/server/scripts/publish_keys_release.sh transfer-keys-v12 "$(pwd)/{{spp-keys-dir}}"

build-photon:
    cargo build --locked -p photon-indexer --bin photon

ensure-photon:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -n "${ZOLANA_PHOTON_BIN:-}" ]]; then
      if [[ ! -x "$ZOLANA_PHOTON_BIN" ]]; then
        echo "ZOLANA_PHOTON_BIN is not executable: $ZOLANA_PHOTON_BIN" >&2
        exit 1
      fi
      echo "Using Photon binary at $ZOLANA_PHOTON_BIN"
      exit 0
    fi
    just build-photon

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
    # The `server` package's handler tests need redis, but the queue-routing
    # unit test does not -- run it explicitly so routing stays covered in CI.
    go test ./server/ -run '^TestGetQueueNameForCircuit$'

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
