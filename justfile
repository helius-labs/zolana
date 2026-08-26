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
export ZOLANA_PORT_OFFSET := env_var_or_default("ZOLANA_PORT_OFFSET", "0")
localnet-rpc-port := env_var_or_default("ZOLANA_LOCALNET_RPC_PORT", `echo $((8899 + ${ZOLANA_PORT_OFFSET:-0}))`)
localnet-photon-port := env_var_or_default("ZOLANA_LOCALNET_PHOTON_PORT", `echo $((8784 + ${ZOLANA_PORT_OFFSET:-0}))`)
localnet-prover-port := env_var_or_default("ZOLANA_LOCALNET_PROVER_PORT", `echo $((3001 + ${ZOLANA_PORT_OFFSET:-0}))`)
localnet-ring-rpc-port := env_var_or_default("ZOLANA_LOCALNET_RING_RPC_PORT", `echo $((8785 + ${ZOLANA_PORT_OFFSET:-0}))`)
localnet-rpc-url := env_var_or_default("ZOLANA_LOCALNET_URL", "http://127.0.0.1:" + localnet-rpc-port)
localnet-photon-url := env_var_or_default("ZOLANA_LOCALNET_PHOTON_URL", "http://127.0.0.1:" + localnet-photon-port)
localnet-prover-url := env_var_or_default("ZOLANA_PROVER_URL", "http://127.0.0.1:" + localnet-prover-port)
photon-bin := env_var_or_default("ZOLANA_PHOTON_BIN", "target/debug/photon")
spp-keys-dir := env_var_or_default("ZOLANA_SPP_KEYS_DIR", "prover/server/proving-keys")
# Published proving keys, prefixed by the lockfile the prover embeds so the two
# cannot drift.
proving-keys-base := env_var_or_default("ZOLANA_PROVING_KEYS_URL", "https://d3gbdb0egjwcw9.cloudfront.net")
proving-keys-url := proving-keys-base + "/" + `python3 -c "import json;print(json.load(open('prover/server/prover/provingkeys/proving-keys.lock'))['prefix'])"`

# Exported so every `cargo test` recipe (and the prover the tests spawn) picks up
# the per-clone prover address without each recipe wiring it explicitly. The
# client both connects here and starts the spawned server on this URL's port, so
# this single var is the source of truth for the prover.
export ZOLANA_PROVER_URL := localnet-prover-url

default:
    @just --list

# Preserve module-like subcommands without requiring unstable module support in
# older `just` versions.
forester *args:
    just --justfile forester/justfile {{args}}

prover *args:
    just --justfile prover/server/justfile {{args}}

# === Rust workspace ===

# Build default workspace members.
build:
    cargo build

build-release:
    cargo build --release

# Check default workspace members.
check:
    cargo check

# Check the entire workspace. `zolana-client/proofs` keeps its prover-backed
# test binaries in the type check without letting `cargo test` run them.
check-all:
    cargo check --workspace --all-targets --features zolana-client/proofs

# Default test target.
test: test-shielded-pool test-sdk-libs test-photon

# Everything that needs nothing running. No prover, no validator, no network,
# and no proving keys. CI runs these same suites on every push, one job each.
test-hermetic: test-cli test-program-fast test-user-registry-litesvm test-sdk-libs test-photon

# Program/interface tests for the shielded-pool implementation.
# Depends on build-programs so the litesvm tests load a fresh .so and actually
# run (without it `program_test()` finds no .so and the suite skips). Builds
# the prover server and zolana CLI because transact tests spawn a local prover.
test-shielded-pool: build-programs build-prover-server build-cli
    cargo nextest run -p zolana-interface --features solana
    cargo nextest run -p shielded-pool-program --lib --tests
    # Proof-backed binaries spawn a shared prover server on a fixed port; run
    # them serially because nextest isolates tests in separate processes, so a
    # process-local OnceLock does not prevent concurrent port grabs.
    cargo nextest run -p shielded-pool-tests --features proofs --test-threads 1
    cargo nextest run -p zolana-user-registry --tests
    cargo nextest run -p user-registry-tests --test wire_layout

# Fast SBF-backed state and failure tests. No proof server or local validator.
# The proof-backed binaries are gated behind the `proofs` feature, so the plain
# package run is hermetic by construction.
test-program-fast: build-programs
    cargo nextest run -p zolana-interface --features solana
    cargo nextest run -p shielded-pool-program --lib --tests
    cargo nextest run -p zolana-user-registry --tests
    cargo nextest run -p shielded-pool-tests
    cargo nextest run -p swap-program --tests
    cargo nextest run -p custom-ring-program --tests
    # The featured suite compiles with the rule features the deploy-ring-rules image carries.
    cargo nextest run -p custom-ring-program --test policy_sources --features allowlist,blocklist,freeze

# Run one shielded-pool intent-level binary, for example:
# `just test-shielded-pool-case deposit_model`.
test-shielded-pool-case case: build-programs
    cargo nextest run -p shielded-pool-tests --test {{case}}

# Account-aware Mollusk failures and property mutations for SPP and swap.
test-program-mollusk: build-programs
    cargo nextest run -p shielded-pool-tests --test admin_functional --test admin_rejection --test admin_edge_cases
    cargo nextest run -p shielded-pool-tests --test deposit_functional --test deposit_rejection --test deposit_edge_cases --test deposit_mutation
    cargo nextest run -p swap-program --test failing

# Swap wrapper unit, wire-contract, and SBF-backed negative tests.
test-swap-program: build-programs
    cargo nextest run -p swap-program --tests

# The Go circuit proof check. Needs the canonical keys, because the proof must
# verify under the committed VERIFYINGKEY and gnark setup is non-deterministic,
# so locally generated keys cannot pass.
test-custom-ring: ensure-custom-ring-prover-key
    cd prover/server && go test ./prover/custom_ring -run TestCustomRingProofVerifies -count=1

# === Custom rings ===

# Create a ring directory, ring.toml and the program keypair.
ring-new *args:
    cargo run -q -p custom-ring-cli -- new {{args}}

# Local validator and services for a ring, ring creation is permissionless.
ring-localnet: ensure-custom-ring-live-keys build-programs build-cli ensure-photon
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    bin="target/debug/zolana"
    workdir="target/ring-localnet"
    rm -rf "$workdir"
    mkdir -p "$workdir"
    photon_bin="{{photon-bin}}"
    [[ "$photon_bin" = /* ]] || photon_bin="$PWD/$photon_bin"
    keys_dir="{{spp-keys-dir}}"
    [[ "$keys_dir" = /* ]] || keys_dir="$PWD/$keys_dir"
    export ZOLANA_PHOTON_BIN="$photon_bin"
    export ZOLANA_PROVER_KEYS_DIR="$keys_dir"
    for port in {{localnet-rpc-port}} {{localnet-photon-port}} {{localnet-prover-port}}; do
      lsof -ti "tcp:$port" 2>/dev/null | xargs kill -9 2>/dev/null || true
    done
    sleep 2
    accounts_dir="$workdir/accounts"
    cargo run -q -p xtask -- generate-account-snapshots \
      --deploy-dir target/deploy --accounts-dir "$accounts_dir"
    # SIMD-0500 is off, the ring deploys as SBPF v0 like on devnet.
    "$bin" dev start --no-use-surfpool \
      --rpc-port {{localnet-rpc-port}} --photon-port {{localnet-photon-port}} \
      --prover-port {{localnet-prover-port}} \
      --account-dir "$accounts_dir" --limit-ledger-size 5000000 \
      --sbf-program "$SHIELDED_POOL_PROGRAM_ID" target/deploy/shielded_pool_program.so \
      --sbf-program "$USER_REGISTRY_PROGRAM_ID" target/deploy/zolana_user_registry.so \
      -- --deactivate-feature B8JJXCy5amZyWG9r7EnUYLwzXSXTxG7GZ1qZ1qggo83g
    echo
    echo "localnet ready"
    echo "  rpc       {{localnet-rpc-url}}"
    echo "  photon    {{localnet-photon-url}}"
    echo "  prover    {{localnet-prover-url}}"
    echo "  ring rpc  http://127.0.0.1:{{localnet-ring-rpc-port}}  (started by 'just ring-rpc-derived')"

# Stops the validator, photon, the prover, and a ring RPC left on the ring RPC
# port by a ring's `just pipeline`.
ring-localnet-stop:
    lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-prover-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-ring-rpc-port}}" 2>/dev/null | xargs kill 2>/dev/null || true
    pkill -f solana-test-validator 2>/dev/null || true

# Photon and the prover against an external cluster, Photon indexes from the current slot.
ring-devnet-services rpc_url: ensure-custom-ring-live-keys build-prover-server ensure-photon
    #!/usr/bin/env bash
    set -euo pipefail
    workdir="target/ring-devnet"
    mkdir -p "$workdir"
    photon_bin="{{photon-bin}}"
    [[ "$photon_bin" = /* ]] || photon_bin="$PWD/$photon_bin"
    keys_dir="{{spp-keys-dir}}"
    [[ "$keys_dir" = /* ]] || keys_dir="$PWD/$keys_dir"
    lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-prover-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    sleep 1
    nohup "$photon_bin" --rpc-url "{{rpc_url}}" --port {{localnet-photon-port}} --start-slot latest \
      > "$workdir/photon.log" 2>&1 &
    nohup target/prover-server start --keys-dir "$keys_dir" \
      --prover-address 0.0.0.0:{{localnet-prover-port}} --auto-download=true \
      ${ZOLANA_PROVER_REDIS_URL:+--redis-url "$ZOLANA_PROVER_REDIS_URL"} \
      > "$workdir/prover.log" 2>&1 &
    # A slow start must look different from a hang.
    wait_for() {
      printf 'waiting for %-7s %s ' "$1" "$2"
      for _ in $(seq 1 120); do
        if curl -sf --max-time 5 "$3" >/dev/null 2>&1; then
          echo " ready"
          return 0
        fi
        printf '.'
        sleep 1
      done
      echo " timed out"
      echo "$1 did not become ready, see $4" >&2
      return 1
    }
    wait_for photon "{{localnet-photon-url}}" "{{localnet-photon-url}}/readiness" "$workdir/photon.log"
    wait_for prover "{{localnet-prover-url}}" "{{localnet-prover-url}}/health" "$workdir/prover.log"
    echo "devnet services ready"
    echo "  photon    {{localnet-photon-url}}  (indexing {{rpc_url}}, log $workdir/photon.log)"
    echo "  prover    {{localnet-prover-url}}  (log $workdir/prover.log)"

# Stops photon, the prover and a ring RPC started for devnet.
ring-devnet-services-stop:
    lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-prover-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
    lsof -ti "tcp:{{localnet-ring-rpc-port}}" 2>/dev/null | xargs kill 2>/dev/null || true

# Foreground ring RPC in derived mode, one key per ring.
ring-rpc-derived:
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p target/ring-localnet
    secret="target/ring-localnet/root.secret"
    if [ ! -f "$secret" ]; then
        cargo run -q -p zolana-ring-rpc -- keygen --out "$secret" --kind root
    fi
    cargo run -q -p zolana-ring-rpc -- serve --port {{localnet-ring-rpc-port}} \
        --indexer-url {{localnet-photon-url}} --rpc-url {{localnet-rpc-url}} \
        --root-secret-file "$secret"

# gnark's Setup is non-deterministic, one run must produce the proving key and
# the committed verifying key together.
ensure-custom-ring-prover-key: build-prover-server
    #!/usr/bin/env bash
    set -euo pipefail
    key="prover/server/proving-keys/custom_ring.key"
    mkdir -p prover/server/proving-keys
    if [[ -f "$key" ]]; then
        echo "custom-ring proving key present"
        exit 0
    fi
    target/prover-server setup-custom-ring --output "$key"
    export_dir="$(mktemp -d)"
    trap 'rm -rf "$export_dir"' EXIT
    target/prover-server export-vk --keys-file "$key" --output "$export_dir/vk.bin"
    cargo run -q -p xtask -- bsb22-vk "$export_dir/vk.bin" custom-rings/interface/src verifying_key.rs
    rustfmt custom-rings/interface/src/verifying_key.rs

ensure-custom-ring-live-keys: ensure-custom-ring-prover-key
    #!/usr/bin/env bash
    set -euo pipefail
    keys_dir="prover/server/proving-keys"
    temp_dir="$(mktemp -d)"
    trap 'rm -rf "$temp_dir"' EXIT
    for name in transfer_ring_1_2.key transfer_ring_2_2.key; do
        want="$(python3 -c 'import json, sys; print(json.load(open("prover/server/prover/provingkeys/proving-keys.lock"))["keys"][sys.argv[1]]["sha256"])' "$name")"
        path="$keys_dir/$name"
        if [[ -f "$path" ]] && [[ "$(shasum -a 256 "$path" | awk '{ print $1 }')" == "$want" ]]; then
            continue
        fi
        curl -fsSL "{{proving-keys-url}}/$name" -o "$temp_dir/$name"
        [[ "$(shasum -a 256 "$temp_dir/$name" | awk '{ print $1 }')" == "$want" ]]
        install -m 0644 "$temp_dir/$name" "$path"
    done

# Program-side Groth16 matrices only. CI runs this variant: the client proving
# matrices' CI home is `test-client-integration` (`--all-features`), so they do
# not run twice per PR.
test-program-proofs-programs-only: build-programs build-prover-server build-cli
    cargo nextest run -p shielded-pool-tests --features proofs --test transact_functional --test transact_withdrawal --test transact_settlement --test mixed_interface_transfers --test merge_functional --test-threads 1

# Groth16-backed program and client matrices, separated from fast state tests.
# The full local gate; CI splits it (see test-program-proofs-programs-only).
test-program-proofs: test-program-proofs-programs-only
    cargo nextest run -p zolana-client --features proofs --test transaction_proving --test merge_proving --test merge_ring_proving --test ring_authority_proving --test ring_transfer_proving --test-threads 1

# Export Mollusk's exact-error cases as replayable fuzz fixtures. Only the
# Mollusk-backed cases in tests/deposit/rejection.rs (the `deposit_rejection`
# binary's `mollusk_deposit_rejects_*` tests) eject fixtures; LiteSVM-backed
# rejection tests do not go through Mollusk and produce none.
eject-mollusk-fixtures output="target/fuzz-fixtures": build-programs
    #!/usr/bin/env bash
    set -euo pipefail
    mkdir -p "{{output}}"
    output_dir="$(cd "{{output}}" && pwd)"
    EJECT_FUZZ_FIXTURES_JSON="$output_dir" \
      cargo test -p shielded-pool-tests --test deposit_rejection \
      'mollusk_deposit_rejects_'

# User-registry litesvm tests only (no Light fixture bundle required).
test-user-registry-litesvm: build-programs
    cargo nextest run -p user-registry-tests

# Unit, integration, and property tests for the client-side SDK crates, plus
# the ring service and the custom-ring host crates, which all run against
# in-memory fakes. nextest skips doctests, so the `--doc` line keeps the
# zolana-keypair doctest covered. The zolana-client proving binaries are behind
# its `proofs` feature, so `--features client` stays hermetic.
test-sdk-libs:
    cargo nextest run -p zolana-keypair
    cargo test --doc -p zolana-keypair
    cargo nextest run -p zolana-transaction
    cargo nextest run -p zolana-client --features client
    cargo nextest run -p zolana-wallet
    cargo nextest run -p zolana-ring-client
    cargo nextest run -p zolana-ring-rpc
    cargo nextest run -p custom-ring-sdk
    cargo nextest run -p custom-ring-cli
    cargo nextest run -p custom-ring-interface
    cargo nextest run -p zolana-ring-policy

# TypeScript SDK formatting, linting, types, unit tests, and package build.
test-ts:
    npm run check:ts

# Full TypeScript SDK flow against a fresh validator, Photon, and prover.
test-ts-e2e: (_test-ts-live "test:ts:e2e")

# Public TypeScript SDK example against a fresh validator, Photon, and prover.
test-ts-example: (_test-ts-live "test:ts:example")

_test-ts-live test-script: build-programs build-prover-server build-cli ensure-photon ensure-custom-ring-live-keys
    #!/usr/bin/env bash
    set -euo pipefail
    # A command substitution that exits nonzero is no `set -e` trigger, so the
    # ids are captured first and each one the recipe reads is required.
    program_ids="$(cargo run -q -p xtask -- program-ids)"
    eval "$program_ids"
    : "${SHIELDED_POOL_PROGRAM_ID:?xtask did not emit SHIELDED_POOL_PROGRAM_ID}"
    : "${USER_REGISTRY_PROGRAM_ID:?xtask did not emit USER_REGISTRY_PROGRAM_ID}"
    : "${CUSTOM_RING_PROGRAM_ID:?xtask did not emit CUSTOM_RING_PROGRAM_ID}"
    : "${DEFAULT_TREE_ADDRESS:?xtask did not emit DEFAULT_TREE_ADDRESS}"
    bin="target/debug/zolana"
    workdir="target/ts-sdk-e2e"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-prover-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-ring-rpc-port}}" 2>/dev/null | xargs kill 2>/dev/null || true
    }
    trap cleanup EXIT
    rm -rf "$workdir"
    mkdir -p "$workdir"
    export ZOLANA_CONFIG_DIR="$PWD/$workdir"
    photon_bin="{{photon-bin}}"
    [[ "$photon_bin" = /* ]] || photon_bin="$PWD/$photon_bin"
    keys_dir="{{spp-keys-dir}}"
    [[ "$keys_dir" = /* ]] || keys_dir="$PWD/$keys_dir"
    export ZOLANA_PHOTON_BIN="$photon_bin"
    export ZOLANA_PROVER_KEYS_DIR="$keys_dir"
    cleanup
    sleep 2

    # Generate the canonical protocol accounts (protocol config, asset counter,
    # and the state Merkle tree that stores private token accounts (UTXOs) at
    # DEFAULT_TREE_ADDRESS) from the current local build and load them at
    # validator boot, so the localnet matches production addresses and no tree
    # is created at runtime. The snapshot leaves ring creation permissionless,
    # so the ring registers itself with SPP without a Squads vault co-signer.
    accounts_dir="$workdir/accounts"
    cargo run -q -p xtask -- generate-account-snapshots \
      --deploy-dir target/deploy --accounts-dir "$accounts_dir"

    ring_dir="$workdir/ring"
    ring_origin="http://localhost:3000"
    ring_rpc_url="http://127.0.0.1:{{localnet-ring-rpc-port}}"
    mkdir -p "$ring_dir"
    solana-keygen new --no-bip39-passphrase --silent --force -o "$ring_dir/authority.json"
    ring_authority="$(solana-keygen pubkey "$ring_dir/authority.json")"

    # The ring program is loaded upgradeable, only its upgrade authority may
    # create the ring config.
    "$bin" dev start --no-use-surfpool \
      --rpc-port {{localnet-rpc-port}} --prover-port {{localnet-prover-port}} \
      --photon-port {{localnet-photon-port}} --account-dir "$accounts_dir" \
      --sbf-program "$SHIELDED_POOL_PROGRAM_ID" target/deploy/shielded_pool_program.so \
      --sbf-program "$USER_REGISTRY_PROGRAM_ID" target/deploy/zolana_user_registry.so \
      --upgradeable-program "$CUSTOM_RING_PROGRAM_ID" target/deploy/custom_ring_program.so \
      "$ring_authority"
    "$bin" config set --rpc-url {{localnet-rpc-url}} \
      --indexer-url {{localnet-photon-url}} --prover-url {{localnet-prover-url}} >/dev/null
    "$bin" wallet new --outfile "$workdir/authority.json"
    mint_output="$("$bin" dev pool test-mint --keypair "$workdir/authority.json" \
      --authority-path "$workdir/authority.json" --airdrop-lamports 20000000000 \
      --amount 1000000)"
    mint="$(sed -n 's/^ok test_mint mint=\([^ ]*\).*/\1/p' <<<"$mint_output")"
    token_account="$(sed -n 's/^ok test_mint .* token_account=\([^ ]*\).*/\1/p' <<<"$mint_output")"
    test -n "$mint"
    test -n "$token_account"
    token_2022_output="$("$bin" dev pool test-mint --keypair "$workdir/authority.json" \
      --authority-path "$workdir/authority.json" --token-program token2022 --amount 1000000)"
    token_2022_mint="$(sed -n 's/^ok test_mint mint=\([^ ]*\).*/\1/p' <<<"$token_2022_output")"
    token_2022_account="$(sed -n 's/^ok test_mint .* token_account=\([^ ]*\).*/\1/p' <<<"$token_2022_output")"
    test -n "$token_2022_mint"
    test -n "$token_2022_account"

    # The ring CLI parses both targets even though this ring only acts on localnet.
    cat > "$ring_dir/ring.toml" <<TOML
    name = "ts-sdk-e2e-ring"
    program_id = "$CUSTOM_RING_PROGRAM_ID"
    authority_keypair = "$PWD/$ring_dir/authority.json"
    target = "localnet"

    [localnet]
    rpc = "{{localnet-rpc-url}}"
    indexer = "{{localnet-photon-url}}"
    prover = "{{localnet-prover-url}}"
    ring_rpc = "$ring_rpc_url"

    [devnet]
    rpc = "{{localnet-rpc-url}}"
    indexer = "{{localnet-photon-url}}"
    prover = "{{localnet-prover-url}}"
    ring_rpc = "$ring_rpc_url"
    TOML
    cargo run -q -p zolana-ring-rpc -- keygen --out "$ring_dir/auditor.key"
    cargo run -q -p custom-ring-cli -- --config "$ring_dir/ring.toml" \
      init --auditor-pubkey-file "auditor.key.pub"
    # Reads are grant only, the ring authority included.
    cargo run -q -p custom-ring-cli -- --config "$ring_dir/ring.toml" \
      reader grant "$ring_authority"

    # Local mode, the served key is the one the ring config pins.
    cargo build -q -p zolana-ring-rpc
    nohup target/debug/ring-rpc serve --port {{localnet-ring-rpc-port}} \
      --indexer-url {{localnet-photon-url}} --rpc-url {{localnet-rpc-url}} \
      --auditor-key-file "$ring_dir/auditor.key" --ring-program-id "$CUSTOM_RING_PROGRAM_ID" \
      --allow-origin "$ring_origin" --webauthn-rp-id localhost \
      > "$workdir/ring-rpc.log" 2>&1 &
    printf 'waiting for ring rpc %s ' "$ring_rpc_url"
    for _ in $(seq 1 60); do
      if curl -sf --max-time 5 "$ring_rpc_url/health" >/dev/null 2>&1; then break; fi
      printf '.'
      sleep 1
    done
    if ! curl -sf --max-time 5 "$ring_rpc_url/health" >/dev/null 2>&1; then
      echo " timed out"
      echo "the ring rpc did not answer, see $workdir/ring-rpc.log" >&2
      exit 1
    fi
    echo " ready"
    # The ring-status probe, otherwise exercised only against a hosted rpc.
    cargo run -q -p custom-ring-cli -- --config "$ring_dir/ring.toml" rpc-check

    ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" \
      ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      ZOLANA_PROVER_URL="{{localnet-prover-url}}" \
      ZOLANA_TREE="$DEFAULT_TREE_ADDRESS" \
      ZOLANA_TEST_MINT="$mint" \
      ZOLANA_TEST_TOKEN_ACCOUNT="$token_account" \
      ZOLANA_TEST_TOKEN_2022_MINT="$token_2022_mint" \
      ZOLANA_TEST_TOKEN_2022_ACCOUNT="$token_2022_account" \
      RING_PROGRAM_ID="$CUSTOM_RING_PROGRAM_ID" \
      RING_RPC_URL="$ring_rpc_url" \
      RING_AUTHORITY_KEYPAIR="$PWD/$ring_dir/authority.json" \
      RING_ORIGIN="$ring_origin" \
      ZOLANA_TEST_AUTHORITY_WALLET="$PWD/$workdir/authority.json" npm run "{{test-script}}"

test-ts-all: test-ts test-ts-e2e

# Photon unit and SQLite-backed integration tests. The Postgres migration smoke
# test runs in CI where a database service is available.
test-photon:
    cargo nextest run -p photon-indexer

# Paths dropped at report time. Single source of truth for `coverage-report`,
# which both `just coverage` and the CI job go through.
coverage-ignore-paths := '(program-tests|sdk-tests|bench)/'

# Line/region coverage via cargo-llvm-cov over the library and binary crates.
# Default prints a summary; `just coverage --html` writes target/llvm-cov/html,
# `just coverage --lcov --output-path lcov.info` for CI upload. `{{args}}` reaches
# the report step, so the collection pass stays fixed.
#
# Which crates are measured is decided by manifest PATH in
# tools/coverage-packages.py, not by a list of names here: #181 renamed
# zone-test-program to ring-test-program, a name-based `--exclude` stopped
# matching, and a test crate silently entered the coverage set and failed the
# job. See that script for what each excluded directory is and why.
#
# `zolana-client/client` reaches its indexer and RPC surfaces. Its proving
# binaries need the `proofs` feature, which stays off, so this run is hermetic.
coverage *args="--summary-only":
    #!/usr/bin/env bash
    # `set -e` matters here: without it a failing coverage-packages.py expands to
    # no `-p` flags at all, cargo silently falls back to the workspace's
    # default-members (forester, zolana-interface, shielded-pool-program), and
    # the job reports that as a successful coverage run.
    set -euo pipefail
    packages="$(python3 tools/coverage-packages.py)"
    cargo llvm-cov clean --workspace
    # Unquoted on purpose: the flags must word-split into separate arguments.
    cargo llvm-cov --no-report $packages --features zolana-interface/solana,zolana-client/client
    just coverage-report {{args}}

# Re-render the collected profile data. Split out so `just coverage` and the CI
# job share one definition of the path filter rather than repeating it per
# output format.
#
# The filter is needed because selecting crates with `-p` keeps a crate's own
# tests from running but still instruments its source wherever a covered binary
# links it, so the harness crates would otherwise land in the report at ~0% and
# depress the total while measuring nothing shipped.
coverage-report *args="--summary-only":
    cargo llvm-cov report --ignore-filename-regex '{{ coverage-ignore-paths }}' {{args}}

# All zolana-client tests (lib unit tests and the proving/integration test
# binaries). The proving tests spawn the prover server
# (via the zolana CLI), which lazily downloads any missing proving keys from
# CloudFront (verified against the committed lockfile; no token). Builds the Go
# prover binary and the zolana CLI the spawned server/test rely on.
test-client-integration: build-prover-server build-cli
    cargo nextest run -p zolana-client --all-features --test-threads 1
    cargo test --doc -p zolana-client --all-features

# One real transfer proof through Redis, TransferQueueWorker, and the Rust
# client's async /prove status polling. Requires a reachable Redis URL.
test-client-async-transfer-queue: build-prover-server build-cli
    #!/usr/bin/env bash
    set -euo pipefail
    : "${ZOLANA_PROVER_REDIS_URL:?set ZOLANA_PROVER_REDIS_URL to a reachable Redis instance}"
    ZOLANA_EXPECT_ASYNC_PROVER=true \
        cargo nextest run -p zolana-client --features proofs --test transfer_dummy -E 'test(=dummy_transfer_2_3_proof_verifies)' --test-threads 1

# Program integration tests backed by LiteSVM. Transact tests spawn the prover
# through the zolana CLI.
test-programs: build-programs build-prover-server build-cli
    cargo nextest run -p shielded-pool-tests --features proofs --test-threads 1

# Proving-key-independent interface, program, and LiteSVM proofless tests.
# The explicit shielded-pool suites cover pool administration, deposit batches,
# and ring config (including the fixture program's signed CPI into SPP); the
# proof-backed binaries are gated behind the `proofs` feature, so the plain
# package run is hermetic by construction.
test-proofless-programs: build-programs
    cargo test -p zolana-interface --features solana
    cargo test -p shielded-pool-program --lib --tests
    cargo nextest run -p shielded-pool-tests

# Aggregate of all CI-runnable Rust tests. Needs a prover and the released
# custom-ring keys. `just test-hermetic` is the subset that needs nothing.
test-all: test test-programs test-user-registry-litesvm test-swap-program test-custom-ring

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
    cargo nextest run -p zolana-cli

# === Bench ===
#
# Bench recipes stay on `cargo test ... -- --ignored --nocapture`, not nextest:
# they are manual profiling runs (regenerate a CU report), so nextest's
# hang-timeout/retry value does not apply, and `--run-ignored` + streamed
# --nocapture output is simplest via plain `cargo test`.

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
    cargo test -p shielded-pool-tests --features proofs --test bench_cu -- --ignored --nocapture

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
swap-keys-tag := "swap-keys-v4"

# Same contract as swap-keys-tag, for the dynamic-swap example's two circuits
# (escrow_open/escrow_settle). The release assets are
# the only key set matching the committed Rust verifying keys; rotating locally
# (regen-dynamic-swap-keys) requires publishing a new release and updating
# dynamic-swap-keys.CHECKSUM plus the committed verifying keys together.
dynamic-swap-keys-tag := "dynamic-swap-keys-v4"

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

ensure-dynamic-swap-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    base="sdk-tests/dynamic-swap"
    for c in escrow_open escrow_settle; do
        dir="$base/build/gnark/$c"
        for kind in pk vk; do
            if [ ! -f "$dir/$kind.bin" ]; then
                mkdir -p "$dir"
                gh release download "{{dynamic-swap-keys-tag}}" --repo helius-labs/zolana \
                    --pattern "${c}_${kind}.bin" --output "$dir/$kind.bin" --clobber
            fi
            want=$(awk -v n="${c}_${kind}.bin" '$2==n {print $1}' "$base/dynamic-swap-keys.CHECKSUM")
            got=$(shasum -a 256 "$dir/$kind.bin" | awk '{print $1}')
            if [ "$want" != "$got" ]; then
                echo "checksum mismatch for $dir/$kind.bin (want $want, got $got)" >&2
                echo "refresh from the {{dynamic-swap-keys-tag}} release (delete the file and rerun)," >&2
                echo "or rotate keys with 'just regen-dynamic-swap-keys' and publish a new release" >&2
                exit 1
            fi
        done
    done

# Rotate the dynamic-swap proving keys: regenerate every circuit, rewriting the
# committed Rust verifying keys and the checksum manifest. Publish the new
# build/gnark key files to a fresh dynamic-swap-keys release and bump
# dynamic-swap-keys-tag afterwards.
regen-dynamic-swap-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    base="sdk-tests/dynamic-swap"
    for c in escrow_open escrow_settle; do
        cargo run --release -p dynamic-swap-prover --bin dynamic-swap-prover-setup -- \
            "$c" "$base/build/gnark/$c" \
            --rust-vk "$base/program/src/verifying_keys/$c.rs"
    done
    : > "$base/dynamic-swap-keys.CHECKSUM"
    for c in escrow_open escrow_settle; do
        for kind in pk vk; do
            shasum -a 256 "$base/build/gnark/$c/$kind.bin" \
                | awk -v n="${c}_${kind}.bin" '{print $1 "  " n}' >> "$base/dynamic-swap-keys.CHECKSUM"
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

# Confidential RFQ settlement CU benchmark: profiles a single co-signed
# shielded-pool `transact` (SOL for USDC, no escrow, no custom program) under
# mollusk. The shielded-pool program is built with profile-program so its
# `#[profile]` functions appear in the CU table; it must never land in
# target/deploy, so build into a dedicated dir matching PROFILING_SBF_DIR in
# bench_cu.rs.
bench-rfq:
    cargo build-sbf --tools-version {{sbf-tools-version}} \
        --sbf-out-dir target/rfq-bench \
        --manifest-path programs/shielded-pool/Cargo.toml \
        -- --features bpf-entrypoint,profile-program
    cargo test -p rfq-test --test bench_cu -- --ignored --nocapture

# Fetch the pinned escrow/withdraw proving keys from the escrow-keys release
# and verify them against the committed manifest. groth16.Setup is
# non-deterministic, so the published keys are the only set matching the
# committed Rust verifying keys; regenerating locally (regen-escrow-keys)
# requires publishing a new release and updating timelock-escrow-keys.CHECKSUM
# plus the committed verifying keys together.
escrow-keys-tag := "escrow-keys-v2"

ensure-escrow-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    base="sdk-tests/timelock-escrow"
    for c in escrow withdraw; do
        dir="$base/build/gnark/$c"
        for kind in pk vk; do
            if [ ! -f "$dir/$kind.bin" ]; then
                mkdir -p "$dir"
                gh release download "{{escrow-keys-tag}}" --repo helius-labs/zolana \
                    --pattern "${c}_${kind}.bin" --output "$dir/$kind.bin" --clobber
            fi
            want=$(awk -v n="${c}_${kind}.bin" '$2==n {print $1}' "$base/timelock-escrow-keys.CHECKSUM")
            got=$(shasum -a 256 "$dir/$kind.bin" | awk '{print $1}')
            if [ "$want" != "$got" ]; then
                echo "checksum mismatch for $dir/$kind.bin (want $want, got $got)" >&2
                echo "refresh from the {{escrow-keys-tag}} release (delete the file and rerun)," >&2
                echo "or rotate keys with 'just regen-escrow-keys' and publish a new release" >&2
                exit 1
            fi
        done
    done

# Rotate the escrow/withdraw proving keys: regenerate both circuits, rewriting
# the committed Rust verifying keys and the checksum manifest. Publish the new
# build/gnark key files to a fresh escrow-keys release and bump
# escrow-keys-tag afterwards.
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

# The profiling dynamic-swap build calls the same profiler syscall
# solana-test-validator does not register, so it must never land in
# target/deploy either -- build the bench programs into their own dedicated
# dir, matching PROFILING_SBF_DIR in dynamic-swap's bench_cu.rs. dynamic-swap's
# own gnark keys (build/gnark/{escrow_open,escrow_settle}) are
# generated locally and gitignored; there is no release download step for them
# yet, so this assumes they already exist.
bench-dynamic-swap:
    cargo build-sbf --tools-version {{sbf-tools-version}} \
        --sbf-out-dir target/dynamic-swap-bench \
        --manifest-path programs/shielded-pool/Cargo.toml \
        -- --features bpf-entrypoint
    cargo build-sbf --tools-version {{sbf-tools-version}} \
        --sbf-out-dir target/dynamic-swap-bench \
        --manifest-path sdk-tests/dynamic-swap/program/Cargo.toml \
        -- --features bpf-entrypoint,profile-program
    cargo test -p dynamic-swap-test --test bench_cu -- --ignored --nocapture

# === Local validator helpers ===

# Local-validator proofless deposit coverage only. Unlike test-localnet-e2e,
# this starts no prover and runs no transact/withdraw circuit.
test-localnet-deposit: build-programs build-cli
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cargo run -p zolana-cli -- dev start --local --skip-prover --no-use-surfpool --rpc-port {{localnet-rpc-port}} --sbf-program "$SHIELDED_POOL_PROGRAM_ID" target/deploy/shielded_pool_program.so --sbf-program "$USER_REGISTRY_PROGRAM_ID" target/deploy/zolana_user_registry.so --sbf-program "$RING_TEST_PROGRAM_ID" target/deploy/ring_test_program.so
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" cargo test -p shielded-pool-tests --features localnet --test localnet_deposit -- --nocapture

# Local-validator end-to-end SOL cycle.
test-localnet-e2e: build-programs build-prover-server build-cli
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    # `localnet_e2e` and `localnet_deposit` each create the singleton
    # `protocol_config` PDA, so they cannot share one ledger. `dev start` stops
    # any running validator and resets, so restarting between the suites gives
    # each a clean environment (mirroring the per-test restart in the Photon
    # recipe below).
    dev_start() {
      cargo run -p zolana-cli -- dev start --local --skip-prover --no-use-surfpool --rpc-port {{localnet-rpc-port}} --sbf-program "$SHIELDED_POOL_PROGRAM_ID" target/deploy/shielded_pool_program.so --sbf-program "$USER_REGISTRY_PROGRAM_ID" target/deploy/zolana_user_registry.so --sbf-program "$RING_TEST_PROGRAM_ID" target/deploy/ring_test_program.so
    }
    dev_start
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" cargo nextest run -p shielded-pool-tests --features localnet --test localnet_e2e --no-capture
    dev_start
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" cargo nextest run -p shielded-pool-tests --features localnet --test localnet_deposit --no-capture

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
      cargo nextest run -p shielded-pool-tests --features localnet --test localnet_photon --no-capture
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo nextest run -p shielded-pool-tests --features localnet --test localnet_wallet_cli --no-capture

# Spawn a localnet (validator + prover + photon) via the `zolana` CLI, bootstrap a
# pool tree with an authority wallet, then run the tools/cli_smoke.sh coverage
# script against it: one pass over every CLI operation using the real binary,
# both asset rails (SOL + SPL) on the supported ed25519 wallet rail. The
# authority wallet doubles as the smoke actor so the SPL `test-mint` rail is
# permitted. Services and workdir are torn down on exit.
test-cli-smoke: build-programs build-prover-server build-cli ensure-photon
    #!/usr/bin/env bash
    set -euo pipefail
    eval "$(cargo run -q -p xtask -- program-ids)"
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_PROVER_KEYS_DIR="$PWD/{{spp-keys-dir}}"
    bin="target/debug/zolana"
    workdir="target/cli-smoke"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-prover-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    rm -rf "$workdir"; mkdir -p "$workdir"
    export ZOLANA_CONFIG_DIR="$PWD/$workdir"

    # Clear any services left over from a previous run so the validator binds
    # cleanly (dev start also stops them, but this avoids a port-release race).
    cleanup; sleep 2

    # 1. Spawn services (dev start daemonizes the validator/prover/photon and
    #    returns once each is ready).
    "$bin" dev start --no-use-surfpool \
      --rpc-port {{localnet-rpc-port}} --prover-port {{localnet-prover-port}} \
      --photon-port {{localnet-photon-port}} \
      --sbf-program "$SHIELDED_POOL_PROGRAM_ID" target/deploy/shielded_pool_program.so \
      --sbf-program "$USER_REGISTRY_PROGRAM_ID" target/deploy/zolana_user_registry.so \
      --sbf-program "$RING_TEST_PROGRAM_ID" target/deploy/ring_test_program.so

    # 2. Bootstrap: a funder keypair (funds the smoke wallets), an authority wallet
    #    (also the smoke actor), and a pool tree. Capture the created tree address.
    funder="$workdir/funder.json"
    solana-keygen new --no-bip39-passphrase --silent --force --outfile "$funder"
    "$bin" config set --rpc-url {{localnet-rpc-url}} \
      --indexer-url {{localnet-photon-url}} --prover-url {{localnet-prover-url}} >/dev/null
    "$bin" wallet new --outfile "$workdir/alice.json"
    tree="$("$bin" dev pool create-tree --keypair "$workdir/alice.json" \
      --tree-keypair "$workdir/tree.json" --airdrop-lamports 20000000000 \
      | sed -n 's/^ok tree //p')"
    solana airdrop 100 "$(solana address --keypair "$funder")" --url {{localnet-rpc-url}} >/dev/null

    # 3. Run the coverage script against the live localnet.
    WORKDIR="$PWD/$workdir" ZOLANA_BIN="$PWD/$bin" FUNDER="$PWD/$funder" \
      RPC="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      ZOLANA_PROVER_URL="{{localnet-prover-url}}" ZOLANA_TREE="$tree" \
      tools/cli_smoke.sh

# Run only the proof-bearing batch nullifier-tree lifecycle and its per-batch CU ceiling.
test-nullifier-batch-proof-cu: build-programs build-prover-server build-cli ensure-photon ensure-smart-account
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
      cargo nextest run -p shielded-pool-tests --features localnet --test localnet_photon \
      --no-capture -E 'test(nullifier_test_forester_batches_queued_nullifiers_with_photon_indexer)'

# Decrypt-and-spend lifecycle tests over a fresh validator + Photon per test
# (program-tests/spp-test-validator).
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
      cargo nextest run -p spp-test-validator --test lifecycle --test proof_cu

# Run only real-validator CU ceilings for P256 transact and maximal 8x1 merge.
test-spp-validator-proof-cu: build-programs build-prover-server build-cli ensure-photon
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
      cargo nextest run -p spp-test-validator --test proof_cu --no-capture

# Run the transfer case that also decodes the emitted event.
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
      cargo nextest run -p spp-test-validator --test lifecycle --no-capture -E 'test(=actor_payer_transfers_cover_sol_and_spl_assets)'

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
      cargo nextest run -p spp-test-validator --test lifecycle --no-capture -E 'test(merge)'

# Run only the randomized 50-transaction workload from test-spp-validator.
# Set ZOLANA_RANDOM_SEED (decimal or 0x-prefixed hex) to replay a run.
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
      cargo nextest run -p spp-test-validator --test lifecycle --no-capture -E 'test(randomized_mixed_asset)'

# Run the non-randomized spp-validator lifecycle tests.
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
      cargo nextest run -p spp-test-validator --test lifecycle --no-capture \
      -E 'not test(randomized_mixed_asset) and not test(merge)'

# Run the transfer lifecycle case.
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
      cargo nextest run -p spp-test-validator --test lifecycle --no-capture -E 'test(transfer)'

# Ring lifecycle tests over a fresh validator + Photon per test
# (program-tests/ring-test-program). Mirrors test-spp-validator but loads the
# policy-ring fixture program (ring_test_program.so) and CPIs into SPP via its
# `ring_auth` PDA, so the recipe also exports RING_TEST_PROGRAM_ID and
# USER_REGISTRY_PROGRAM_ID. build-programs builds ring_test_program.so; the merge
# flow reads the user-registry record so that program must be co-loaded, and the
# ring deposits use the Squads smart account binary (ensure-smart-account). The
# prover server persists while each test restarts the validator + Photon.
test-ring-validator: build-programs build-prover-server build-cli ensure-photon ensure-smart-account
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
    export RING_TEST_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo nextest run -p ring-test-program --test ring_lifecycle --test p256_ring_lifecycle --test proof_cu --release

# Run only real-validator CU ceilings for ring EdDSA/P256 transact,
# ring-authority transact, and maximal 8x1 merge-ring.
test-ring-validator-proof-cu: build-programs build-prover-server build-cli ensure-photon ensure-smart-account
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
    export RING_TEST_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo nextest run -p ring-test-program --test proof_cu --release --no-capture

# Regenerate services/photon/tests/fixtures/ring_transact.json from a real ring
# CPI. The fixture is committed; Photon replays it without a validator. Run this
# only when the ring account layout or the transaction shape changes.
dump-ring-fixture: build-programs build-prover-server build-cli ensure-photon ensure-smart-account
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
    export RING_TEST_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo nextest run -p ring-test-program --test ring_lifecycle --release \
      --run-ignored all --no-capture -E 'test(=dump_ring_transact_fixture)'

# Fully-inlined create+fill (derived and verifiable-encryption take rails) and
# create+cancel swap flows over a fresh validator
# (sdk-tests/zk-program-swap/test/tests/{swap,take_verifiable_encryption,cancel}.rs).
# Each test binary boots solana-test-validator via the `zolana` CLI with the swap
# program, the shielded pool, the user registry, and the Squads smart account
# loaded together, plus Photon and the persistent SPP prover -- mirroring
# test-spp-validator. Cargo runs the test binaries serially, so each boots a
# fresh validator.
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
      cargo nextest run -p swap-test-validator --test swap --test take_verifiable_encryption --test cancel --no-capture

# Custom-ring lifecycle on a local validator
# (custom-rings/test/tests/ring.rs): create the ring config holding the
# auditor key, register it with SPP, ring-deposit, then a ring transact whose
# proof binds the verifiable encryption of the transaction viewing key to the
# auditor key -- and assert the auditor client decrypts the outputs.
test-custom-ring-validator: ensure-custom-ring-live-keys build-programs build-cli ensure-photon ensure-smart-account
    #!/usr/bin/env bash
    set -euo pipefail
    # `eval "$(...)"` alone cannot fail the recipe: a command substitution that
    # exits nonzero is not a `set -e` trigger, so a broken xtask would leave the
    # program ids unset and the test would silently run against its fallbacks.
    program_ids=$(cargo run -q -p xtask -- program-ids)
    eval "$program_ids"
    : "${CUSTOM_RING_PROGRAM_ID:?xtask did not emit CUSTOM_RING_PROGRAM_ID}"
    : "${SHIELDED_POOL_PROGRAM_ID:?xtask did not emit SHIELDED_POOL_PROGRAM_ID}"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    export CUSTOM_RING_PROGRAM_ID
    export SHIELDED_POOL_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    cargo build -q -p custom-ring-cli
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo nextest run -p custom-ring-test-validator --test ring --no-capture
    if [ -n "${ZOLANA_RING_TEMPLATE_DIR:-}" ]; then
      cargo nextest run -p custom-ring-cli --run-ignored all -E 'binary(new_smoke)'
    fi

# Two-ring shared policy source lifecycle on a local validator
# (custom-rings/test/tests/shared_sources.rs): both rings run the blocklist
# image, the subscriber's Block kind reads the curator's records, one curator
# write refuses the subscriber's transfer, clearing it or re-pointing the
# source re-admits it. The `blocklist` test feature must match the image, the
# on-chain policy hash pins the compiled table.
test-custom-ring-shared: ensure-custom-ring-live-keys build-programs build-cli ensure-photon ensure-smart-account
    #!/usr/bin/env bash
    set -euo pipefail
    program_ids=$(cargo run -q -p xtask -- program-ids)
    eval "$program_ids"
    : "${CUSTOM_RING_PROGRAM_ID:?xtask did not emit CUSTOM_RING_PROGRAM_ID}"
    : "${SHIELDED_POOL_PROGRAM_ID:?xtask did not emit SHIELDED_POOL_PROGRAM_ID}"
    cleanup() {
      lsof -ti "tcp:{{localnet-rpc-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      lsof -ti "tcp:{{localnet-photon-port}}" 2>/dev/null | xargs kill -9 2>/dev/null || true
      pkill -f solana-test-validator 2>/dev/null || true
    }
    trap cleanup EXIT
    export CUSTOM_RING_PROGRAM_ID
    export SHIELDED_POOL_PROGRAM_ID
    export ZOLANA_PHOTON_BIN="{{photon-bin}}"
    export ZOLANA_LOCALNET_RPC_PORT="{{localnet-rpc-port}}"
    export ZOLANA_LOCALNET_PHOTON_PORT="{{localnet-photon-port}}"
    export CUSTOM_RING_PROGRAM_SO="$PWD/target/deploy-ring-blocklist/custom_ring_program.so"
    env ZOLANA_LOCALNET_URL="{{localnet-rpc-url}}" ZOLANA_INDEXER_URL="{{localnet-photon-url}}" \
      cargo nextest run -p custom-ring-test-validator --test shared_sources --features blocklist --no-capture

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
      cargo nextest run -p timelock-escrow-test --test escrow --no-capture

# Runs the swap and escrow lifecycle suites back to back in one CI job.
test-swap-and-escrow-validator: test-swap-validator test-escrow-validator

# Plaintext compressed-account lifecycle on a local validator
# (sdk-tests/compression/test/tests/compression.rs). The test binary runs
# `xtask generate-account-snapshots` itself and boots solana-test-validator
# via the `zolana` CLI with the compression example program and the shielded
# pool loaded, plus Photon and the persistent SPP prover -- mirroring
# test-escrow-validator. The test resolves target/debug/{zolana,xtask} itself,
# so build-cli and the explicit xtask build must run first.
test-compression-validator: build-programs build-prover-server build-cli ensure-photon
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build -q -p xtask
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
      cargo nextest run -p compression-example-test --test compression --no-capture

# Minimal zolana-client SDK example: deposit, shielded transfer, and withdrawal
# building the SPP instructions by hand and submitting them
# (sdk-tests/client/rust/deposit_transfer_withdraw.rs). Boots
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

# Dynamic-swap example lifecycle tests
# (sdk-tests/dynamic-swap/test/tests/{pair,escrow_flow,escrow_refund}.rs). Each
# test binary boots its own solana-test-validator +
# Photon via the `zolana` CLI and starts the shared SPP prover server itself
# (spawn_prover); dynamic-swap's own circuits (escrow_open/
# escrow_settle) prove in-process through an embedded gnark FFI,
# no separate prover process for those. Needs the Squads smart-account binary
# (ensure-smart-account) since setup() always loads it, and exports the
# per-clone ZOLANA_PORT_OFFSET-derived ports/URLs like the other localnet
# recipes so it never collides with a concurrent session on the default
# ports. Pass extra cargo-test args to select a single test binary, e.g.
# `just test-dynamic-swap --test pair`.
test-dynamic-swap *args: ensure-dynamic-swap-keys build-programs build-prover-server build-cli ensure-photon ensure-smart-account
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
      cargo nextest run -p dynamic-swap-test {{args}} --no-capture

# Confidential RFQ settlement on a local validator: the maker and taker co-sign
# one shielded-pool transact that swaps SOL for USDC with no escrow and no custom
# program (sdk-tests/rfq/tests/rfq.rs). Boots solana-test-validator via the
# `zolana` CLI with the shielded pool, the user registry, and the Squads smart
# account, plus Photon and the SPP prover -- mirroring test-client-example.
test-rfq-validator: build-programs build-prover-server build-cli ensure-photon ensure-smart-account
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
      cargo test -p rfq-test --test rfq -- --nocapture

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

# Build one service image locally and publish it to ECR by the same rules as
# the publish-image workflow, `just publish-image prover --push`.
publish-image service *args:
    tools/publish-image.sh {{service}} {{args}}

# Isolated ECS test deployment of the prover and one ring RPC, every resource
# named zolana-rings-test-*, `RINGS_TEST_INDEXER_URL=... just rings-test up`.
rings-test command *args:
    tools/rings-test-deploy.sh {{command}} {{args}}

build-prover-server:
    mkdir -p target
    cd prover/server && go build -o ../../target/prover-server .

# Regenerate all proving keys (transfer, merge, custom ring, and batch
# address-append), the committed verifying keys in both crates, and
# proving-keys.lock. groth16 setup is non-deterministic, so the
# batched-merkle-tree vkeys are regenerated with the keys -- commit both
# together. Mirrors scripts/rotate_proving_keys.sh minus the fingerprint refresh
# and the S3 upload (publish-spp-keys).
build-spp-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    keys_dir="$(cd "$(dirname "{{spp-keys-dir}}")" && pwd)/$(basename "{{spp-keys-dir}}")"
    prover/server/scripts/generate_keys_transfer.sh "$keys_dir"
    prover/server/scripts/generate_keys_merge.sh "$keys_dir"
    prover/server/scripts/generate_keys_custom_ring.sh "$keys_dir"
    # The generate_* scripts leave the light-prover binary in prover/server.
    for spec in 10 250; do
        prover/server/light-prover setup \
            --circuit address-append \
            --address-append-tree-height 40 \
            --address-append-batch-size "$spec" \
            --output "$keys_dir/batch_address-append_40_${spec}.key" \
            --output-vkey "$keys_dir/batch_address-append_40_${spec}.vkey"
    done
    prover/server/scripts/regenerate_all_vkeys.sh "$keys_dir"
    tmp_dir="$(mktemp -d)"
    trap 'rm -rf "$tmp_dir"' EXIT
    for spec in 10 250; do
        stem="batch_address-append_40_${spec}"
        module="batch_address_append_40_${spec}"
        prover/server/light-prover export-vk --keys-file "$keys_dir/${stem}.key" --output "$tmp_dir/${stem}.vkbin" >/dev/null
        cargo run -q -p xtask -- bsb22-vk \
            "$tmp_dir/${stem}.vkbin" \
            "program-libs/batched-merkle-tree/src/verify/verifying_keys" \
            "${module}.rs"
    done
    python3 prover/server/scripts/generate_lockfile.py "$keys_dir"

# Upload the local proving keys to their immutable S3 version folder; the prefix
# (proving-keys/<version-hash>) comes from the committed lockfile. Needs the aws
# CLI with bucket write access. Full rotation (regen keys + vkeys + lock + upload)
# is scripts/rotate_proving_keys.sh.
publish-spp-keys:
    #!/usr/bin/env bash
    set -euo pipefail
    bucket="${ZOLANA_PROVING_KEYS_BUCKET:-zolana-proving-keys}"
    prefix="$(python3 -c "import json; print(json.load(open('prover/server/prover/provingkeys/proving-keys.lock'))['prefix'])")"
    aws s3 sync "{{spp-keys-dir}}/" "s3://$bucket/$prefix/" --exclude '*' --include '*.key'

build-photon:
    cargo build --locked -p photon-indexer --bin photon --target-dir target

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

# Build the localnet release artifacts and regenerate cli/release-artifacts.lock:
# version-suffixed program .so files, an account-snapshot bundle (generated
# in-process with LiteSVM -- no keypairs or running validator needed), and the
# prover/photon binaries for the host platform plus linux-x64 (Go cross-compile
# for the prover; Docker for the linux photon, so docker must be running).
# Stages assets and rewrites the lockfile only, unless you forward flags to
# `create-release`: add `--upload` to publish via `gh release create`
# (re-published cleanly, tag re-pointed at HEAD) and `--prerelease` to mark a
# GitHub pre-release. Example: `just release v0.1.0-alpha --upload --prerelease`.
release tag *args: build-programs fetch-smart-account
    cargo run -p xtask -- create-release --tag {{tag}} {{args}}

# The ring program and the zolana-ring cli only, under their own lockfile.
release-custom-rings tag *args: build-programs
    cargo run -p xtask -- create-release --custom-rings --tag {{tag}} {{args}}

# === Formatting and linting ===

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    cargo clippy --workspace --all-targets --features zolana-client/proofs -- -D warnings

check-test-hygiene:
    ./tools/check-test-hygiene.sh

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

# Exports one verifying key end to end. The xtask shells out to the Go prover,
# so Go is required. The single 8 MB proving key is fetched into a scratch
# directory and checked against the lockfile sha256.
[private]
xtask-create-verifying-keys-smoke:
    #!/usr/bin/env bash
    set -euo pipefail
    if ! command -v go >/dev/null 2>&1; then
        echo "go is required because xtask create-verifying-keys runs the prover server's export-vk" >&2
        exit 1
    fi
    name=transfer_confidential_1_1.key
    smoke_dir=target/verifying-keys-smoke
    keys_dir="$smoke_dir/keys"
    out_dir="$smoke_dir/out"
    mkdir -p "$keys_dir"
    want="$(python3 -c 'import json, sys; print(json.load(open("prover/server/prover/provingkeys/proving-keys.lock"))["keys"][sys.argv[1]]["sha256"])' "$name")"
    path="$keys_dir/$name"
    if [[ ! -f "$path" ]] || [[ "$(shasum -a 256 "$path" | awk '{ print $1 }')" != "$want" ]]; then
        curl -fsSL "{{proving-keys-url}}/$name" -o "$path"
        [[ "$(shasum -a 256 "$path" | awk '{ print $1 }')" == "$want" ]]
    fi
    cargo run -p xtask -- create-verifying-keys --keys-dir "$keys_dir" --out-dir "$out_dir" --limit 1
    [[ -s "$out_dir/transfer_confidential_1_1.vkey" ]]
    grep -q transfer_confidential_1_1.vkey "$out_dir/MANIFEST.txt"

# === Maintenance ===

metadata:
    cargo metadata --format-version 1 --no-deps

clean:
    cargo clean
