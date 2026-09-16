# PR #320 cached merge benchmark

This worktree completes the original cache path for a four-output merge: four 36-input merges and one 4-input/3-output cached transfer. It uses the existing cached circuit unchanged, a local development proving key, and a matching local verifying key. These setup keys are for benchmarking and must not be published as production trusted-setup artifacts.

All merge witnesses and the final transfer witness are built before any merge is submitted. The final transfer uses the merged commitments already known to the owner, zero as its unused state root, and the pre-merge non-inclusion proofs of the merged-output nullifiers. Original merges publish different nullifiers. Existing nullifier PDAs still prevent replay of both original and merged notes. The cache address and slot are bound into every merge's external-data hash.

The benchmark requests all five proofs together, creates an actual cache, submits each merge through the normal Squads smart-account wrapper, and executes the cached transfer. The current harness greedily packs adjacent instructions using the SDK transaction-size check; set `E2E_BENCH_PACKED=0` to retain one instruction per transaction. It waits for the recipient's indexed output and verifies wallet decryption. The v1 transaction header requests a 256 KiB heap. Cache creation is included in the transaction count, CU, and spend time. Deposits and registry setup are excluded and reported separately.

Client concurrency is not server concurrency: default `PROVER_SYNC_CONCURRENCY=1` admits one CPU proof at a time. The cold key-loading cost remains inside the first measured proving phase. There are no GPU measurements in this benchmark.

## Reproduce

Use the worktree's CLI, Photon, Surfpool and user-registry/Squads artifacts. Generate the local key and matching verifying-key module, then rebuild the local shielded-pool program:

```sh
go build -C prover/server -o ../../target/prover-server .
target/prover-server setup-transfer --circuit transfer-confidential-cached --n-inputs 4 --n-outputs 3 --output prover/server/proving-keys/transfer_confidential_cached_4_3.key
target/prover-server export-vk --keys-file prover/server/proving-keys/transfer_confidential_cached_4_3.key --output /tmp/cache-4-3.vkbin
cargo run -p xtask -- bsb22-vk /tmp/cache-4-3.vkbin program-libs/interface/src/verifying_keys transfer_confidential_cached_4_3.rs
SHIELDED_POOL_PROGRAM_ID=sppU489D7A4U1exNo1oeMGZtLEofq3a6o2fR7UeoWB6 cargo build-sbf --tools-version v1.54 --sbf-out-dir target/deploy --manifest-path programs/shielded-pool/Cargo.toml -- --locked --features bpf-entrypoint
```

The merge proving keys must match the existing merge verifying keys. The current benchmark run uses `merge_36_1.key` and `merge_8_1.key` from the existing PR #320 artifacts.

```sh
SHIELDED_POOL_PROGRAM_ID=sppU489D7A4U1exNo1oeMGZtLEofq3a6o2fR7UeoWB6 \
ZOLANA_LOCALNET_RPC_PORT=9099 ZOLANA_LOCALNET_PHOTON_PORT=8984 \
ZOLANA_LOCALNET_URL=http://127.0.0.1:9099 \
ZOLANA_INDEXER_URL=http://127.0.0.1:8984 \
ZOLANA_PROVER_URL=http://127.0.0.1:3201 \
E2E_BENCH_INPUTS=144 E2E_BENCH_WARM_KEYS=1 \
cargo test -p spp-test-validator --test proof_cu cached_merge_spend_e2e_benchmark -- --ignored --nocapture
```

Explicit `ZOLANA_CLI_BIN`, `ZOLANA_PHOTON_BIN`, and `ZOLANA_PROVER_KEYS_DIR` may be needed when multiple worktrees share dependencies. Do not run this fixture alongside another localnet fixture: the CLI currently stops local validator processes globally during startup.

For a cold-key result, omit `E2E_BENCH_WARM_KEYS` and use a freshly started prover. The warm mode discards one representative proof of each key type before the measured proving/submission phase. It still includes witness generation in the reported total.

A tested server-parallel configuration is `ZOLANA_PROVER_URL=http://127.0.0.1:3202 PROVER_SYNC_CONCURRENCY=4 GOMAXPROCS=18 E2E_BENCH_WARM_KEYS=1`. The server logs its actual permit count and `runtime.GOMAXPROCS(0)` at startup. Use a fresh prover when changing these settings.
