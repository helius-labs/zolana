# Protocol operations

This directory owns the tools and libraries used to operate Zolana.

| Directory | Purpose |
| --- | --- |
| `cli` | `zolana-protocol`: initialize protocol authorities, discover smart accounts, update configuration and tree fees, and execute program upgrades. |
| `forester` | Drain ready nullifier batches, submit updates through the forester vault, close reclaimable nullifier PDAs, and report metrics. |
| `forester-prover` | Build batch address-append inputs and prove with existing gnark keys through Go FFI or a remote prover. |
| `instructions` | Protocol administration and maintenance instruction builders; account data and tags remain in `program-libs/interface`. |
| `smart-account` | Authority vault derivations, smart-account instruction builders, role policies, and settings decoding. |
| `merkle-tree` | Reference state and indexed nullifier trees, including their indexed-array storage, shared with test infrastructure. |

Transaction helpers live separately in forester, the protocol CLI, and the SDK.

Changes anywhere under `protocol-ops/` trigger `protocol-ops / compile + test`:
Rust formatting, Clippy, Go bridge tests, remote-only compilation, and tests for
the six crates above. Changes limited to this directory skip the Rust SDK,
TypeScript, and Photon suites. Changes to shared workspace files or SDK code
still trigger their respective suites.

The protocol CLI and forester depend on protocol crates and `program-libs`, with
no Rust dependency on `sdk-libs`. Wallet and application SDKs remain there.

Protocol authority builders are imported from `zolana_protocol_instructions`
instead of `zolana_program::instruction`. The SDK's `protocol-instructions`
and `protocol` feature flags have been removed; the wallet and program
instruction builders remain in the SDK.

Run operator commands with:

```sh
cargo run -p zolana-protocol-cli -- --help
just protocol init-protocol --help
cargo run -p forester -- run --help
```

Forester uses `RPC_URL`, `PHOTON_URL`, and `PAYER`. Set `FORESTER_KEYS_DIR` to a
directory containing the existing `batch_address-append_40_<batch-size>.key`
files to prove in process. The worker reconstructs the reference tree and
builds inputs locally in this mode. No separate prover or Redis is needed.
Keys load lazily and remain cached; their SHA-256 digests must match the
checked-in verifier. The FFI archive uses the existing Go circuit and key
loader under `prover/server`, and does not generate or replace proving keys.
Building local proving support requires the Go version in `prover/server/go.mod`
and a C compiler.

Alternatively, set `PROVER_URL` to use the existing remote prover service.
`--client-proof-data` builds inputs locally before sending them; otherwise
the remote prover resolves indexed proof data. `FORESTER_KEYS_DIR` selects
local proving when both variables are set. Build with `--no-default-features`
for a remote-only forester without the Go archive.

```sh
cargo test -p forester -p zolana-forester-prover -p zolana-protocol-cli \
  -p zolana-protocol-instructions \
  -p zolana-smart-account-client -p zolana-merkle-tree
```

The ignored `local_batch_proof` test additionally loads an existing pinned
40x10 key from `FORESTER_TEST_KEYS_DIR`, generates a proof through Go FFI, and
verifies it with the checked-in Solana verifier.
Protocol CI downloads and verifies this key, then explicitly runs both the local
proof test and the Redis-backed `remote_batch_proof` test through the Forester
client. The Redis test uses `FORESTER_TEST_PROVER_BIN`, `FORESTER_TEST_KEYS_DIR`,
and `FORESTER_TEST_REDIS_URL` with an isolated Redis database.

```sh
FORESTER_TEST_KEYS_DIR=/path/to/keys cargo test -p zolana-forester-prover \
  --test local_batch_proof -- --ignored
```
