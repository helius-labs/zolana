# Protocol operations

This directory owns the tools and libraries used to operate Zolana.

| Directory | Purpose |
| --- | --- |
| `cli` | `zolana-protocol`: initialize protocol authorities, discover smart accounts, update configuration and tree fees, and execute program upgrades. |
| `forester` | Drain ready nullifier batches, submit updates through the forester vault, close reclaimable nullifier PDAs, and report metrics. |
| `forester-prover` | Build batch address-append inputs and prove with existing gnark keys using native Rust or a remote prover. |
| `instructions` | Protocol administration and maintenance instruction builders; account data and tags remain in `program-libs/interface`. |
| `smart-account` | Authority vault derivations, smart-account instruction builders, role policies, and settings decoding. |
| `merkle-tree` | Reference state and indexed nullifier trees, including their indexed-array storage, shared with test infrastructure. |

Transaction helpers live separately in forester, the protocol CLI, and the SDK.

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
Key metadata loads lazily after verifying the existing file's SHA-256 against
the checked-in verifier. Native Rust reads the original compressed queries,
solves the serialized R1CS, and constructs the quotient with disk-backed FFTs.
It does not generate or replace proving keys and does not build or link Go.
The 4,999 key is about 74 GB; allow approximately 32 GB more for temporary
solver files. See [`forester-prover`](forester-prover/README.md) for the
standalone proof command and memory measurement.

Alternatively, set `PROVER_URL` to use the existing remote prover service.
`--client-proof-data` builds inputs locally before sending them; otherwise
the remote prover resolves indexed proof data. `FORESTER_KEYS_DIR` selects
local proving when both variables are set. Build with `--no-default-features`
for a remote-only forester without the native proving dependencies.

```sh
cargo test -p forester -p zolana-forester-prover -p zolana-protocol-cli \
  -p zolana-protocol-instructions \
  -p zolana-smart-account-client -p zolana-merkle-tree
```

The ignored `local_batch_proof` test additionally loads an existing pinned
40x10 key from `FORESTER_TEST_KEYS_DIR`, generates a proof in native Rust, and
verifies it with the checked-in Solana verifier.

```sh
FORESTER_TEST_KEYS_DIR=/path/to/keys cargo test -p zolana-forester-prover \
  --test local_batch_proof -- --ignored
```
