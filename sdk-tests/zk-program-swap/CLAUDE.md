# ZK Program Swap Example

An SPP ZK program: a confidential swap between a maker and a designated taker.
The program verifies a small Groth16 proof of the swap rules and CPIs SPP
`transact` for the confidential transfer; it stores no state and owns no
accounts.

`swap_program.md` is the source of truth for the privacy model, order terms,
instructions, and circuits. `BENCHMARK.md` holds CU and proving-time numbers
(regenerate with `just bench-swap`).

## Crates

### `program` (`swap-program`)

The on-chain Pinocchio program.

- Four instructions, one file each under `src/instructions/`: `create_swap`,
  `fill`, `fill_verifiable_encryption`, `cancel`.
- Each instruction verifies its Groth16 proof (constants in
  `src/verifying_keys/`) against `private_tx_hash`, then CPIs SPP `transact`
  with the escrow-authority PDA flipped to a signer.
- Owns the instruction data structs, proof types, tags, and errors; there is no
  separate interface crate, the sdk re-exports from here.
- The per-instruction modules hold the canonical public-input hash
  implementations (`FillPublicInput::hash()`, `CancelPublicInput::hash()`, ...);
  the sdk reuses them when assembling proof inputs.
- `tests/`: host-side unit tests (error-code stability, fill/cancel window
  boundaries).

### `prover` (`swap-prover`)

In-process proving engine for the swap circuits; no prover server. Mirrors the
main prover server's role: it does not process data — it takes prepared
witnesses and proves.

- Go gnark circuits in `circuits/` (`create`, `fill`,
  `fill_verifiable_encryption`, `cancel`).
- `build.rs` compiles the Go package to a c-archive; `src/ffi.rs` exposes
  `setup` / `preload` / `prove` over bindgen.
- Per-circuit `*ProofInputs` structs are pure field-element containers
  (`OrderTermsProofInput`, `zolana_transaction::ProofInputUtxo` slots,
  precomputed hashes); their only logic is witness-map encoding and
  `prove() -> OrderProof`.
- No hashing or domain logic lives here; all transformation is in the sdk. The
  crate exports the circuit constants (`FILL_MODE_*`, KDF/blinding domains).
- `swap-prover-setup` bin regenerates proving/verifying keys and the Rust vk
  constants in the program crate.
- The per-circuit proof tests live in `sdk/tests/`.

### `sdk` (`swap-sdk`)

Client library for building and discovering swaps; owns all data
transformation between domain types and prover witnesses.

- `instructions/`: one directory per instruction, each with a private
  `instruction.rs` (builder struct + account/wire assembly) and `proof.rs`
  (`*ProofInputParams::to_proof_inputs()`: payout validation, `ProofInputUtxo`
  slots from the canonical `TryFrom` conversions, `private_tx_hash`, and the
  public input hash via the program's `*PublicInput::hash()`); the module's
  `mod.rs` only `pub use`s the public items. `fill/` also owns
  `derive_destination_blinding`; `fill_verifiable_encryption/encryption.rs`
  owns the verifiable-encryption ciphertext codec.
- `state/order.rs`: the client-side order state — `OrderTerms` (with its
  `OrderTermsProofInput` conversion and `DataHash` impls), the `PlainTextData`
  note payload, and the escrow `OrderUtxo` (output and spend forms). Impl
  blocks are grouped and commented by the instructions that use them.
- `shared.rs`: helpers shared across the instruction modules and tests
  (`input_sum`, `check_output_utxo`, `to_blinding_array`).
- `discover.rs`: taker-side order discovery — wallet sync, marker decoding,
  maker resolution via the user registry, escrow opening recovery.
- `prover.rs`: `SwapProverClient`, mirroring `zolana_client::ProverClient` —
  one `prove_*(&*ProofInputs) -> OrderProof` per circuit, no data processing.
  The SPP transfer proof comes from `ProverClient::prove_transact` directly.
- `tests/`: per-circuit prove/verify tests against the generated and program
  verifying keys, including program-side public-input recomputation;
  `tests/shared/` holds test-only helpers (`escrow_owner_hash`).

### `test` (`swap-test-validator`)

Localnet integration tests and benchmarks.

- `tests/swap.rs`, `tests/cancel.rs`: cucumber end-to-end flows
  (create -> discover -> fill / cancel) against localnet + photon + prover.
- `tests/bench_cu.rs`: mollusk CU profiling that regenerates `BENCHMARK.md`.
- `tests/shared.rs`: common environment setup.

## Key Artifacts

- `build/gnark/<circuit>/{pk,vk}.bin`: proving/verifying keys, produced by
  `swap-prover-setup`; pinned by `swap-keys.CHECKSUM`.
- `program/src/verifying_keys/`: committed Rust vk constants; regenerate with
  the keys, they must match.
