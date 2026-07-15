# ZK Program Example Layout

An example ZK program is a small Solana program that verifies a Groth16 proof
of its rules and CPIs SPP `transact`; it stores no state and owns no accounts.
Each example has a design doc as its source of truth for the privacy model,
instructions, and circuits.

## What Goes Where

- `program`: the Pinocchio program. Instruction processors, proof
  verification, verifying-key constants, instruction data, tags, errors, and
  the canonical public-input hashing. No separate interface crate; the sdk
  re-exports from here.
- `prover`: in-process proving engine. Go gnark circuits, ffi bindings, proof
  input struct definitions for the prover, circuit constants, and the
  key-generation binary. Takes prepared proof inputs and proves; hashing and
  domain logic belong in the sdk.
- `sdk`: client library. State definitions, instruction data builders, proof
  input builders, utxo data definitions and hashing, discovery, encryption
  codecs, and the prover client. Owns all transformation between domain types
  and proof inputs. Per-circuit prove/verify tests live here.
- `test`: localnet end-to-end tests and CU benchmarks.

## Patterns

- program: one file per instruction under `src/instructions/`; each verifies
  its proof against the public-input hash, then CPIs SPP `transact` with the
  program authority PDA flipped to a signer. Public-input hash impls live next
  to the instruction and are reused by the sdk. Host-side unit tests
  (error-code stability, boundary checks) in `tests/`.
- prover: `build.rs` compiles the Go package to a c-archive, exposed as
  `setup` / `preload` / `prove` over bindgen. Proof input structs are pure
  containers whose only logic is witness-map encoding and a `prove()` method.
- sdk: one directory per instruction with `instruction.rs` (builder struct
  with a consuming `instruction()` method, not free functions) and
  `proof.rs` (a params struct with `to_proof_inputs()` doing validation and
  hashing); `mod.rs` only re-exports. Shared helpers in `shared.rs`. The
  prover client mirrors `zolana_client::ProverClient`: one `prove_*` method
  per circuit, no data processing.
- test: cucumber end-to-end flows against localnet + photon + prover; mollusk
  CU profiling that regenerates the benchmark doc.

## Dependencies

- program: `pinocchio` (+`cpi`), `zolana-interface`, `zolana-account-checks`,
  `zolana-hasher` (+`poseidon`), `groth16-solana` (+`bsb22`) for verification,
  `wincode`/`borsh` for instruction data, `thiserror` +
  `solana-program-error` for errors. Never sdk crates.
- prover: `groth16-solana` (+`bsb22`) and `solana-bn254` for proof types,
  `zolana-transaction` for proof input slots, the program crate for shared
  types.
- sdk: `zolana-client`, `zolana-keypair`, `zolana-transaction`,
  `solana-instruction`/`solana-address` for wire types, plus the program and
  prover crates.
- test: `zolana-program-test` + `zolana-test-utils` for the harness,
  `zolana-client` (+`indexer-api`, `solana-rpc`), `cucumber`, `mollusk-svm` +
  `light-program-profiler` for benchmarks.

## Key Artifacts

- `build/gnark/<circuit>/{pk,vk}.bin`: generated proving/verifying keys,
  pinned by checksum.
- `program/src/verifying_keys/`: committed Rust vk constants; must match the
  generated keys.
