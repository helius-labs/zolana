# zk

The generic zero-knowledge crates: a circuit DSL over BN254 with its Groth16 prover, and the
gadgets built on it. Nothing here knows the zolana protocol. `zolana-program` builds the
protocol on these crates and re-exports them, so a ZK program depends on `zolana-program`
alone.

| Crate | Holds |
| --- | --- |
| [`dsl`](dsl) (`zolana-zk-dsl`) | Circuit values and operations, the `Circuit` and `CircuitType` traits, the sealed `CircuitOutput` with `PublicHashOutput`, proof input conversion, errors, the prover and key handling, `CompressedProof`. |
| [`gadgets`](gadgets) (`zolana-zk-gadgets`) | `poseidon`, `nonzero_hash_chain`, `is_in`/`assert_in`, `one_hot`/`select_index`, `HashBytes`. |
| [`macros`](macros) (`zolana-zk-macros`) | `#[derive(CircuitType)]`, `#[derive(ProofInput)]`, `#[derive(ErrorName)]`. |
| [`macros-core`](macros-core) (`zolana-zk-macros-core`) | The expansion logic these derives share with `zolana-macros`. |
| [`test-harness`](test-harness) | The unit-test harness (circom, snarkjs, Picus, digests), included by path into each test crate. |
| [`tests/standalone`](tests/standalone) | A circuit on the DSL and gadgets alone, without `zolana-program`. |

## Rules

- A zk crate depends on no zolana crate except another `zolana-zk-*` crate and
  `zolana-hasher`. No crate depends on both `zolana-program` and a zk crate: a ZK program uses
  the `zolana-program` re-exports, a standalone circuit the zk crates. `just check-deps`
  enforces both.
- The derives generate paths under `::zolana_program`. A crate that uses the DSL without
  `zolana-program` names it so in its root: `extern crate zolana_zk_dsl as zolana_program;`.
- Every gadget and DSL operation has an R1CS digest pinned in its crate's `fingerprints`
  test. A changed digest changes every proving key built on the operation; re-derive and
  re-pin it deliberately.
- `just test-zk` and `just check-zk` run these crates alone.
