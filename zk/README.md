# zk

The generic zero-knowledge crates: a circuit DSL over BN254 with its Groth16 prover, and the
gadgets built on it. Nothing here knows the zolana protocol. `zolana-program` builds the
protocol on these crates and re-exports them, so a ZK program depends on `zolana-program`
alone.

| Crate | Holds |
| --- | --- |
| [`dsl`](dsl) (`zolana-zk-dsl`) | Circuit values and operations, the `Circuit` and `CircuitType` traits, the sealed `CircuitOutput` with `PublicHashOutput` and `Public`, proof input conversion, the public input layout, errors, the prover and key handling, `CompressedProof`. Feature `verifier`: the no_std on-chain verifier. Feature `wasm` (and `wasm-prover`, `wasm-threads`, `wasm-verify`): the wasm runtime. Feature `build`: the circuit crate build `zolana zk` runs. |
| [`gadgets`](gadgets) (`zolana-zk-gadgets`) | `poseidon`, `nonzero_hash_chain`, `is_in`/`assert_in`, `one_hot`/`select_index`, `HashBytes`. |
| [`macros`](macros) (`zolana-zk-macros`) | `#[derive(CircuitType)]`, `#[derive(ProofInput)]`, `#[derive(PublicInputs)]`, `#[derive(ZkCircuit)]`, `#[derive(ErrorName)]`. |
| [`macros-core`](macros-core) (`zolana-zk-macros-core`) | The expansion logic these derives share with `zolana-macros`. |
| [`test-harness`](test-harness) | The unit-test harness (circom, snarkjs, Picus, digests), included by path into each test crate. |
| [`tests/standalone`](tests/standalone) | Circuits on the DSL and gadgets alone, without `zolana-program`, and the Solana program verifying them. |

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
- `just test-zk` and `just check-zk` run these crates alone. `just test-zk-wasm` proves the
  standalone fixture in Node through its wasm package, and `just test-zk-standalone-program`
  verifies its proof in its SBF program in litesvm (`sdk-tests/zk-tests`).

## Standalone circuits

A circuit with public inputs is a struct with exactly the fields `private` and `public` that
derives `ZkCircuit`. The public struct derives `PublicInputs`, and the circuit returns
`Public` of it:

```rust
extern crate zolana_zk_dsl as zolana_program;

#[derive(Clone, Copy, Debug, PublicInputs)]
pub struct Payout {
    pub commitment: Field,
    pub amount: u64,
    pub destination: Address,
}

#[derive(Clone, Copy, Debug, ZkCircuit)]
pub struct Withdrawal {
    pub private: Note,
    pub public: Payout,
}

impl Circuit for WithdrawalCircuit {
    type Output = Public<PayoutCircuit>;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        // constrain the private inputs against the public ones
        Ok(Public(self.public.clone()))
    }
}
```

Each public field is bound directly as Groth16 public inputs, in declaration order, with no
hashing: integers, bools and 32-byte field values (`Field`, `[u8; 32]` below the modulus) take
one input each, `Bytes<N>` and `Address` pack into 31-byte big-endian chunks
(`zolana_hasher::primitives::pack_be`), arrays list their items. Every public input adds a
scalar multiplication to on-chain verification; hash many values into one with the gadgets'
`poseidon` instead. A ZK program (`zolana-program`) binds exactly one public input, the
Poseidon hash of its public fields and its private transaction hash.

The build is `zolana_zk_dsl::build`, which `zolana zk compile` and
`zolana build-zk-program` run: it exports each circuit's r1cs through the hook `ZkCircuit`
emits (feature `r1cs-export` of the crate, forwarding the DSL's), writes test keys, and
generates `src/verifier/<circuit>.rs` with the circuit's on-chain `PublicInputs`, their
encoding and `verify`, plus `<circuit>.vk.rs`. The SBF program links only the DSL's
`verifier` feature and those modules. The wasm package exports `<circuit>ProofInputs`, which
builds proof inputs from the circuit's typed inputs, and the `<Circuit>Prover` class, whose
`prove` returns `{ proof, compressedProof, publicInputs }`. `tests/standalone` is a complete
example.
