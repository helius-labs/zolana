# zolana-program

The SDK for Solana programs built on the shielded pool (SPP). It has three parts:

- **Instructions.** The crate re-exports [`zolana-instruction`](../instruction): the SPP
  instruction builders, the `transact` CPI (feature `cpi`), and the SPP derivations a Solana
  program recomputes. Without features the crate is `no_std` and builds for SBF.
- **Compressed accounts.** `compression` keeps a pinocchio program's state as SPP UTXOs that
  one of its PDAs owns, and creates, updates and reads them through a `transact` CPI.
- **ZK programs.** A program with its own Groth16 circuit, whose proof shares `private_tx_hash`
  with the SPP transaction it CPIs. A `circuit` fn written in the DSL of `zolana_program::circuit` runs
  twice:
  - natively on the client, where it builds the SPP transaction's inputs and outputs;
  - as R1CS in the prover, where it checks the constraints and the public hash.

  The circuits are arkworks 0.6 R1CS over BN254. The DSL, the prover and the core derives
  come from [`zolana-zk-dsl`](https://github.com/helius-labs/zk-tools/tree/f4807e0be04e92d7111f198a49ad994e367bd70b/zk-dsl/dsl), the gadgets from
  [`zolana-zk-gadgets`](https://github.com/helius-labs/zk-tools/tree/f4807e0be04e92d7111f198a49ad994e367bd70b/zk-dsl/gadgets), and the UTXO derives from
  [`zolana-macros`](../macros). This crate re-exports all of them at the paths below.

The ZK program part implements [`docs.md`](docs.md); [`tests/invariants/`](tests/invariants) states what
each protocol type guarantees and which tests cover it. The builtins' invariants live with the
DSL in [`zk-dsl/dsl/tests/invariants`](https://github.com/helius-labs/zk-tools/tree/f4807e0be04e92d7111f198a49ad994e367bd70b/zk-dsl/dsl/tests/invariants) and
[`zk-dsl/gadgets/invariants`](https://github.com/helius-labs/zk-tools/tree/f4807e0be04e92d7111f198a49ad994e367bd70b/zk-dsl/gadgets/invariants).

A developer writes plain Rust input types, and the client, the tests and the prover all take
them. `CircuitVar` appears only in the `circuit` impls.

## Features

No feature is on by default.

| Feature | Contents |
| --- | --- |
| none | `no_std`: the `zolana-instruction` re-export and `CompressedProof`. |
| `cpi` | The SPP `transact` instruction as a signed CPI from a pinocchio program. |
| `compression` | Compressed accounts for pinocchio programs (implies `cpi`). |
| `protocol-instructions` | Builders for protocol operations: authority administration, tree creation, ring activation and nullifier tree maintenance. |
| `circuit` | The DSL, `conversion`, `hasher`, the input and UTXO types, `ConfidentialTransaction` and R1CS synthesis. Needs `std`. |
| `client` | The native run, the SPP transaction, loading proving keys, proving, verifying and transaction encryption. |
| `setup` | Includes `client`; adds test setup, writing proving keys and exporting the verifying key. |
| `r1cs-export` | `client` and `setup`, for exporting a circuit's `.r1cs` and its verifier module. |
| `verifier` | `no_std`: `VerifyError`, `public_hash` and `verify_groth16`, which the generated verifier modules call with a `CompressedProof`. `client` includes it. |
| `parallel` | Proving on a rayon thread pool. |
| `serde`, `tsify` | Serde and TypeScript types for the client types. |
| `wasm` | JavaScript transaction and state-decoding bindings. |
| `wasm-prover`, `wasm-threads` | Include Xark's proving runtime in the application's WASM module. JavaScript workers each load their own instance. |
| `wasm-verify` | Proof and verifying-key conversion helpers for independent verification with snarkjs. |
| `test-support` | Circuit diagnostics and internal inspection for SDK tests. |
| `external-tools` | Test only: the unit suite's cross-checks that spawn circom and snarkjs. |

A Solana program depends on the crate with `compression` or `cpi`, and with `verifier` when it
verifies ZK program proofs. Its client enables `client`, and a key setup needs `setup` as well.

## Building a ZK program

1. Declare each instruction's inputs as a struct with exactly the fields `private` and
   `public` and `#[derive(ZkProgramCircuit)]`, its private inputs with `#[derive(ProofInput)]`, a
   program state with `#[derive(UtxoState)]`, and the public inputs with
   `#[derive(PublicInputs)]`. `#[derive(CircuitType)]` declares a plain circuit type that is
   not stored in a UTXO.
2. Implement `Circuit` on the derived circuit type.
3. `zolana build-zk-program -p <crate>` writes each circuit's `.r1cs` and test keys to
   `<target>/zk/<crate>`, the verifier modules to `src/verifier/`, builds the wasm module and
   runs `cargo build-sbf`. `zolana zk compile | setup | import | export-verifier` run the steps
   one at a time.
4. `src/verifier/` is committed. It holds `mod.rs` and, per program, `<program>.rs` with its
   `PublicInputs`, their `hash`, and a `Verifier` with a `verify` method, and `<program>.vk.rs` with the verifying key. The
   export build enables the crate's `r1cs-export` feature, declared as
   `r1cs-export = ["zolana-program/r1cs-export"]`, and the crate gates `pub mod verifier;` and
   the code that uses it with `#[cfg(not(feature = "r1cs-export"))]`, so the export compiles
   without the generated files. A program in the same crate calls
   `crate::verifier::<program>::Verifier { ... }.verify()`, another crate
   `<circuits crate>::verifier::<program>::Verifier { ... }.verify()`.
   `--check` regenerates the modules without writing them and fails when the committed files
   differ, for CI.
5. On the client, `create_program_transaction` builds the SPP transaction and the proof
   inputs, and `Groth16Prover::prove` proves them.

## Layout

The ZK program part spans several crates. The generic pieces live in `helius-labs/zk-tools` under `zk-dsl/` and know
nothing of the protocol; this crate holds the protocol and re-exports everything:

| Crate | Holds |
| --- | --- |
| [`zolana-zk-dsl`](https://github.com/helius-labs/zk-tools/tree/f4807e0be04e92d7111f198a49ad994e367bd70b/zk-dsl/dsl) | The builtins (`CircuitVar`, `Bool`, `Uint`, `Bytes`, `Assert`, `Select`), the `Circuit` and `CircuitType` traits, `ProofInput`, `FromCircuit`, `Allocator`, `Records`, the errors, `ZkCircuit`, `CompressedProof`, and the prover: `Groth16Prover`, the Groth16 types, zkeys and the R1CS synthesis. |
| [`zolana-zk-gadgets`](https://github.com/helius-labs/zk-tools/tree/f4807e0be04e92d7111f198a49ad994e367bd70b/zk-dsl/gadgets) | `poseidon`, `nonzero_hash_chain`, `is_in`/`assert_in`, `one_hot`/`select_index`, `HashBytes`. |
| `zolana-keypair` (feature `circuit`) | The owner circuit types and how a `ShieldedAddress` enters a circuit. |
| `zolana-transaction` (feature `circuit`) | The asset and UTXO circuit types and how a `Mint` and a `WalletUtxo` enter a circuit. |

In this crate, modules are grouped by the phase that uses them:

| Module | Phase |
| --- | --- |
| `circuit/` | The DSL a `circuit` fn is written in, re-exported, plus `protocol/`: the UTXOs built on the circuit types and the transaction. |
| `conversion/` | Between client and circuit values: the re-exported conversion traits and the `TxContext` conversion. |
| `client/` | The plain Rust side: `TxContext`, `ProgramOwner`, `DataUtxo`, and with feature `client`, `ZkProgramCircuit` and `ProgramTransaction`. |
| `hasher/` | The data hashes and discriminators that Solana programs and circuits share. |
| `program/` | Compressed accounts for pinocchio programs. |
| `wasm/` | The wasm bindings. |

The public paths follow the same split. The crate root holds what the client and the prover
use, `zolana_program::circuit` the DSL, and `zolana_program::conversion` what lies between.

## Abstractions

### `zolana_program`: client and prover

| Name | What it is good for |
| --- | --- |
| `TxContext` | The transaction settings: the blinding seed, from the OS RNG in `new`, and the output tree, `None` by default, which follows the first spent input's `latest_tree_id` and is an error when that input has none, or `Some(tree)`. The first nullifier comes from the first spent input and the sender from the keys. |
| `UtxoOwner` | An owner preimage: the tag (`S`, for Ed25519 and PDA keys), the key bytes and the nullifier key. From a `ShieldedAddress`, or a signing key and nullifier key. |
| `Bytes<N>` | A byte string the circuit sees byte by byte. |
| `ProgramOwner` | A program PDA as a UTXO owner: its public key, owner hash and `ShieldedAddress` under the fixed zero nullifier key. `input` turns an output the program's transaction created into a spendable `WalletUtxo`. `decrypt_data_utxos::<T>` decrypts the PDA's outputs in indexer transactions with a viewing key and keeps the data UTXOs whose hash commits a `T`, minus those the same transactions spend. |
| `DataUtxo<T>` | A decrypted UTXO and the program state its data holds. `TryFrom<WalletUtxo>` accepts ordinary `DATA` state or `UNIQ` state prefixed by its reserved address, checks the matching UTXO hash, and returns that address when present. |
| `ZkProgramCircuit` | Feature `client`. Implemented for every `ZkCircuit` input whose circuit has `Output = CheckedTransaction` and whose type is `'static`. `create_program_transaction` runs `circuit` natively, resolves the slots against the records and returns a `ProgramTransaction`. `create_finalized_transaction` returns only the SPP transaction. `create_proof_inputs_and_encrypt_with_keys` encrypts it with the sender's `ShieldedKeys` into `SppProofInputs`, after checking their `padding_independent_private_tx_hash` against the circuit's. `check_constraints`, `proof_inputs` and the exports come from `ZkCircuit`. |
| `ProgramTransaction` | Feature `client`. What `create_program_transaction` returns: the SPP `FinalizedTransaction`, the program's `ProofInputs` and the public hash, so one call feeds both proofs. |
| `ZkCircuit` | Feature `client`. Implemented for every input that implements `ProofInput` with a `Circuit` and `Placeholder`, whatever the circuit's `Output`. `check_constraints` runs the circuit natively and in R1CS without proving, and also synthesizes the placeholder the keys come from: it names a value read of a variable, a shape that differs from the placeholder's and the first constraint that does, and an unsatisfied row by its rule and line. `proof_inputs` returns the full variable assignment and `export_assignment` writes it as a snarkjs `.wtns` file. `export_r1cs` and `export_picus_r1cs` (feature `setup`) write the circuit's constraints in the iden3 `.r1cs` format for a snarkjs ceremony and in the Picus format. The public inputs follow the circuit's `Output`: none for `()`, the public hash for `CheckedTransaction`. `Groth16Prover` takes only a `ZkProgramCircuit`; snarkjs proves a `()` circuit from the exported files. |
| `Groth16Prover<P>` | Feature `client`. The Groth16 keys of program `P`. `new_with_test_setup` (feature `setup`) sets them up from `P`'s placeholder with a fixed seed, and `new` takes loaded keys and refuses keys of another circuit. Setup and proving both use the snarkjs QAP reduction, so keys from the local setup and from a zkey have the same shape. `prove` borrows the inputs and returns a `ProofResult`; `verify` checks one in its compressed form, as a program does. |
| `ProofResult` | Feature `client`. A proof and the public hash it is valid for. |
| `SolanaProof` | Feature `client`. A proof in the groth16-solana layout, from an arkworks `Proof`. |
| `CompressedProof` | No feature, so Solana programs and `compression` use it. The 128-byte form an instruction contains, with a wincode layout. Feature `client` adds `CompressedProof::try_from(&proof)` from a `SolanaProof` and `CompressedProof::verify`, which decompresses and verifies it. |
| `CircuitError` | What circuit code returns: a broken rule, a value out of range, a wrong length, a bounded `Vec` with too many or too few items (`TooManyItems`, `TooFewItems`, naming the field) or a bad owner or UTXO. `broken_rule()` names the rule and `location()` the `file:line:column` of the program's line that broke it. |
| `ClientError` | What building a transaction returns: a circuit error, a slot that does not resolve or a transaction the SPP builder refuses. |
| `ProverError` | What `check_constraints`, the keys and `Groth16Prover` return. The error of a failing constraint includes its row, the rule of the check that made it and the circuit's `file:line`, which `location()` returns. |
| `SourceLocation`, `SlotKind` | The `file:line:column` of an error, and the kind of slot a slot error names. |
| `ProvingKey`, `VerifyingKey`, `Proof` | Features `client` or `setup`. The arkworks Groth16 types over BN254, without the curve parameter. |

**Setup** (feature `setup`)

| Name | What it is good for |
| --- | --- |
| `Groth16Keys` | A proving key and its verifying key, from an arkworks `ProvingKey` or `Groth16Prover::keys`. `to_bytes` writes canonical arkworks key bytes; `load_checked` reads them against a trusted SHA-256 and validates the points. `load_zkey::<P>` (feature `client`) reads a snarkjs Groth16 zkey. It checks every point, refuses an identity in the verifying key and a zkey without a phase-2 contribution, and checks that the shape and the A and B rows match `P`'s circuit. `export_verifying_key` writes the program constant. |
| `VerifyingKeyExport` | Where `export_verifying_key` writes the `VERIFYINGKEY` constant: the output directory, filename and setup kind. The digest is computed from the key object. The file comes from groth16-solana's generator. Keys from the local setup are `InsecureTest`. Only a validated ceremony zkey import can be exported as `Production`; the digest pins its serialized key. |
| `SolanaVerifyingKey` | The verifying key in the groth16-solana layout, from an arkworks `VerifyingKey`. It converts into the `Groth16Verifyingkey` that `verify_groth16` takes. |

### `zolana_program::circuit`: the DSL

**Values and hashing**

| Name | What it is good for |
| --- | --- |
| `Field` | A native element of the BN254 scalar field that UTXO hashes and the public hash live in. It is a newtype over arkworks' `Fr`, with `From` for `u8` to `u128`, `bool` and `Fr`, `Fr::from(field)` back, and `+`, `-`, `*` and negation on native values. `is_zero`, `inverse`, `sqrt`, `pow` and `u64::try_from` / `u128::try_from` are available when preparing input values. |
| `CircuitVar` | The value type inside `circuit`: a `Field` value, a constant in the native run and a variable in R1CS. `+`, `-`, `*`, unary `-`, `+=`, `-=` and `*=` are field arithmetic that wraps around the modulus: a sum and a product by a constant are free, and a product of two variables costs one constraint. `inverse`, `div` and `pow` (by a constant exponent) are methods in the field; `inverse` and `div` refuse a zero divisor. `/`, `%`, `==` and `<` do not compile: the `/` and `%` errors point to `Uint::div_rem` and `CircuitVar::div`, and the `==` and `<` errors name the rules `UseAssertEqual` and `UseUintComparison`, for `assert_equal` or `is_equal` and the `Uint` comparisons. `CircuitVar::from` takes a `Bool` or a `Uint<BITS>`, and `Bool::try_from(&var)` and `Uint::try_from(&var)` check one back. `assert_product(other, product, rule)` constrains `self * other = product` in one row. |
| `CircuitSystem`, `ConstraintSystem` | The constraint system R1CS instantiation allocates into. `ConstraintSystem::new_ref()` makes one. |
| `constant`, `zero`, `value` | Build a constant `CircuitVar`, or read a constant's value. Native execution represents proof inputs as constants, so `value` can read them. In R1CS, proof inputs are variables: reading one fails with `ReadsVariableValue` at the read's source location during setup or proving. A successful native run alone does not establish that a circuit can be proved; use `check_constraints`. |
| `Assert` | Equality with a named rule on `CircuitVar`, `Uint<BITS>`, `Bool`, `Bytes<N>`, `SolanaAddress`, `SigningPubkey`, `UtxoOwner` and arrays: `assert_equal`, `assert_not_equal`, `assert_equal_if(condition)`, and `is_equal`, which returns a `Bool`. A zero check on a `CircuitVar` compares it with `zero()`: `is_equal(&zero())`, `assert_equal(&zero(), rule)` or `assert_not_equal(&zero(), rule)`. |
| `Uint<BITS>` | A value below `2^BITS`, 1 to 253 bits, with the aliases `U8`, `U16`, `U32`, `U64` and `U128`. `add`, `mul` and `sum` return a wider type at no cost. `From` widens between the aliases and turns a `Bool` into a `Uint`; `TryFrom` narrows between the aliases and range-checks a `CircuitVar` into a `Uint`. `checked_add`, `checked_mul`, `checked_sub`, the `assert_less_*` comparisons, `assert_in_range(low, high)` (inclusive), `assert_equal`, `assert_not_zero` and `div_rem` check a named rule; the `is_less_*` comparisons return a `Bool`, and `min` and `max` select by one. Range checks and comparisons decompose through arkworks' `to_bits_le_with_top_bits_zero`; ordering works on at most 252 bits, so a difference cannot wrap around the field. Widths are checked when the circuit is built: a sum or product that could wrap does not compile. |
| `CircuitVar` bit checks | `check_bits(bits)`, `check_is_bool`, and `to_bits_le::<N>()`, which returns the bits as `Bool`s. `from_bits_le` recomposes them. |
| `Bool` | A 0 or 1 value, from a `bool` input, `Bool::try_from(&var)`, `is_equal` or a comparison: `select(if_true, if_false)` for any `Select` type, `not`, `and`, `or`, `xor`, `nand`, `implies`, `Bool::all`, `Bool::any`, `assert_true`, `assert_false` and `assert_true_if(condition)`. `Uint::from(flag)` and `CircuitVar::from(flag)` turn one into a value, for arithmetic or hashing. A circuit needs no arkworks import to branch on one. |
| `Select` | Selection by a `Bool`, for `CircuitVar`, `Uint<BITS>`, `Bool`, `Bytes<N>`, `SolanaAddress`, `SigningPubkey`, `UtxoOwner` and arrays. `one_hot::<N>(index)` and `select_index(&items, index)` index an array by a variable and refuse an index outside it. |
| `is_in`, `assert_in` | Membership of a value in a set of `CircuitVar`s. |
| `poseidon` | The circom Poseidon that zolana hashes with natively, built from light-poseidon's parameters. |
| `nonzero_hash_chain` | The hash chain `private_tx_hash` computes over the input and output hashes. It skips zeros, so dummies do not enter it. |
| `Bytes<N>::hash_bytes()` | A fixed-width commitment over checked bytes: 31-byte big-endian chunks folded with Poseidon. Use one `N` per protocol hash domain; leading zeroes are valid. |
| `Bytes<N>` | `N` byte variables, each range-checked to 8 bits when allocated. `Bytes::<N>::try_from(&var)` splits a variable into big-endian bytes and `CircuitVar::try_from(&bytes)` packs them back, for `N` up to 31. |

**UTXOs**

| Name | What it is good for |
| --- | --- |
| `SolanaAddress` | A Solana address as 32 checked bytes, used for mints and public-transfer accounts. `hash_bytes()` uses SPP’s address encoding and shares its cached result across clones. `SolanaAddress::constant(&SOL_MINT)` creates the SOL asset address. |
| `SigningPubkey` | The tag and key bytes. `identity()` is `hash_bytes(tag \|\| key)`, the value the program sees as `owner_identity`. |
| `UtxoOwner` | An `SigningPubkey` and the nullifier key. `hash()` is the owner hash. Owners compare by their packed preimage. |
| `ShieldedAddressCircuit` | A distinct circuit value whose `hash()` includes both the owner hash and the viewing key. UTXO ownership uses its `UtxoOwner` projection. |
| `Utxo` | The circuit form of a spent UTXO, with its `UtxoOwner` and `SolanaAddress`. Its amount is crate-private: the SPP proof range-checks it, and a circuit reads it through `UtxoTrait`. `Utxo::dummy()` pads a `TokenUtxos`. A dummy's owner is unconstrained and never read: it adds no hash and no amount. |
| `UtxoMeta` | The spent UTXO's nullifier and latest tree, not part of the commitment; the SPP proof constrains them, and this circuit includes them. |
| `DataHash` | The hash of a state: Poseidon over its fields, each contributing its own `hash`. |
| `UtxoData` | Names a state's client form. The borsh bytes of that form are the data a new data UTXO contains. |
| `DataUtxo<S>` | The `LightAccount` counterpart: a UTXO with state `S`, from `new_init(owner)` or `new_mut`; `close()` suppresses its output; `with_asset` selects a non-SOL asset. It moves value through `UtxoTrait` like a token UTXO; what is left is its output, a real UTXO even at a zero balance because it contains state, or must be zero once closed. |
| `UniqueDataUtxo<S>` | A `DataUtxo` with an address the circuit derives from its owner, so one address holds the state. `new_init` reserves the address, `new_mut` spends and replaces the state, `close()` leaves an address tombstone and `burn()` leaves nothing. The last of these builders selects the final output mode. The client includes the address input and places the address before the Borsh state in the output data. |
| `TokenUtxos` | Plain UTXOs of one owner and asset: none from `new_init(owner, asset)`, or `N` slots from `new_mut`, with any slot allowed to be a dummy. It moves value through `UtxoTrait`, and its lifecycle decides whether what is left becomes an output. An output whose balance is zero at proof time, and that only empty outputs follow, is an empty UTXO: it keeps its slot and derived blinding, enters `private_tx_hash` as 0, and leaves no zero-amount UTXO. Dummies must come after every real output, so add change that may reach zero last. The circuit decides this from the balances, so a prover cannot choose it. `close()` asserts that nothing is left and takes no slot. `with_optional(owner, asset)` allows zero real inputs and checks real inputs against the supplied owner and asset. Configure it before balance operations. Without it, registration requires a real input. |
| `UtxoTrait` | The value operations the UTXO types share: `owner`, `asset`, `amount`, `transfer` and `transfer_all` into a destination UTXO of any type, `deposit`, `withdraw` and `withdraw_all`. Amounts are `Uint<64>`. A transfer refuses a closed destination and constrains the destination to hold the source's asset, at no cost when the destination was built from the source's `asset()`. `transfer` and `withdraw` check that what remains fits in 64 bits: a named error natively, a range check in R1CS. A public transfer of zero is refused by a constraint. `amount` is a `Uint<64>`, range-checked only when the balance could exceed 64 bits, as for a token with several inputs. They are default methods over a crate-private `Balance`. |

**Transaction and circuit**

| Name | What it is good for |
| --- | --- |
| `TxContext` | The transaction settings in circuit form, the output tree as a `Uint<16>`. `check` derives the output blindings and `private_tx_blinding` from them and the first spent input's nullifier, and selects the output tree. |
| `PublicInputs` | Hashes a circuit's public fields, then the transfer-aware `transaction_hash`, into the public hash. The generated verifier derives it from the SPP private hash and the actual public transfers. |
| `ConfidentialTransaction<P>` | The transaction's inputs and outputs registered with `with(item)`, with no SPP shape. `TransactionItem` registers token UTXOs, typed or raw-hash state UTXOs, unique state UTXOs, and `NewAddress` reservations. Inputs are stably ordered with real inputs before dummies; outputs retain registration order. Padding is compact by default; `with_dummy_padding()` preserves dummy input slots and publishes dummy padding. `check` refuses value that a transfer moved into or out of a UTXO the transaction does not contain, blinds and hashes the outputs, a trailing `TokenUtxos` output of zero as an empty UTXO, and computes `private_tx_hash` and the public hash. The client places each empty output in its slot with `zolana_transaction`'s `add_empty_output_utxo`. |
| `CheckedTransaction` | What `check` returns: the public hash, `private_tx_hash` and the slots. |
| `Circuit` | Defines `type Output: CircuitOutput` and `fn circuit(&self) -> Result<Self::Output, CircuitError>`. Used for both standalone constraints and transaction programs. |
| `CircuitOutput` | Sealed output contract. `()` adds no public inputs; a `PublicHashOutput`, such as `CheckedTransaction`, binds its public hash to one public input. The SDK owns the allocation and equality constraints for these outputs. |

**Diagnostics**

| Name | What it is good for |
| --- | --- |
| `CircuitLabel`, `LabelKind`, `VariableRole` | What a synthesis records: the rows of each check and scope and the private variables of each allocation, with the rule and the circuit's `file:line`. |
| `FailedConstraint` | The first failing row and its innermost label. |
| `CircuitSize` | Constraints and public and private variables, for comparing a proof's synthesis with the placeholder's. |

### `zolana_program::testing` (feature `test-support`)

| Name | What it is good for |
| --- | --- |
| `constraint_labels` | The labels of a proof input's synthesis. |
| `check_tampered`, `Tamper` | Changes the public hash or one private variable and reports the labelled row that refuses it. A circuit returning `()` has no public hash, so `Tamper::PublicHash` on that circuit is `WrongPublicInputCount`. |
| `check_private_variables`, `PrivateVariableReport`, `FreeVariable` | Perturbs each private variable in turn and lists the ones no constraint refuses. A free variable is an under-constrained circuit, except equality hints (`Multiplier`) and the unused inputs' nullifier and latest tree, which the SPP proof constrains (`Carried`). The scenario suites run it on every proof. |

### Writing a gadget

A gadget is an ordinary function over declared `CircuitVar` inputs or typed
builtins such as `U32` and `U64`. Use `#[track_caller]` for caller locations.
Arithmetic and assertions generate constraints directly. Linear combinations and
`assert_product` can express any R1CS row.

The caller computes any additional values, declares them in its `ProofInput`,
and passes their circuit variables to the gadget. For example, a field square
root is supplied as an input and constrained by its square:

```rust
use zolana_program::{circuit::CircuitVar, CircuitError};

#[track_caller]
fn assert_square_root(
    value: &CircuitVar,
    root: &CircuitVar,
) -> Result<(), CircuitError> {
    root.assert_product(root, value, "root squared equals value")
}
```

Existing operations allocate their own intermediate values.
External gadgets build on those operations and add the required equations,
range checks and bounds over their inputs. Native computation by the caller
is not a constraint on the supplied values.

Test gadgets as standalone `ZkCircuit`s with `check_constraints` and
`check_private_variables`. Test incorrect supplied values directly in R1CS too:
instantiate with `Allocator::R1cs`, generate the gadget's constraints and check
`ConstraintSystem::is_satisfied`. This avoids mistaking native rejection for
constraint rejection. [`tests/external_gadget`](tests/external_gadget)
contains integer and field square roots, arbitrary linear combinations, and a
program that proves and verifies with Groth16 using a declared root input.

### Implementing a derived circuit

`#[derive(ProofInput)]` generates the circuit form of a client type, and
`#[derive(ZkProgramCircuit)]` does the same for a program's inputs and adds its wasm bindings and r1cs
export hook. Implement `Circuit` on the associated type with ordinary Rust:

```rust,ignore
impl Circuit for <Transfer as ProofInput>::Circuit {
    type Output = CheckedTransaction;

    fn circuit(&self) -> Result<Self::Output, CircuitError> {
        // Build and check the transaction using self's circuit fields.
    }
}
```

`ZkProgramCircuit` requires `ProofInput<Circuit: Circuit> + Placeholder`, so its associated
type must implement `Circuit`. Input fields and state types only need `CircuitType`.
Use the generated name for inherent impls (`impl TransferCircuit`) and for generic
impls such as `impl<const N: usize> Circuit for TransferCircuit<N>`.

A circuit spends a fixed number of UTXOs, but a client rarely holds exactly that many. A
`Vec` field takes the UTXOs the client has, up to a bound the input type sets:

```rust,ignore
#[derive(Clone, ProofInput)]
pub struct Transfer {
    pub tx_context: TxContext,
    #[max_len(MAX_INPUTS)]
    pub token_utxos: Vec<WalletUtxo>,
    pub amount: u64,
}
```

- `#[max_len(N)]` is required on every `Vec` field and `#[min_len(M)]` is optional, with a
  default of 1, since a `TokenUtxos` normally requires a real input. `#[min_len(0)]` allows an
  empty `Vec`; use `TokenUtxos::new_mut(...).with_optional(owner, asset)` to allow all its converted slots to be dummies. `M <= N` is checked when the program
  compiles.
- The circuit field is `[T::Circuit; N]`, so `TokenUtxos::new_mut(&self.token_utxos)` is
  unchanged. Instantiating fills the unused slots with `Dummy::dummy(first)`: dummies in the
  first UTXO's tree, or in tree 0 when the `Vec` is empty. A dummy's tree enters only its
  own hash, which a `TokenUtxos` replaces with zero. The placeholder fills all `N` slots, so
  the circuit and its keys are those of a `[WalletUtxo; N]` field.
- More than `N` or fewer than `M` items is a `TooManyItems` or `TooFewItems` error that
  names the field.
- The item type implements `Dummy`; today that is `WalletUtxo`. A padded `u64` has no
  empty marker, so `Vec<u64>` does not compile.
- `UtxoState`, `CircuitType` and `PublicInputs` refuse bounded fields: a state and a public
  input have a fixed layout.

Set `#![deny(unused_must_use, unused_variables, unused_assignments)]`,
`#![forbid(unsafe_code)]`, and `#![deny(clippy::let_underscore_must_use)]` on circuit
crates or modules. Use `#[deny(clippy::disallowed_types)]` on circuit impls and
gadgets to apply the collection restrictions in [`clippy.toml`](clippy.toml).

### `zolana_program::conversion`: between the two

Everything the derives generate goes through these, and each can be written by hand.

| Name | What it is good for |
| --- | --- |
| `ProofInput` | Turns a client value into its circuit type. Plain Rust types implement it: `u128`, `u64`, `u32` and `u16` become range-checked `Uint` values; `bool`, `[u8; 32]`, `Bytes<N>`, `UtxoOwner`, `ShieldedAddress`, `Mint`, `WalletUtxo`, and arrays. `Field` is an unchecked private value. A derived struct's bounded `Vec` field becomes an array of its `#[max_len]`. |
| `FromCircuit` | The way back in the native run, with the same range checks: `u64`, `u32`, `u16`, `bool`, `[u8; 32]`, `Bytes<N>`, `UtxoOwner`, arrays, and a state's client form. |
| `Placeholder` | A value of the type that instantiates, so setup synthesizes the circuit from the type alone. The SDK types above implement it; a program implements it field by field. |
| `Dummy` | An item that fills an unused slot of a bounded `Vec`, built from the first item, or from nothing when the `Vec` is empty. `WalletUtxo` implements it with `WalletUtxo::dummy_with_blinding`: a zero blinding in the first UTXO's tree, or tree 0, so the proof inputs depend only on the real items. The padding never reaches the SPP proof, which pads with its own random dummies. |
| `instantiate_padded`, `placeholders` | What the derive calls for a bounded `Vec` field, for a hand-written `ProofInput`: `instantiate_padded::<T, MIN, MAX>(items, field, allocator)` checks the length, pads with dummies and instantiates `[T::Circuit; MAX]`, and `placeholders::<T, MAX>()` builds the field's placeholder. |
| `Allocator` | Chooses the run. `Native` keeps constants and fills `Records`, and `R1cs` allocates variables, each labelled with what it is. Allocation stays inside the SDK: a hand-written `ProofInput` builds on the SDK's implementations. |
| `Records` | What a `CircuitVar` cannot hold, keyed by hash: addresses, `Mint`s and spent UTXOs. |
| `field`, `field_bytes`, `to_bytes` | SDK bytes to circuit values and back. |

### `zolana_program::hasher` (feature `circuit`)

| Name | What it is good for |
| --- | --- |
| `DataHasher` | The hash of a state that its data UTXO commits to. `#[derive(UtxoState)]` implements it to match the circuit's `DataHash`. |
| `Discriminator`, `state_discriminator` | An 8-byte state type tag: the first bytes of `sha256("account:" \|\| type_name)`. |
| `data_hash`, `unique_data_hash` | A data UTXO's data hash under the `DATA` and `UNIQ` domains: a state or an addressed state. |
| `ToByteArray` | A value as the 32 bytes a hash takes. |

`zolana_program::EncryptionCodec` (feature `circuit`) defines a state's encryption plaintext
and reconstructs the state after decryption. `UtxoState` generates a complete Borsh-backed
codec by default. Use `#[utxo_state(custom_codec)]` and implement the trait to encode a
smaller payload without changing ordinary Borsh serialization. The SDK checks that the
payload reconstructs the original commitment before accepting an output, and verifies
the UTXO commitment after decoding. Reconstruction uses only the payload; custom
decoders must reject malformed and trailing bytes. See the [encryption payload example](docs.md#utxo).

### `zolana_program::program` (feature `compression`)

A compressed account is a UTXO a program PDA owns whose data hash commits to the program's
plaintext state. The PDA's nullifier key is zero, so the program recomputes the UTXO hash
and the nullifier from the state instead of trusting instruction data.

| Name | What it is good for |
| --- | --- |
| `PdaOwner` | A program PDA as the owner of its accounts: its identity and owner hash under `ZERO_NULLIFIER_PUBKEY`. |
| `AddressSeed`, `NewAddress` | The address an account is created at, derived from the owner and a seed in an address tree. Only create derives it; update and read use its metadata. |
| `hasher::DataHasher` | The native state hash, including a type tag. State also implements Borsh serialization; address and blinding stay outside application state. |
| `UtxoMeta` | What a client sends about an account's current UTXO besides its state: the address, the blinding and the root indexes it is proven against. Wrong values give a UTXO hash or nullifier no proof matches. |
| `UniqueDataUtxo<S>` | A PDA-owned state UTXO with an immutable address and mutable application state. `new_init(owner, seed, tree_context)` derives and reserves the address; `new_mut` spends the current UTXO while preserving its address. `data_hash()` is `Poseidon(UNIQ, address, state.hash())`, matching the circuit type. |
| `SppTransactCpi` | Puts the accounts an instruction writes into one SPP transaction and invokes it, signed by the owning PDAs. It derives everything but the proof in the Solana program: the blindings, the output UTXO hashes, the external data hash and the private transaction hash. |
| `ReadRoots`, `load_tree_id` | Read an account without spending it: the program verifies its own proof of state-tree inclusion and nullifier-tree non-inclusion under the roots `ReadRoots::load` reads from the tree account, and `assert_unspent` checks that the nullifier PDA does not exist. |
| `UtxoKey` | A state UTXO's hash and zero-secret nullifier, reconstructed by `ReadRoots::key(owner, meta, state)`. The UTXO hashing helper is private. |
| `CompressedAccountError` | The errors, with their program error codes. |

`SppTransactCpi::with_unique_data_utxo` publishes `address || Borsh(state)` inside the
plaintext output envelope. Readers derive the UTXO blinding from the creating
transaction's first nullifier, `ACCOUNT_BLINDING_SEED`, and output position.
The blinding is UTXO metadata and is excluded from the application state hash.
Native state hashes and the default Borsh codec must match the circuit/client state.

The state's `DataHasher::hash` implementation selects Poseidon or SHA-256; both are
available without extra features. For SHA-256, `hasher::Sha256BE` clears the digest's
first byte so it fits the BN254 field. Include a type tag and all state fields in
either hash. States using different algorithms can share one transaction. The
`UtxoState` derive continues to generate Poseidon hashes for circuit states.

Rules a program keeps:

- Only a UTXO with a non-zero data hash is program state. Anyone can send a PDA a UTXO with
  a zero data hash; a non-zero one needs the owner's signature in the transact circuit, and
  only the program signs for its PDA.
- A program that signs with a state-owning PDA builds every output that PDA owns itself. It
  never signs transact data a client built.
- The state hash commits to its type tag; the SDK wraps it with `UNIQ` and the address.

### `zolana_program::wasm` (feature `wasm`)

`zolana zk compile` builds the existing program crate with wasm-pack. Its module
exports `ProgramTransaction`, `FinalizedTransaction` and `DataUtxo` TypeScript types,
a `<name>Transaction` function per program, and state-decoding helpers. The TypeScript
SDK's `decodeProgramTransaction` turns the returned transaction into SDK inputs and
outputs.

The default package directory is `<target>/zk/<package>/wasm/`. It contains the
generated JavaScript/WASM/declarations, `runtime-options.json`, `xark/` pool scripts,
and a `<circuit>/` directory of TypeScript client files per circuit. `--wasm-out`
selects a different package directory. The build stages this package together before
replacing the previous generation; circuit/key artifacts stay beside `wasm/`.

The default build enables `wasm-prover` and includes Xark's runtime in that module,
including `preloadStreaming`, `proveStreamingPreloaded` and `verify`. The build copies
Xark's pool scripts into `xark/`; pass the combined glue URL or Node.js glue path to
`createPool({ wasm })`. Browser proving with a pool runs inside a Web Worker and needs
cross-origin isolation. Each pool worker initializes a separate WASM instance using
the normal Rust toolchain.

When using a generated circuit client, pass the initialized application module
through Xark's existing `wasm` option so it does not load the stock prover module:

```ts
import init, * as runtime from "./wasm_test_program.js";
import { Escrow } from "./escrow/escrow";

await init();
const prover = await Escrow.prover("/circuits/escrow/", { wasm: runtime });
```

`--single-threaded` writes `threads: false` in `runtime-options.json` for loaders to
disable the pool. `--no-prover` builds the transaction/state bindings and also disables
the pool. `--verifier` adds `proofToSnarkjs` and `verifyingKeyToSnarkjs`; Xark's `verify`
is included with the proving runtime. `compressedProgramProof` remains available in
the transaction-only build.

This development branch uses workspace path dependencies pointing at
`/Users/jorrit/dev/experiments/xark-client-wasm`. The build discovers that checkout
from Cargo metadata and selects its `target/release/xark` compiler automatically.
Generated circuit entries use the same path dependency. To rebuild the local tool,
run `tools/xark/build.sh /Users/jorrit/dev/experiments/xark-client-wasm`.
`XARK` can select a separate compiler executable. Change the workspace dependency
paths to select a different source. The build uses those paths directly, without
Git bootstrapping, source overrides, or patch checks.

Verifier generation uses `groth16-solana 0.3.1` to emit
`VERIFYINGKEY_PROVING_KEY_SHA256`, `VERIFYINGKEY_INSECURE_TEST_SETUP`, and its standard
retained setup marker. `zolana vks` can inspect that marker in a program binary.
The hash covers the exact serialized `pk.bin` bytes; `ZOLANA_VK_SHA256` separately
identifies `vk.bin`.

Proving builds also write `proving-keys.json` beside the application module with
the same proving-key hashes and setup flags. Obtain the expected hash from trusted
application build output or an inspected program marker, then call
`checkProvingKey(keyBytes, new Uint8Array(expectedSha256))` before preloading or
transcoding a downloaded key. Missing or malformed hashes are rejected. Downloading
a checksum alongside an untrusted key does not provide a trusted expected value.
The setup classification comes from the trusted setup artifacts; a checksum alone
does not establish ceremony provenance. Transcoding changes file bytes, so check
the original download before deriving a different serialized cache format.

## Flow

```mermaid
stateDiagram-v2
    accTitle: How an instruction goes from its inputs to the program verifier
    accDescr: The client runs the circuit natively to build the SPP transaction. The prover runs the same circuit in R1CS against the public hash. The program verifies the compressed proof.

    state "Plain Rust inputs of one instruction" as Inputs
    state "Circuit type over constants, Records filled" as Native
    state "CheckedTransaction" as Checked
    state "ProgramTransaction" as Program
    state "Proven by the SPP prover" as SppProver
    state "Groth16Prover of the program, with its keys" as Prover
    state "Circuit type over variables" as R1cs
    state "ProofResult" as Proof
    state "Accepted by the generated verify" as Accepted
    state "Refused with a named CircuitError or ClientError" as Refused
    state "Refused, a constraint fails" as Unsatisfied

    [*] --> Inputs
    Inputs --> Native : create_program_transaction instantiates natively
    Native --> Checked : circuit, then check
    Checked --> Refused : a rule breaks or a slot does not resolve
    Checked --> Program : resolve slots, finalize with zolana_transaction
    Program --> SppProver : the finalized transaction, encrypted
    [*] --> Prover : new_with_test_setup from the placeholder, or new with loaded keys
    Program --> R1cs : the proof inputs
    Prover --> R1cs : the keys
    R1cs --> Unsatisfied : a constraint fails
    R1cs --> Proof : Groth16, checked against the keys
    Proof --> Accepted : compress, then verify on the public hash
    SppProver --> [*]
    Accepted --> [*]
    Refused --> [*]
    Unsatisfied --> [*]
```

*Figure 1: One set of inputs feeds both proofs.*

`create_program_transaction` instantiates the inputs natively, which runs the range checks and
fills the records. It then runs `circuit`, resolves each slot of the `CheckedTransaction`
against the records and converts the amounts. `zolana_transaction` finalizes the SPP
transaction, which pads to the smallest SPP shape that fits and is encrypted before the SPP
proof, and its `padding_independent_private_tx_hash` must equal the circuit's. A broken rule
or a slot without a record stops it with a named `CircuitError` or `ClientError`.

The proof inputs go to a `Groth16Prover` of the program. Its keys come from
`new_with_test_setup`, which synthesizes the circuit from the program's `Placeholder`, or from
`new` with loaded keys. Serialized keys include a digest of their circuit matrices, which `new`
checks against the current circuit before proving. `prove` proves and checks the proof against the keys. `verify` and the
program's generated `zk::<program>::verify` accept the compressed proof for that public hash.

```mermaid
stateDiagram-v2
    accTitle: The DataUtxo and TokenUtxos lifecycles
    accDescr: Both UTXO types start as Init or Mut; close selects no output. Init adds an output, Mut inputs and an output, Close only existing inputs. A closed UTXO transfers its value into other UTXOs and has no output.

    state "Init - no input, one output" as Init
    state "Mut - inputs in, the new state or change out" as Mut
    state "Close - inputs in, no output of its own" as Close
    state "Slots in the ConfidentialTransaction" as Slots

    [*] --> Init : new_init
    [*] --> Mut : new_mut
    Init --> Close : close
    Mut --> Close : close
    Init --> Slots : output
    Mut --> Slots : inputs and output
    Close --> Slots : inputs, its value transferred into other UTXOs
    Slots --> [*]
```

*Figure 2: The lifecycles shared by `DataUtxo` and `TokenUtxos`, the counterparts of `LightAccount`.*

A UTXO starts in `Init` or `Mut`; `close()` selects `Close`. `Init` adds only an output: the new state for a
`DataUtxo`, the value transferred into it for a `TokenUtxos`. `Mut` adds its inputs and that
output, the change for a `TokenUtxos`. A `TokenUtxos` output that ends at zero is an empty
UTXO in its slot. `Close` adds only its inputs, and its transfers must move out its whole
value. Every UTXO but a closed one can receive a transfer: an `Init` UTXO holds the asset it
was built with, the others their inputs' asset.

## Tests

```bash
just test-zolana-program-unit       # the unit suite
just test-zolana-program-release    # the scenario suites and the macro tests, in release
just test-zolana-program-external   # the unit suite with the circom, snarkjs and Picus checks
just check-wasm                     # the wasm32 builds
just test-zk-program-wasm           # the wasm module in Chromium
```

- `tests/unit` covers each builtin natively and in R1CS: Poseidon and `nonzero_hash_chain`
  parity, the integer and boolean rules, the plain input types, the records and
  `FromCircuit`, the lifecycles and the slot order, the transfer rules and the conservation
  check, `ZkProgramCircuit` resolution, dropped dummies, empty output padding, owner tags and errors,
  and the circuit verifier interface. Key checksum checks and export are covered by the CLI and browser regression tests.
- `tests/scenarios` proves and verifies whole programs, and runs `check_private_variables` on
  every proof.
- `tests/external_gadget` proves a program with a hand-written gadget.
- `tests/compression*` cover the compressed account CPI and the read.
- `tests/wasm` holds a test program and its Playwright suite, which prove in the browser and
  compare against the native fixtures and snarkjs (`just bench-zk-program-wasm` measures it).

## Keys for a deployment

`new_with_test_setup` and the keys `zolana build-zk-program` writes come from a single-party
setup with a fixed seed, for tests only. A deployment needs a ceremony and its exported
verifying key in the program. The ceremony runs on snarkjs over a published,
phase-2-prepared ptau:

```bash
zolana zk compile -p <crate> --skip-keys --skip-wasm --r1cs-out keys
snarkjs groth16 setup keys/<circuit>.r1cs powersOfTau28_hez_final_14.ptau keys/<circuit>_0000.zkey
snarkjs zkey contribute keys/<circuit>_0000.zkey keys/<circuit>_0001.zkey --name="contributor 1"
snarkjs zkey beacon keys/<circuit>_0001.zkey keys/<circuit>_final.zkey <beacon hex> 10 -n="final beacon"
snarkjs zkey verify keys/<circuit>.r1cs powersOfTau28_hez_final_14.ptau keys/<circuit>_final.zkey
```

`zolana zk import keys/<circuit>_final.zkey --r1cs keys/<circuit>.r1cs -p <crate>` then checks
the zkey against the r1cs and writes `target/zk/<crate>/<circuit>.pk`, and
the following exports the checked key into `src/verifier/<circuit>.vk.rs`:

```bash
zolana zk export-verifier --setup production -p <crate> \
  --checksums target/zk/<crate>/<circuit>.pk.sha256 target/zk/<crate>/<circuit>.pk
```

This is the verifying key the program includes. `build-zk-program` keeps a production key instead of replacing it with a
test key. The circuit is frozen from the `groth16 setup` on.

Key generation and import also write `<circuit>.pk.sha256`, a sha256sum-style
manifest. Export checks each selected `.pk` against `--checksums` before loading it;
manifest paths are relative to the manifest directory. For several circuits,
combine their manifests in that directory and select the keys to export.

WASM `<Name>Prover.fromKey(provingKey, expectedSha256)` requires the expected SHA-256 as
32 bytes. Pin that digest in trusted application metadata (for example, the
release's key manifest). A missing, malformed, or mismatched digest rejects the
load. Fetching a digest from the same untrusted source as the key does not
establish authenticity. The local examples use manifests produced during their
trusted test-key build.

Keys use arkworks canonical uncompressed serialization: a ceremony-import flag
followed by the proving key. Loading validates curve and subgroup membership.
A trusted checksum covers the provenance flag along with the key; it does not
prove that a ceremony's participants behaved honestly.

`UniqueDataUtxo::new_init(owner, seed)` reserves an address. Include the program id
and account identifier in the seed to separate applications and accounts. The
Rust client prepends address slots to the transaction and fetches only their nullifier
non-inclusion proofs. Use `create_proof_inputs_and_encrypt_with_keys` when a new
address supplies the first nullifier; it has no cached transaction viewing key. Address-first transactions also need an
explicit output tree in `TxContext`.

`ProofInputs::public_hash()` works only when synthesis established a single public
input. A `.wtns` file does not record that layout, so imported assignments expose
the public hash through the prover's verified `ProofResult`.

UTXO nullifier and tree-selection metadata are internal. ZK programs verify the
shared `private_tx_hash`; the SPP proof binds the transaction's nullifiers and
other SPP fields. Application authorization uses the program's constrained state
and public inputs, not the carried metadata. Tests that inspect SDK internals
must explicitly enable `test-support`.

### Circuit outputs and client traits

A standalone circuit implements `Circuit` with `type Output = ()` and returns
`Ok(())` after its assertions. A transaction circuit sets
`type Output = CheckedTransaction` and returns `transaction.check()`.
Both use `ZkCircuit` for checking and exports. Transaction circuits additionally
implement `ZkProgramCircuit` automatically, providing transaction construction and
encryption. Import `ZkCircuit` to call its methods on a concrete program input;
a generic `P: ZkProgramCircuit` already inherits those methods.

For a `PublicHashOutput` such as `CheckedTransaction`, the SDK allocates the
public hash as the first public input, before the circuit instantiates any
private input, and constrains it to the output's public hash after the circuit
runs. Variable 1 is therefore always the public hash, and moving that allocation
changes every proving key. `CircuitOutput` is sealed: an output is `()` or a
`PublicHashOutput`, which only names its hash; it never allocates or constrains
the public input itself.
