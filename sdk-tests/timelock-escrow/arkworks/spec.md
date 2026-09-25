# zk-program-sdk spec

Status: draft, 2026-09-25.

## Protocol assumption

This spec assumes a protocol change that is not implemented yet. [`docs/spec.md`](../../../docs/spec.md)
still includes `external_data_hash` in `private_tx_hash`.

- `private_tx_hash = Poseidon(input_utxo_hash_chain, output_utxo_hash_chain,
  address_nullifier_chain, private_tx_blinding)`, without `external_data_hash`.
- The SPP proof keeps `external_data_hash` as its own public input, which SPP recomputes from
  the instruction data. The SPP proof still covers the external data.
- P256 owners sign `SHA-256(private_tx_hash || external_data_hash)`. SPP computes the digest.
- Ed25519 owners are covered by the Solana transaction signature, as today.
- `zolana_transaction` computes this hash with
  `SppProofInputs::private_tx_hash_without_external_data`. The current hash, which
  `message_hash` uses, stays as it is.

The logic proof then depends only on the UTXOs, not on the encrypted notes.

## Circuit structure

A circuit's inputs are one struct with two fields:

```rust
pub struct Escrow {
    pub private: EscrowPrivateInputs,
    pub public: EscrowPublicInputs,
}
```

- `private` holds everything the program does not see: the input UTXOs, their state, the new
  state that cannot be computed from the old state, and the transaction values.
- `public` holds the circuit-specific values the program knows or recomputes, for the escrow
  `{ escrow_owner }`.
- The proof's one public input is the public hash, `Poseidon(public..., private_tx_hash)`. The
  public inputs struct fixes the order: its fields in declaration order, then
  `private_tx_hash` last. The native run computes the public hash, and `ArkworksCircuit`
  passes it to R1CS as the instance variable.

A Solana developer writes these plain types first, and the client, the tests and the prover
all take them. Instantiation turns `Escrow` into `circuit::Escrow`, with the same two fields
as circuit types (see [Types and range checks](#types-and-range-checks)). The `circuit`
module is the only place `CircuitVar` appears.

Rules:

1. The proof has exactly one public input, the public hash. `private` and `public` are both
   private inputs of the proof.
2. `private_tx_hash` is not an input. The circuit builds it from the transaction it
   creates.
3. `ConfidentialTransaction::check` computes the public hash. In R1CS, zk-program-sdk asserts
   that it equals the public input.
4. The program hashes the same `public` fields in the same order, then the SPP's
   `private_tx_hash`, and passes the result to the verifier.

### Public inputs

The public hash ends with `private_tx_hash`, which the circuit computes. The public inputs
struct holds only the circuit-specific fields before it, and their declaration order is the
hash order:

```rust
pub struct EscrowPublicInputs {
    pub escrow_owner: ShieldedAddress,
}

pub struct WithdrawPublicInputs {
    pub unlock: u64,
    pub owner_identity: [u8; 32],
}
```

- The program proof and the SPP proof share `private_tx_hash`: both prove the same
  transaction, and the program passes the SPP's hash into its own public input.
- The circuit-specific fields are what the program must check itself, for example the
  escrow owner it expects or the unlock time it compares with the clock.
- Every public inputs circuit type implements `PublicInputs`, which computes the public
  hash:

  ```rust
  pub trait PublicInputs {
      fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError>;
  }

  impl PublicInputs for circuit::EscrowPublicInputs {
      fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, RelationError> {
          poseidon(&[self.escrow_owner.clone(), private_tx_hash.clone()])
      }
  }
  ```

### Private inputs

Every private inputs struct starts with `tx_context`. The rest is circuit specific, in this
order:

1. `tx_context: TxContext`: the transaction values the circuit cannot compute, namely the
   first nullifier, the blinding seed, the output tree and the sender. `first_nullifier` is
   the nullifier of the UTXO the logic adds first. The sender is the wallet whose keys encrypt
   the outputs. `TxContext::new(first_nullifier, output_tree_id, sender)` picks the blinding
   seed.
2. Token UTXOs, one array per asset: `token_utxos_asset_a: [WalletUtxo; A]`,
   `token_utxos_asset_b: [WalletUtxo; B]`. Each length is a const generic or a constant, so
   the circuit's shape is fixed. `WalletUtxo::dummy` pads an array. In `circuit` each array
   becomes a `TokenUtxo`.
3. Data UTXOs: one named `WalletUtxo` per spent UTXO that holds program state, with its
   state next to it.
4. Arbitrary data: every other value, for example an amount or a recipient's
   `ShieldedAddress`.

Spent UTXOs are `WalletUtxo`s, the notes a wallet gets from the indexer, so the client holds
everything the transaction crate needs to build the SPP transaction.

```rust
pub struct EscrowPrivateInputs {
    pub tx_context: TxContext,
    pub token_utxos_asset_a: [WalletUtxo; ESCROW_TOKEN_INPUTS],
    pub creator: ShieldedAddress,
    pub unlock: u64,
    pub amount: u64,
}

pub struct WithdrawPrivateInputs {
    pub tx_context: TxContext,
    pub escrow: WalletUtxo,
    pub terms: EscrowTerms,
    pub creator: ShieldedAddress,
    pub creator_nullifier_pk: [u8; 32],
}
```

- The escrow spends the creator's token UTXOs of one asset.
- The withdraw spends `escrow`, a data UTXO, and `terms` is its old state.
- `creator` is the address the escrow's change and the withdraw's payout go to.
- `unlock` and `amount` are new data: the prover sets them and the escrow output includes
  them. The circuit checks that `amount` is not zero. Beyond its `u64` range, `unlock` needs
  no check at creation, because the program compares it with the clock at withdraw.
- `creator_nullifier_pk` is checked with the public `owner_identity`:
  `Poseidon(owner_identity, creator_nullifier_pk)` must equal `terms.creator`.
- Nothing the circuit can compute is a private input. Outputs, blindings and hashes are
  built in `circuit`.

### Types and range checks

Instantiating a circuit transforms its types. Proof inputs go in, and the types of the same
name in the `circuit` module come out, with every field a `CircuitVar` or a struct of them:

| Proof input | Circuit type |
| --- | --- |
| `Escrow` | `circuit::Escrow` |
| `EscrowPrivateInputs` | `circuit::EscrowPrivateInputs` |
| `EscrowTerms` | `circuit::EscrowTerms` |
| `TxContext` | `circuit::TxContext` |
| `WalletUtxo` | `circuit::Utxo` |

Proof inputs use plain Rust types that implement `ProofInput`:

| Type | Becomes | Check |
| --- | --- | --- |
| `u64`, `u32`, `u16` | the number | fits the width |
| `bool` | 0 or 1 | is 0 or 1 |
| `[u8; 32]` | the value | is canonical |
| `ShieldedAddress` | its owner hash | none |
| `Mint` | its asset hash | none |
| `WalletUtxo` | a `Utxo` | none, the SPP proof range-checks UTXO fields |
| a struct | its circuit type, field by field | its fields' checks |

- `circuit` is a method of the circuit type, so inside it every value is a `CircuitVar`.
- Instantiation is the only way from a proof input to its circuit type, and it runs the
  checks: natively as a comparison that fails with a named `RelationError`, in R1CS as
  constraints, for example a bit decomposition for a `u64`.
- A state has two forms, written by hand for now: the client form, for example
  `EscrowTerms { creator: [u8; 32], unlock: u64 }`, and the circuit form with `CircuitVar`
  fields.
- `FromCircuit` is the way back, `from_circuit(&circuit) -> Result<Self>`. It reads the
  values of the native run and checks the same ranges. `u64`, `u32`, `u16`, `bool`,
  `[u8; 32]` and arrays of them implement it, and a state's client form implements it
  field by field. A `ShieldedAddress`, a `Mint` or a spent UTXO cannot come back from its
  hash.
- A computed value that needs a bound gets an explicit check in `circuit`:
  `check_bits(bits)` or `check_is_bool` on `CircuitVar`.
- The SPP proof range-checks UTXO amounts. The circuit range-checks its inputs and the
  computed values its logic relies on, such as the operands of a comparison.

## UTXO types

zk-program-sdk has three UTXO types, each a version of Light's `LightAccount`:

| Type | What it is |
| --- | --- |
| `DataUtxo<S>` | A UTXO with program state `S`, close to `LightAccount`: `new_init`, `from_output_utxo`, `new_mut`, `new_burn`, and `transfer` once burned. |
| `TokenUtxo<N>` | `LightAccount` without data: `N` UTXOs of one owner and one asset, to transfer from: `new_init`, `new_mut`, `new_burn`. |
| `OutputTokenUtxo` | The output UTXO a transfer creates for its recipient. |

- A state `S` implements `DataHash`, a Poseidon hash over its fields in declaration order.
  Each field contributes its own `hash`: a `CircuitVar` is itself, and a nested struct is its
  `DataHash`.

  ```rust
  impl DataHash for circuit::EscrowTerms {
      fn hash(&self) -> Result<CircuitVar, RelationError> {
          poseidon(&[self.creator.hash()?, self.unlock.hash()?])
      }
  }
  ```
- A state's circuit form implements `UtxoData`, which names its client form:

  ```rust
  impl UtxoData for circuit::EscrowTerms {
      type Client = EscrowTerms;
  }
  ```

  The client form implements `FromCircuit` and derives `BorshSerialize` and
  `BorshDeserialize`. Its borsh bytes are the data a new data UTXO contains, for the escrow
  `creator || unlock`. The native run converts the new state back and serializes it. R1CS
  does neither. A client reads a spent UTXO's state back with `try_from_slice`.
- `DataUtxo::new_init(owner)` holds no value: SOL with amount 0.
- `token.transfer(recipient, amount)` returns an `OutputTokenUtxo` for the recipient.
- A `TokenUtxo` tracks a change balance: its inputs plus deposits, minus withdrawals and
  transfers. The balance becomes a change UTXO to the token's owner. The change is not
  passed around: `with_token_utxos` creates it.
- Any input after the first can be a dummy, so a wallet with fewer UTXOs than `N` pads with
  dummies. The first input is real: the token takes its owner and asset from it. A dummy
  has the protocol's dummy domain, holds nothing, skips the owner and asset checks, and its
  input slot hashes as 0.
- `token.deposit(amount)` adds to the change balance and `token.withdraw(amount)` subtracts
  from it. They only balance the UTXOs. The public amounts themselves are controlled by the
  SPP proof.
- A `TokenUtxo` has a lifecycle like a `DataUtxo`, so the circuit's shape is fixed:

  | Lifecycle | Constructor | Inputs | Change output |
  | --- | --- | --- | --- |
  | `Init` | `new_init(owner, asset)` | none (`N = 0`), the balance comes from `deposit` | yes |
  | `Mut` | `new_mut(inputs)` | `N` | yes |
  | `Burn` | `new_burn(inputs)` | `N` | none |

  A `Burn` token's balance must end at zero, and the circuit asserts it. The SPP proof would
  otherwise book a leftover as a public withdrawal.
- An `OutputTokenUtxo` is added to the transaction as an output, or becomes the value of a
  new data UTXO through `DataUtxo::from_output_utxo`.

## The `circuit` method

`circuit` implements the logic of the circuit and creates the output UTXOs. It builds a
`ConfidentialTransaction` and ends with `check`. It lives in the `circuit` module, where
`Escrow` and `EscrowTerms` are the circuit types:

```rust
impl Circuit for Escrow {
    fn circuit(&self) -> Result<CheckedTransaction, RelationError> {
        let private = &self.private;
        private.amount.assert_not_equal(&zero(), "the escrow locks nothing")?;
        let mut tokens = TokenUtxo::new_mut(private.token_utxos_asset_a.clone())?;
        let locked = tokens.transfer(&self.public.escrow_owner, private.amount.clone());
        let mut escrow = DataUtxo::<EscrowTerms>::from_output_utxo(locked)?;
        escrow.creator = tokens.owner().clone();
        escrow.unlock = private.unlock.clone();

        ConfidentialTransaction::<_, N_INPUTS, N_OUTPUTS>::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(escrow)
            .check()
    }
}
```

- `with_token_utxos(TokenUtxo)` adds what the lifecycle implies: `Init` adds the change
  output, `Mut` the inputs and the change output, and `Burn` the inputs.
- `with_output_token_utxo(OutputTokenUtxo)` adds a transfer's output.
- `with_data_utxo(DataUtxo)` adds what the lifecycle implies: `Init` adds an output, `Mut` an
  input and an output, and `Burn` an input.
- `ConfidentialTransaction<IN, OUT>` has the SPP circuit's shape. `IN` and `OUT` are the
  program's `N_INPUTS` and `N_OUTPUTS`.
- Slots follow the order in which UTXOs are added: each input takes the next input slot and
  each output the next output slot.
- Unused input slots hash as 0. Unused output slots hold a zero-SOL output to
  `tx_context.sender`, the transaction crate's padding, so every output slot carries a
  ciphertext and the transaction does not show how many outputs are real. Adding more inputs
  than `IN` or more outputs than `OUT` fails with a named `RelationError`.
- `check` does the rest:
  1. fills the unused output slots, derives each output's blinding from `tx_context` and
     hashes the output,
  2. computes `private_tx_hash` from the input and output hashes,
  3. computes the public hash with `public.hash(&private_tx_hash)`.

  It returns a `CheckedTransaction`: the public hash, `private_tx_hash` and the slots, which
  the client resolves (see [Client](#client)).
- In R1CS, zk-program-sdk asserts the returned public hash equals the public input.
  `ConfidentialTransaction` is `#[must_use]`, so a circuit cannot skip `check`.
- The same method runs natively on constants, where a broken rule is a named
  `RelationError`, and in R1CS on allocated variables, where it is an unsatisfied
  constraint.
- The logic does not branch on values, so both runs build the same slots.
- A burned `DataUtxo` pays out its value with `transfer(recipient, amount)`, which returns an
  `OutputTokenUtxo` like `TokenUtxo::transfer`. It has no change: its transfers must pay out
  its whole value, and the circuit asserts it. The withdraw transfers the whole escrow amount
  to `terms.creator`.

## Client

The proof inputs are the crate's root types: `Escrow`, `EscrowPrivateInputs`,
`EscrowPublicInputs`. Their circuit forms have the same names in the `circuit` module. This
inverts Anchor, where the program's `Initialize<'info>` is primary and `accounts::Initialize`
is its client counterpart. Here the client type is primary, and `circuit::Escrow` derives from
it.

The client runs the same `circuit` natively through the `ZkProgram` trait, and the prover runs
it in R1CS:

```rust
impl ZkProgram for Escrow {}

let (escrow, spp_proof_inputs) =
    escrow.create_proof_inputs_and_encrypt(&shielded_keys, payer, expiry_unix_ts)?;
let proof = ArkworksCircuit::new(escrow)?.prove(&keys, &mut rng)?;
```

- `ZkProgram` requires the inputs to implement `ProofInput` and `ProofInput::Circuit` to
  implement `Circuit`. It provides `create_proof_inputs_and_encrypt`, which:
  1. instantiates the inputs natively and runs `circuit`,
  2. resolves the slots against the records and converts each output amount to `u64`, with a
     named error when one does not fit,
  3. builds `zolana_transaction::ConfidentialTransaction` from the resolved inputs and
     outputs, with the circuit's blinding seed and shape, and encrypts it with the keys:
     blindings, owner tags, ciphertexts and `external_data_hash`,
  4. sets the expiry and checks that `private_tx_hash_without_external_data` equals the
     circuit's `private_tx_hash`.

  It takes the inputs by value and returns them with the `SppProofInputs`.
- The keys implement `ShieldedKeys`, and their address must be `tx_context.sender`.
- Both proofs share the hash `private_tx_hash_without_external_data` computes from the
  `SppProofInputs`.
- Building the program instruction from the proofs is a separate step, after proving.
- Native instantiation records what a `CircuitVar` cannot hold, keyed by the hash the logic
  uses: `owner_hash → ShieldedAddress`, `asset_hash → Mint` and `utxo_hash → WalletUtxo`.
  R1CS instantiation records nothing.
- `create_proof_inputs_and_encrypt` checks `tx_context.first_nullifier` against slot 0 and
  resolves each slot of the `CheckedTransaction` against these records: an input hash to its
  `WalletUtxo`, an unused input slot to `WalletUtxo::dummy` in the tree before it, and an
  output's owner and asset hashes to its address and `Mint`. Each resolved output must hash
  to the circuit's output hash.
- Every output owner, change included, comes from a `ShieldedAddress` input: a spent UTXO has
  its owner's signing and nullifier keys but not the viewing key the encryption needs.
- Both proofs start from the result of `create_proof_inputs_and_encrypt` and run in
  parallel.
- The client also holds what the circuit does not see: Merkle proofs and leaf indexes,
  nullifier data and owner signers, and recipient viewing keys.
- Encryption, owner tags and the SPP proof input types come from `zolana_transaction`, the same
  code a wallet's plain transfer uses.

## SDK modules

zk-program-sdk follows the same split:

| Path | Contents |
| --- | --- |
| `zk_program_sdk` | What the client and the prover use: `TxContext`, `ZkProgram`, `ArkworksCircuit`, the Groth16 types and their `ProvingKey`, `VerifyingKey` and `Proof` aliases, `RelationError`. |
| `zk_program_sdk::circuit` | The DSL: `CircuitVar`, `Field`, `CircuitSystem`, `ConstraintSystem`, `Assert`, `constant`, `zero`, `value`, `poseidon`, `TxContext`, `Utxo`, `TokenUtxo`, `DataUtxo`, `OutputTokenUtxo`, `ConfidentialTransaction`, `CheckedTransaction`, `PublicInputs`, `DataHash`, `UtxoData`, `Circuit`. |
| `zk_program_sdk::conversion` | Between the two: `ProofInput`, `FromCircuit`, `Allocator`, `Records`, and bytes to fields and back. |

Everything a future macro derives can also be written by hand, so `conversion` stays public.
A feature may gate it later.

## Setup and features

- `ArkworksCircuit::setup` synthesizes default sample inputs. `ConfidentialTransaction<IN, OUT>`
  and `TokenUtxo<N>` keep the sizes generic, so another shape is other constants.
- zk-program-sdk has two features:

  | Feature | Contents |
  | --- | --- |
  | `client` | The native run, the SPP proof inputs, loading a proving key, proving. |
  | `setup` | Groth16 setup, writing the proving key, exporting the verifying key as a program constant marked `InsecureTest`. |

  The input types, the UTXO types, `ConfidentialTransaction`, `circuit` and R1CS synthesis
  compile without either. Both are on by default. A wallet that does not generate keys
  depends on zk-program-sdk with `default-features = false, features = ["client"]`.

## Tests

Each test builds its inputs inline. Shared helpers only create keypairs and spendable UTXOs.

## Out of scope for the PoC

- A macro that rejects logic that branches on values.
- A derive macro on the client types that generates their `circuit` module types and the
  `ProofInput`, `FromCircuit`, `DataHash` and `UtxoData` impls.
