# zolana-program spec

Status: draft, 2026-09-25.

## Protocol

The circuits follow the padding-independent private transaction hash of
[`docs/spec.md`](../../docs/spec.md) (proposal:
[`docs/padding_independent_private_tx_hash.md`](../../docs/padding_independent_private_tx_hash.md)).

- `private_tx_hash` is `Poseidon(input_chain, output_chain, address_chain, blinding)` and leaves
  out `external_data_hash`. Each chain is a nonzero hash chain: it skips zeros, takes the first
  real value as it is and hashes each later value with the running value using Poseidon, so
  padding does not enter it.
- Dummies come after every real slot, on the input side and on the output side. The SPP
  transact circuit enforces it, and `zolana_transaction` refuses a real slot after a dummy.
- `zolana_transaction` computes the hash with
  `SppProofInputs::padding_independent_private_tx_hash`; `message_hash`, which a P256 owner
  signs, is `sha256(private_tx_hash || external_data_hash)`.

The logic proof then depends only on the real UTXOs, not on the SPP shape or the encrypted
notes.

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
  `private_tx_hash` last. The native run computes the public hash, and the prover passes it
  to R1CS as the instance variable.

A Solana developer writes these plain types first, and the client, the tests and the prover
all take them. Instantiation turns `Escrow` into `circuit::Escrow`, with the same two fields
as circuit types (see [Types and range checks](#types-and-range-checks)). The `circuit`
module is the only place `CircuitVar` appears.

Rules:

1. The proof has exactly one public input, the public hash. `private` and `public` are both
   private inputs of the proof.
2. `private_tx_hash` is not an input. The circuit builds it from the transaction it
   creates.
3. `ConfidentialTransaction::check` computes the public hash. In R1CS, zolana-program asserts
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
      fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, CircuitError>;
  }

  impl PublicInputs for circuit::EscrowPublicInputs {
      fn hash(&self, private_tx_hash: &CircuitVar) -> Result<CircuitVar, CircuitError> {
          poseidon(&[self.escrow_owner.clone(), private_tx_hash.clone()])
      }
  }
  ```

### Private inputs

Every private inputs struct starts with `tx_context`. The rest is circuit specific, in this
order:

1. `tx_context: TxContext`: the transaction settings no input determines, namely the
   blinding seed and the output tree. `TxContext::new()` draws the seed from the OS RNG and
   sets the output tree to `Some(0)`; `None` appends the outputs to the first spent input's
   `latest_tree_id`. The circuit takes the first nullifier from the UTXO the logic spends
   first, and the client takes the sender from the keys that encrypt.
2. Token UTXOs, one bounded `Vec` per asset: `#[max_len(A)] token_utxos_asset_a:
   Vec<WalletUtxo>`, `#[max_len(B)] token_utxos_asset_b: Vec<WalletUtxo>`. Each bound is a
   const generic or a constant: the most UTXOs of that asset the circuit spends. The client
   passes the UTXOs it has, at least `#[min_len]` of them (default 1; `#[min_len(0)]` allows
   none), and the derive fills the unused slots with `Dummy::dummy(first)`, dummies in the
   first UTXO's tree, or in tree 0 when there is none. More or
   fewer UTXOs than the bounds allow is a `TooManyItems` or `TooFewItems` error naming the
   field. Only an item type that implements `Dummy`, today `WalletUtxo`, can be bounded, and
   states and public inputs refuse bounded fields. In `circuit` each field is a `[Utxo; A]`
   and becomes a `TokenUtxos`. A fixed `[WalletUtxo; A]` still works when the caller pads
   it.
3. Data UTXOs: one named `WalletUtxo` per spent UTXO that holds program state, with its
   state next to it.
4. Arbitrary data: every other value, for example an amount or a recipient's
   `ShieldedAddress`.

Spent UTXOs are `WalletUtxo`s, the notes a wallet gets from the indexer, so the client holds
everything the transaction crate needs to build the SPP transaction.

```rust
pub struct EscrowPrivateInputs {
    pub tx_context: TxContext,
    #[max_len(ESCROW_TOKEN_INPUTS)]
    pub token_utxos_asset_a: Vec<WalletUtxo>,
    pub unlock: u64,
    pub amount: u64,
}

pub struct WithdrawPrivateInputs {
    pub tx_context: TxContext,
    pub escrow: WalletUtxo,
    pub terms: EscrowTerms,
}
```

- The escrow spends the creator's token UTXOs of one asset. The change goes back to their
  owner, and the escrow state records that owner as `creator`.
- The withdraw spends `escrow`, a data UTXO, and `terms` is its old state. The payout goes to
  `terms.creator`, whose key identity must equal the public `owner_identity`.
- The keys that encrypt name the address the client encrypts the change and the payout for.
- `unlock` and `amount` are new data: the prover sets them and the escrow output includes
  them. The circuit checks that `amount` is not zero. Beyond its `u64` range, `unlock` needs
  no check at creation, because the program compares it with the clock at withdraw.
- Nothing the circuit can compute is a private input, and every private input is read by a
  constraint. Outputs, blindings and hashes are built in `circuit`.

### Types and range checks

Instantiating a circuit transforms its types. Proof inputs go in, and the types of the same
name in the `circuit` module come out, with every field a circuit type: a `CircuitVar`, a
`Uint<BITS>`, a `Bool` or a struct of them:

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
| `u64`, `u32`, `u16` | a `Uint<64>`, `Uint<32>`, `Uint<16>` | fits the width |
| `bool` | 0 or 1 | is 0 or 1 |
| `[u8; 32]` | the value | is canonical |
| `Bytes<N>` | `N` byte variables | each byte fits 8 bits |
| `ShieldedAddress`, `Owner` | an `Owner`: tag, key bytes, nullifier key | key bytes fit 8 bits, the tag is `S` or `P` |
| `Mint` | an `Asset`: the mint bytes | each byte fits 8 bits |
| `WalletUtxo` | a `Utxo` with its `Owner` and `Asset` | the owner and asset checks; the SPP proof range-checks the other fields |
| a struct | its circuit type, field by field | its fields' checks |

- Byte hashing is exposed through `Bytes<N>::hash_bytes()`, which accepts only
  checked bytes with a type-level length. Every protocol hash domain fixes its N:
  mint and account values are 32 bytes, tagged owner identities are 33 bytes,
  and data byte fields use their declared `Bytes<N>` width. Leading zeroes and
  all-zero values are valid. Length is not encoded in the resulting field value,
  so hashes from different widths must not be used interchangeably in one domain.
  Inputs of at most 31 bytes are packed directly; longer inputs fold packed
  chunks through Poseidon. Raw field slices are not a public byte-hashing API.

- Owners and assets are preimages. The circuit hashes them itself, each once:
  `Asset::hash` is `hash_bytes(mint)`, `OwnerKey::identity` is `hash_bytes(tag || key)`,
  and `Owner::hash` is `Poseidon(identity, nullifier_pk)`. Two owners or two assets are
  compared on their packed preimage chunks, a few constraints and no hashing. A `TokenUtxos`
  checks that its later inputs match the first input's owner and asset this way, then hashes
  them with the first input's owner and asset hashes.
- `Utxo::hash()` commits a dummy using zero owner and asset hash fields, matching
  the native dummy commitment. Hashes of its zero owner and SOL mint preimages
  are not substituted for those zero fields. The selection is constrained by
  the UTXO domain, and the tree id/blinding remain part of the commitment.
- The SPP proof checks dummy inputs. A dummy slot contributes 0 to the input chain, and its
  preimage is all zeros: the byte checks pass for zeros, and only the tag check is skipped
  for a slot whose domain is the dummy domain. Nothing hashes a dummy's owner, so a
  `TokenUtxos` asserts that a dummy's nullifier key is zero, one constraint per later input.

- `circuit` is a method of the circuit type, so inside it every value is a `CircuitVar`.
- Native instantiation represents proof inputs as constants, so `value` may
  read them during client-side evaluation. R1CS instantiation allocates variables,
  and reading a proof input then fails with `ReadsVariableValue`. Native success
  is not a proof-readiness check; `check_constraints` also checks setup/proving.

- Instantiation is the only way from a proof input to its circuit type, and it runs the
  checks: natively as a comparison that fails with a named `CircuitError`, in R1CS as
  constraints, for example a bit decomposition for a `u64`.
- A state has two forms, written by hand for now: the client form, for example
  `EscrowTerms { creator: Owner, unlock: u64 }`, and the circuit form with `circuit::Owner`
  and `Uint<64>` fields.
- `FromCircuit` is the way back, `from_circuit(&circuit) -> Result<Self>`. It reads the
  values of the native run and checks the same ranges. `u64`, `u32`, `u16`, `bool`,
  `[u8; 32]`, `Bytes<N>`, `Owner` and arrays of them implement it, and a state's client form
  implements it field by field. A `ShieldedAddress`, a `Mint` or a spent UTXO cannot come
  back: the viewing key, the asset id and the indexer context are not in the circuit.
- Integers are `Uint<BITS>`, a value below `2^BITS`, with the aliases `U8`, `U16`, `U32`,
  `U64` and `U128`. `add`, `mul` and `sum` return a wider type, and the width checks run when
  the circuit is built, so a sum or a product that could wrap around the field does not
  compile. `From` widens between the aliases and from a `Bool`. A computed value that must
  fit a width gets `checked_add`, `checked_mul`, `checked_sub` or a comparison, each with a
  named rule, or `TryFrom` into a narrower alias, which range-checks it.
- A computed `CircuitVar` that needs a bound gets an explicit check in `circuit`:
  `check_bits(bits)` or `check_is_bool` from `Bits`, or `Uint::try_from(&var)`, which
  range-checks it into a `Uint<BITS>`. `Bool::try_from(&var)` checks a 0 or 1 value and
  `Bytes::<N>::try_from(&var)` splits one into bytes; `CircuitVar::from` turns a `Bool` or a
  `Uint<BITS>` back into a value, and `CircuitVar::try_from(&bytes)` packs bytes.
- `CircuitVar` is a field element. `+`, `-`, `*`, unary `-`, `+=`, `-=` and `*=` wrap around
  the modulus: a sum and a product by a constant are free, and a product of two variables
  costs one constraint. `inverse`, `div` and `pow` (by a constant exponent) are methods;
  `inverse` and `div` refuse a zero divisor. `/`, `%`, `==` and `<` do not compile: the `/`
  and `%` errors point to `Uint::div_rem` and `CircuitVar::div`, and the `==` and `<` errors
  name the rules `UseAssertEqual` and `UseUintComparison`, for `assert_equal` or `is_equal`
  and the `Uint` comparisons. Equality and zero checks go through `Assert`: `is_equal(&zero())`,
  `assert_equal` and `assert_not_equal`.
- A circuit cannot allocate a `CircuitVar`, and `value` reads only a constant. Reading a
  variable fails in both runs with the line of the read.
- The SPP proof range-checks UTXO amounts, so a spent UTXO's amount is a trusted `Uint<64>`
  that a circuit reads through `UtxoTrait`. The circuit range-checks its inputs and the computed
  values its logic relies on, such as the operands of a comparison.

## UTXO types

zolana-program has two UTXO types, each a version of Light's `LightAccount`. Both hold value,
and `UtxoTrait::transfer` moves value from one to the other:

| Type | What it is |
| --- | --- |
| `DataUtxo<S>` | A UTXO with program state `S`, close to `LightAccount`: `new_init(owner, asset)`, `new_mut`, `new_close`. |
| `TokenUtxos` | `LightAccount` without data: UTXOs of one owner and one asset, none from `new_init(owner, asset)`, `N` from `new_mut` or `new_close`. |

- A state `S` implements `DataHash`, a Poseidon hash over its fields in declaration order.
  Each field contributes its own `hash`: a `CircuitVar` or a `Uint` is its value, and a
  nested struct is its `DataHash`.

  ```rust
  impl DataHash for circuit::EscrowTerms {
      fn hash(&self) -> Result<CircuitVar, CircuitError> {
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
  the creator's tag, key and nullifier key, then `unlock`: 73 bytes. The native run converts
  the new state back and serializes it. R1CS does neither. A client reads a spent UTXO's state
  back with `try_from_slice`.
- `new_init(owner, asset)` holds nothing until a transfer or a deposit: amount 0 in `asset`.
  A data UTXO that only holds state passes `&Asset::sol()`.
- `source.transfer(&mut destination, &amount)?` moves `amount` into another UTXO, a
  `TokenUtxos` or a `DataUtxo`, empty or not. An empty destination comes from `new_init` and
  holds the asset it was built with. A destination with inputs holds their asset, and its
  owner signs in SPP because the inputs are spent. Emptiness is structural, never a zero
  balance, since the prover controls the balance. The transfer checks, in order:
  1. the destination is not closed, a structural error in both runs;
  2. the destination holds the source's asset: the packed mint bytes are compared, two
     constraints, skipped when the destination's asset is a clone of the source's, as when it
     was built from `source.asset()`. That identity comes from how the circuit is written, so
     the prover cannot influence it;
  3. the amount fits in 64 bits, which its type `Uint<64>` guarantees. Without it, a
     field-negative amount would move value out of a destination that holds some into the
     source, and both balances would still pass SPP's range checks;
  4. what remains of the source's balance fits in 64 bits, so the transfer does not exceed
     the balance. A mint's total supply is a u64.

  Natively each rule is a named `CircuitError`, so the mistake stops while the proof inputs
  are built; in R1CS rules 2 and 4 are constraints. `transfer_all(&mut destination)?` checks
  rules 1 and 2 and moves the whole balance: a balance cannot go negative, because SPP
  range-checks the input amounts and every debit passes rules 3 and 4. `withdraw` checks rule
  4 for what remains. A public transfer of zero is refused by a constraint, "a public
  transfer moves a nonzero amount". `withdraw_all(&destination)?` returns the amount it
  withdraws. `amount()` is a `Uint<64>`: free while the balance is known to fit 64 bits, one
  range check when it could exceed them, as for a token with several inputs.
- Each UTXO records its net transfers: what it received minus what it sent. `check` sums them
  over every UTXO added to the transaction and asserts the sum is zero, rule "value leaves the
  transaction: a utxo was not added". Forgetting to add a destination compiles, because the
  `&mut` borrow counts as a use; this check refuses it. Every transfer stays within one asset,
  so one sum covers the transaction: one linear constraint in R1CS.
- The constructors borrow their inputs: `TokenUtxos::new_mut(&inputs)`,
  `DataUtxo::new_mut(&input, &state)`. The accessors return values: `amount()`, `owner()`
  and `asset()`. An owner's and an asset's hashes are shared between clones.
- A `TokenUtxos` tracks a balance: its inputs plus deposits and the transfers it receives,
  minus withdrawals and the transfers it sends. The balance becomes an output to the token's
  owner, the change for a token with inputs. `with_token_utxos` creates the change.
- Any input after the first can be a dummy, so a wallet with fewer UTXOs than `N` spends
  them with dummies after them. The first input is real: the token takes its owner and asset
  from it. A dummy
  has the protocol's dummy domain, holds nothing, skips the owner and asset checks, and hashes
  as 0, which `private_tx_hash` skips.
- `token.deposit(amount)` adds to the change balance and `token.withdraw(amount)` subtracts
  from it. They only balance the UTXOs. The SPP proof controls the public amounts.
- A `TokenUtxos` has a lifecycle like a `DataUtxo`, fixed when the circuit is written:

  | Lifecycle | Constructor | Inputs | Output |
  | --- | --- | --- | --- |
  | `Init` | `new_init(owner, asset)` | none, the balance comes from transfers and `deposit` | yes |
  | `Mut` | `new_mut(inputs)` | `N` | yes |
  | `Close` | `new_close(inputs)` | `N` | none |

  A `Close` token's balance must end at zero, and the circuit asserts it. The SPP proof would
  otherwise book a leftover as a public withdrawal.
- The output of an `Init` or `Mut` token is an empty UTXO when its balance is zero at proof
  time and every later output is empty too, because dummies must come after every real
  output: the protocol's dummy domain, zero owner and asset, and its slot's derived blinding.
  It keeps its slot and adds 0 to the output chain of `private_tx_hash`, while its dummy
  commitment stays in the public output hashes. A zero output that a real output follows
  stays a zero-amount UTXO of its owner. A circuit whose change may reach zero adds that
  token last, so a spend of the whole balance leaves no zero-amount UTXO, and the transaction
  still does not show whether the sender kept change. The circuit decides emptiness from the
  balances with an is-zero test per token output, folded from the last output back, so a
  prover cannot choose it. `Close` remains the lifecycle for a circuit that knows nothing is
  left: it takes no output slot and costs one constraint.
- A `DataUtxo` output stays a real UTXO at a zero balance, because it contains state. Only its
  closing lifecycles leave no output or, for a `UniqueDataUtxo`, the closed-address marker.

## The `circuit` method

`circuit` implements the logic of the circuit and creates the output UTXOs. It builds a
`ConfidentialTransaction` and ends with `check`. It lives in the `circuit` module, where
`Escrow` and `EscrowTerms` are the circuit types:

```rust
impl Circuit for Escrow {
    fn circuit(&self) -> Result<CheckedTransaction, CircuitError> {
        let private = &self.private;
        private.amount.assert_not_zero("the escrow locks nothing")?;
        let mut tokens = TokenUtxos::new_mut(&private.token_utxos_asset_a)?;
        let mut escrow =
            DataUtxo::<EscrowTerms>::new_init(&self.public.escrow_owner, &tokens.asset());
        tokens.transfer(&mut escrow, &private.amount)?;
        escrow.creator = tokens.owner();
        escrow.unlock = private.unlock.clone();

        ConfidentialTransaction::new(&private.tx_context, &self.public)
            .with_token_utxos(tokens)
            .with_data_utxo(escrow)
            .check()
    }
}
```

- `with_token_utxos(TokenUtxos)` adds what the lifecycle implies: `Init` adds its output,
  `Mut` the inputs and the change output, and `Close` the inputs.
- `with_data_utxo(DataUtxo)` adds what the lifecycle implies: `Init` adds an output, `Mut` an
  input and an output, and `Close` an input.
- `ConfidentialTransaction` has no shape. It holds the UTXOs the circuit adds, and the client
  picks the smallest SPP shape with enough slots for the real ones.
- Inputs and outputs keep the order in which UTXOs are added. The SPP transaction puts the
  real outputs first, in this order, because an output's blinding depends on its index.
- A dummy input hashes as 0 and the chain skips it. The circuit adds no padding: the SPP
  transaction fills its unused output slots with empty UTXOs, which include a ciphertext like
  every output, so the transaction does not show how many outputs are real.
- `check` does the rest:
  1. asserts that the transfers net to zero over the UTXOs added,
  2. derives each output's blinding from `tx_context` and its index, and hashes the output,
     as an empty UTXO for a token output of zero that only empty outputs follow,
  3. computes `private_tx_hash` with `nonzero_hash_chain` over the input and output hashes,
     where an empty output enters as 0,
  4. computes the public hash with `public.hash(&private_tx_hash)`.

  It returns a `CheckedTransaction`: the public hash, `private_tx_hash` and the slots, which
  the client resolves (see [Client](#client)).
- In R1CS, zolana-program asserts the returned public hash equals the public input.
  `ConfidentialTransaction` is `#[must_use]`, so a circuit cannot skip `check`.
- The same method runs natively on constants, where a broken rule is a named
  `CircuitError` that points at the circuit's line, and in R1CS on allocated variables, where it is an unsatisfied
  constraint. Every check labels its rows with its rule and the circuit's `file:line`, so an
  unsatisfied row names both.
- The logic cannot branch on values, since `value` reads only constants, so both runs build
  the same slots. `check_constraints` also synthesizes the placeholder the keys come from
  and names a shape or a constraint that differs from it.
- `testing::check_private_variables` perturbs every private variable of a proof and lists
  the ones no constraint refuses. Both scenario suites and the escrow tests require that
  list to be empty, apart from equality hints and the unused inputs' nullifier and latest
  tree, which the SPP proof constrains.
- `TokenUtxos` and `DataUtxo` move value through the same `UtxoTrait` trait: `transfer`,
  `transfer_all`, `deposit`, `withdraw` and `withdraw_all`, in every lifecycle. Every
  movement of value between UTXOs is a `transfer` or a `transfer_all`. The lifecycle only
  decides what is left: the output for a token or a data UTXO, an empty UTXO for a token
  output of zero, and zero once closed, which the circuit asserts. The withdraw moves the whole escrow amount into a new `TokenUtxos` for
  `terms.creator` with `transfer_all`.

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

let spp_proof_inputs =
    escrow.create_proof_inputs_and_encrypt_with_keys(&shielded_keys, payer, expiry_unix_ts)?;
let prover = Groth16Prover::<Escrow>::new(Groth16Keys::load(proving_key_path)?)?;
let result = prover.prove(&escrow)?;
```

- `ZkProgram` requires the inputs to implement `ProofInput` and `Placeholder`, and
  `ProofInput::Circuit` to implement `Circuit`. It provides `create_proof_inputs_and_encrypt_with_keys`,
  which:
  1. instantiates the inputs natively and runs `circuit`,
  2. resolves the slots against the records and converts each output amount to `u64`, with a
     named error when one does not fit,
  3. builds `zolana_transaction::ConfidentialTransaction` from the resolved inputs and
     outputs, adding each empty output in its slot with `add_empty_output_utxo`, with the
     circuit's blinding seed, picks the smallest SPP shape they fit, pads it with dummy inputs
     and empty outputs, and encrypts it with the keys: blindings, owner tags, ciphertexts and
     `external_data_hash`,
  4. sets the expiry and checks that `padding_independent_private_tx_hash` equals the
     circuit's `private_tx_hash`.

  It borrows the inputs and returns the `SppProofInputs`. The prover borrows the same inputs,
  so both proofs come from one value.
- The keys implement `ShieldedKeys`. Their address resolves any output the records do not
  name, such as the change.
- Both proofs share the hash `padding_independent_private_tx_hash` computes from the
  `SppProofInputs`.
- Building the program instruction from the proofs is a separate step, after proving.
- Native instantiation records what a `CircuitVar` cannot hold, keyed by the hash the logic
  uses: `owner_hash → ShieldedAddress`, `asset_hash → Mint` and `utxo_hash → WalletUtxo`.
  R1CS instantiation records nothing.
- `create_proof_inputs_and_encrypt_with_keys` resolves the `CheckedTransaction` against these records:
  each nonzero input hash to its `WalletUtxo`, and an output's owner and asset hashes to its
  address and `Mint`. It drops the circuit's dummies, since the transaction crate pads with
  its own. The first real input takes SPP input slot 0, and its nullifier is the one the
  circuit derived the blindings from. Each resolved output must hash to the circuit's output
  hash.
- Every output owner comes from a `ShieldedAddress` input or the keys: a spent UTXO has its
  owner's signing and nullifier keys but not the viewing key the encryption needs.
- Both proofs start from the result of `create_proof_inputs_and_encrypt_with_keys` and run in
  parallel.
- The client also holds what the circuit does not see: Merkle proofs and leaf indexes,
  nullifier data and owner signers, and recipient viewing keys.
- Encryption, owner tags and the SPP proof input types come from `zolana_transaction`, the same
  code a wallet's plain transfer uses.

## SDK modules

zolana-program follows the same split:

| Path | Contents |
| --- | --- |
| `zolana_program` | What the client and the prover use: `TxContext`, `Owner`, `Bytes`, `ProgramOwner`, `DataUtxo`, `ZkProgram`, `Groth16Prover`, `ProofResult`, the Groth16 types and their `ProvingKey`, `VerifyingKey` and `Proof` aliases, `CircuitError`, `ClientError`, `ProverError`, their kinds and `SourceLocation`. |
| `zolana_program::circuit` | The DSL: `CircuitVar`, `Uint`, `U8`, `U16`, `U32`, `U64`, `U128`, `Bool`, `Field`, `CircuitSystem`, `ConstraintSystem`, `Assert`, `Bits`, `Select`, `one_hot`, `select_index`, `is_in`, `assert_in`, `from_bits_le`, `constant`, `zero`, `value`, `poseidon`, `Bytes`, `Asset`, `OwnerKey`, `Owner`, `TxContext`, `Utxo`, `TokenUtxos`, `DataUtxo`, `UtxoTrait`, `ConfidentialTransaction`, `CheckedTransaction`, `PublicInputs`, `DataHash`, `UtxoData`, `Circuit`, and the diagnostics `CircuitLabel`, `LabelKind`, `VariableRole`, `FailedConstraint`, `CircuitSize`. |
| `zolana_program::testing` | Feature `client`: `constraint_labels`, `check_tampered` and `check_private_variables`. |
| `zolana_program::conversion` | Between the two: `ProofInput`, `FromCircuit`, `Placeholder`, `Dummy`, `instantiate_padded`, `placeholders`, `Allocator`, `Records`, and bytes to fields and back. |

Everything a future macro derives can also be written by hand, so `conversion` stays public.
A feature may gate it later.

## Setup and features

- `Groth16Prover::new_with_test_setup` synthesizes the circuit from the program's
  `Placeholder`. Setup never evaluates the values, so the keys depend only on the type, and a
  circuit's structure must not depend on its input values. The fixed seed makes the keys
  reproducible; the setup is insecure either way. `Groth16Prover::new` runs the same synthesis
  on loaded keys and refuses keys of another circuit. `TokenUtxos::new_mut` and `new_close`
  take an array of `N` inputs, so a circuit that spends more UTXOs is another `N`, with other
  keys. A bounded `Vec` field's placeholder fills all `N` slots, so its keys are those of the
  `[WalletUtxo; N]` field it pads to. One set of keys pairs with every SPP shape the real
  UTXOs fit.
- zolana-program has two features:

  | Feature | Contents |
  | --- | --- |
  | `client` | The native run, the SPP proof inputs, loading a proving key, proving. |
  | `setup` | The test setup, writing the proving key, exporting the verifying key as a program constant marked `InsecureTest`. |

  The input types, the UTXO types, `ConfidentialTransaction`, `circuit` and R1CS synthesis
  compile without either. Both are on by default. A wallet that does not generate keys
  depends on zolana-program with `default-features = false, features = ["client"]`.

## Tests

Each test builds its inputs inline. Shared helpers only create keypairs and spendable UTXOs.

## Out of scope for the PoC

- A macro that rejects logic that branches on values.
- A derive macro on the client types that generates their `circuit` module types and the
  `ProofInput`, `FromCircuit`, `DataHash` and `UtxoData` impls.
