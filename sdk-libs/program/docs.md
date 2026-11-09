# Zolana program SDK reference

The API of `spr-program`'s ZK program surface: the input derives, the state types, the
circuit operations from `spr-circuit`, the client, the on-chain verifier, the WASM exports and
the CLI. [`README.md`](README.md) walks through a program end to end with the
[timelock escrow](../../sdk-tests/timelock-escrow) example.

A ZK program is a Solana program with Groth16 circuits written in Rust and compiled by
[Xark](https://github.com/ananas-block/xark/tree/cccbf88c527259620c441c1118014c749ecd582b).
Each circuit checks a private state change and binds it to an SPP transaction through the
transaction's `private_tx_hash`.

## Development of a ZK program

1. **Program and circuits**
   1. Define the state types stored in UTXOs (`UtxoState`).
   2. Define each instruction's private and public inputs (`ZkProgram`, `ClientInputs`,
      `PublicInputs`).
   3. Implement `execute`: the checks, transfers and transaction assembly.
   4. Implement the Solana instruction that recomputes the public inputs, verifies the proof
      and invokes SPP.
2. **Build:** `zolana build-zk-program -p <crate>` compiles the circuits with Xark, generates or
   reuses the keys, writes the verifier modules, builds the WASM package and the SBF program.
3. **Client**
   1. Decode state UTXOs.
   2. Fill the generated client inputs and run `prepare` (Rust) or `<program>Transaction`
      (WASM), which runs `execute` natively and builds the SPP transaction.
   3. Prove the program with Xark and the SPP transaction with the SPP prover.
   4. Send the program instruction. The program verifies the program proof, and SPP verifies
      its own proof and updates the trees.

## Glossary

| # | Term | Definition |
| --- | --- | --- |
| 1 | ZK program | A Solana program that verifies circuit proofs before invoking SPP. |
| 2 | SPP | The shielded pool program, which verifies transaction proofs and applies private transfers and UTXO state changes. |
| 3 | SPP proof | The proof SPP verifies for UTXO spends and transaction balances. |
| 4 | Program | A struct with `private` and `public` inputs that derives `ZkProgram`. Each program is one circuit, one verifying key and one verifier module. |
| 5 | `execute` | The program's inherent method that builds and checks its transaction. It runs natively on the client and is compiled into the circuit. |
| 6 | Private inputs | Values the client supplies and the Solana program does not see. |
| 7 | Public inputs | Values the Solana program recomputes. They hash with the transaction hash into the public hash, the circuit's only public input. |
| 8 | Proof inputs | The flat map of named input values the Xark prover takes: every leaf of the program under `program.` and `public_hash`. |
| 9 | State UTXO | A UTXO whose data hash commits to a program state. |
| 10 | Circuit artifacts | Xark's compiled circuit (`circuit.xbc`), its input schema, source map and digest, per program under `<target>/zk/<crate>/<program>/`. |
| 11 | Proving key, verifying key | `pk.bin` and `vk.bin` from a Groth16 setup over the circuit. Each program has its own pair. |
| 12 | Verifier module | Generated Rust in the program's `src/verifier/`: the verifying key and the `Verifier` the instruction calls. |
| 13 | WASM package | The program crate built for JavaScript: transaction construction, state decoding, proof conversion and Xark's prover. |
| 14 | Transaction context | `TxContext`: the blinding seed and the output tree a transaction uses. |

## Inputs

### `#[input]`

`spr_program::input` is Xark's attribute. It implements `xark::Input` for a struct (how its
values map to proof inputs) and derives `Clone`, `Copy` and `Debug` unless the struct lists
them. Every program, input struct and state is an `#[input]`. An `#[input]` field is any
`Input` type: `Field`, `u8` to `u128`, `bool`, fixed-size arrays, `ArrayVec<T, N>`, the
protocol types (`Utxo`, `TxContext`, `UtxoOwner`, `SigningPubkey`, `ShieldedAddress`) and
other `#[input]` structs.

### `ZkProgram`

```rust
#[input]
#[derive(ZkProgram)]
#[zk_program(path = "circuits::Escrow")] // optional; this is the default
pub struct Escrow {
    pub private: EscrowPrivateInputs,
    pub public: EscrowPublicInputs,
}

impl Escrow {
    pub fn execute(&self) -> Result<CheckedTransaction, CircuitError> { /* ... */ }
}
```

- The struct has exactly the fields `private` and `public` and no generic parameters.
- The program name is the struct name in snake case (`Escrow` -> `escrow`). It names the
  artifact directory, the verifier module and the circuit.
- `path` is the program's path from the crate root, which the generated Xark entry uses.
  The default is `circuits::<Name>`.
- With `client`, it generates `<Name>Client { private, public }`, whose fields are the inputs'
  client types, and
  `<Name>Client::prepare(self, sender: &ShieldedAddress, payer: Address) -> Result<ProgramTransaction, ClientError>`.
  `sender` is the native `spr_keypair::ShieldedAddress` the SPP transaction is sent from.
- With `wasm`, it exports `<name>Transaction(inputs, sender: Uint8Array, payer: string)`.
- `#[zk_program(raw_client)]` generates no client type. The WASM export becomes
  `<name>Transaction(inputs, records, sender, payer)`, where `inputs` is the program in Xark's
  input JSON form and `records` is a `ProgramInputRecords`.
- With `build`, it generates the `__zk_export_<name>` test the CLI runs to discover the program
  and its public input layout.

### `PublicInputs`

Implements `spr_program::circuit::PublicInputs` with
`hash = Poseidon(DataHash::hash(field) for each field, transaction_hash)`, generates
`ClientInputs` for a non-generic struct, and with `build` the public input layout.

| Field type | Hashes as | On-chain type |
| --- | --- | --- |
| `u8` to `u128`, `bool` | the value | `u8` to `u128`, `bool` |
| `Field` | the value | `[u8; 32]`, big-endian |
| `UtxoOwner` | its owner hash | `[u8; 32]` |
| `ShieldedAddress` | `Poseidon(owner hash, hash_bytes(viewing key))` | `[u8; 32]`, from `verifier::address_hash` |

A program has at most 11 public fields, so that they and the transaction hash fit one Poseidon
hash of 12 inputs (`MAX_POSEIDON_INPUTS`). A public field is not a byte array: the circuit
hashes `[u8; N]` with `hash_bytes`, which the generated verifier does not reproduce, so the
build refuses it.

### Client inputs

`ClientInputs` derives `<Name>Client` and
`ClientInputs::from_client(client, &mut InputRecords) -> Result<Self, ClientError>`. Each field
maps by its type:

| Circuit type | Client type (Rust) | TypeScript | Conversion |
| --- | --- | --- | --- |
| `TxContext` | `TransactionOptions` | `TransactionOptions` | `into_context`: a random blinding seed when none is given. |
| `Utxo` | `WalletUtxo` | `WalletUtxo` | `InputRecords::utxo`, which checks the commitment. |
| `ArrayVec<Utxo, N>` | `Vec<WalletUtxo>` | `WalletUtxo[]` | `InputRecords::utxos::<N>`: at most `N`, padded with dummies. |
| `ArrayVec<T, N>` | `Vec<T>` | `T[]` | `InputRecords::bounded::<T, N>`: at most `N`, padded with `T::padding()`. `T` is taken as is, so it must be a plain type (the integers row). |
| `ShieldedAddress` | native `spr_keypair::ShieldedAddress` | `Uint8Array` | `InputRecords::address`, which records its viewing key. |
| `Asset` | `spr_transaction::Mint` | `Mint` | `InputRecords::asset`, which records the mint so outputs of that asset can name it; an address already recorded with another asset ID is refused. |
| `Field` | `Field` | `string` | none; in JavaScript a canonical decimal, refusing `"01"` and values at or above the modulus. |
| `UtxoOwner`, `SigningPubkey` | the same type | the same type | none. |
| `u8`..`u128`, `i8`..`i128`, `usize`, `isize`, `bool`, `String`, and arrays and tuples of them | the same type | the same type | none; `u64` and `u128` are `bigint` in TypeScript. |
| another struct without generic arguments | `<Type>Client` | `<Type>Client` | its own `ClientInputs`. |

Types are matched by the last segment of their path. Each protocol type converts to its
`spr_program` type, so a type that only shares its name fails to compile at the field, and an
alias of a protocol type under another name is taken for another struct. Any other type is refused, among them an array,
tuple or `ArrayVec` holding a type from another row, and `Option`, `Vec` or generic types:
each would pass its items to the circuit without their conversion.

The `#[client]` attribute is refused: every conversion follows from the type. When every
field maps to itself, the derive also implements `From<Name> for NameClient`, which the
escrow uses to pass decoded `EscrowTerms` back as a private input (`terms.into()`). With
`wasm`, client objects reject unknown fields.

## State

### `UtxoState`

```rust
#[input]
#[derive(Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState, spr_program::ClientInputs)]
pub struct EscrowTerms {
    pub creator: UtxoOwner,
    pub unlock: u64,
}
```

`UtxoState` generates:

- `hasher::Discriminator`: the first 8 bytes of `sha256("account:" || type name)`.
- `circuit::DataHash`: `Poseidon(discriminator as u64, DataHash::hash(field)...)`, at most 11
  fields. `DataHash` is implemented for `Field`, `u8` to `u128`, `bool`, `UtxoOwner`,
  `ShieldedAddress`, `[u8; N]` (`hash_bytes`) and every `UtxoState`.
- `EncryptionCodec` over Borsh, unless `#[utxo_state(custom_codec)]`.
- `circuit::UtxoData`, which lets a `DataUtxo<S>` register the state's encoded bytes as output
  data.
- `hasher::DataHasher` (native build), the same hash as bytes, which client decoding and
  compressed accounts use.
- With `wasm`, for a non-generic state, `<state>DataUtxo(walletUtxo)`, which returns
  `DataUtxo<State>` or throws `ClientError.DataHashMismatch`. The state's JS type is a
  generated copy with the same name, camelCase fields and the state's doc comments, so the
  state itself needs no serde or tsify derives. A `Field` is a decimal string and a byte
  array a `Uint8Array`; any other field type must implement `serde::Serialize` and
  `tsify::Tsify`, as the integers, `bool` and `UtxoOwner` do. A `ShieldedAddress` or nested
  state field has neither, so such a state has no JS binding and does not compile with
  `wasm`.

A data UTXO's data hash is `Poseidon(DATA, state hash)`, or
`Poseidon(UNIQ, address, state hash)` for a `UniqueDataUtxo`.

### Encryption payload

`EncryptionCodec` controls the plaintext an output's encrypted `utxo_data` carries and
reconstructs the state after decryption. It is separate from the state's `BorshSerialize` and
`BorshDeserialize`.

```rust
pub trait EncryptionCodec: Sized {
    fn serialize_for_encryption(&self) -> borsh::io::Result<Vec<u8>>;
    fn deserialize_after_decryption(bytes: &[u8]) -> borsh::io::Result<Self>;
}
```

For a smaller payload, add `#[utxo_state(custom_codec)]` and implement the trait. Omitted
fields are reconstructed from the payload or constants of the type. The SDK's
[browser test program](tests/wasm/program/src/state.rs) encrypts `count` and recomputes
`doubled`:

```rust
#[input]
#[derive(Default, PartialEq, Eq, BorshSerialize, BorshDeserialize, UtxoState)]
#[utxo_state(custom_codec)]
pub struct CompactCounter {
    pub count: u64,
    pub doubled: u64,
}

impl EncryptionCodec for CompactCounter {
    fn serialize_for_encryption(&self) -> std::io::Result<Vec<u8>> {
        borsh::to_vec(&self.count)
    }

    fn deserialize_after_decryption(bytes: &[u8]) -> std::io::Result<Self> {
        let count = u64::try_from_slice(bytes)?;
        let doubled = count.checked_mul(2).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "doubled count overflows")
        })?;
        Ok(Self { count, doubled })
    }
}
```

- Before accepting an output, the client encodes the state, decodes it again and compares the
  two state hashes. A payload that does not reconstruct the committed state fails with
  `CircuitErrorKind::InvalidInput("state encoding changes its commitment")`, an error named
  `CircuitError` with code `PROGRAM_CIRCUIT_ERROR` in WASM. These checks run on the client and
  add no constraints.
- After decryption, `DataUtxo<T>::try_from` checks the reconstructed state against the UTXO
  commitment.
- A decoder must consume the whole payload and refuse trailing bytes.
- `#[borsh(skip)]` on a field is refused with the default codec, since it would change the
  ordinary Borsh form too. Use a custom codec instead.
- When a custom payload format changes incompatibly, version it and keep the decoder for
  existing UTXOs. The SDK does not infer payload versions or fall back to Borsh.

### Manual implementation

A state without `UtxoState` implements the same traits by hand, with the same hash in the
circuit and natively. For a counter:

```rust
use borsh::{BorshDeserialize, BorshSerialize};
use spr_program::{
    circuit::{DataHash, UtxoData},
    hasher::{DataHasher, Discriminator, HasherError},
    input, poseidon, CircuitError, EncryptionCodec, Field, UtxoOwner,
};

#[input]
#[derive(Default, BorshSerialize, BorshDeserialize)]
pub struct Counter {
    pub owner: UtxoOwner,
    pub count: u64,
}

impl Discriminator for Counter {
    // The first eight bytes of SHA-256("account:Counter").
    const DISCRIMINATOR: [u8; 8] = [0xff, 0xb0, 0x04, 0xf5, 0xbc, 0xfd, 0x7c, 0x19];
}

impl DataHash for Counter {
    fn hash(&self) -> Result<Field, CircuitError> {
        poseidon(&[
            Field::from(u64::from_be_bytes(Self::DISCRIMINATOR)),
            DataHash::hash(&self.owner)?,
            DataHash::hash(&self.count)?,
        ])
    }
}

impl EncryptionCodec for Counter {
    fn serialize_for_encryption(&self) -> std::io::Result<Vec<u8>> {
        borsh::to_vec(self)
    }

    fn deserialize_after_decryption(bytes: &[u8]) -> std::io::Result<Self> {
        Self::try_from_slice(bytes)
    }
}

impl UtxoData for Counter {}

#[cfg(not(xark))]
impl DataHasher for Counter {
    fn hash(&self) -> Result<[u8; 32], HasherError> {
        let hash = DataHash::hash(self).map_err(|_| HasherError::InvalidNumFields)?;
        Ok(spr_program::to_bytes(&hash))
    }
}
```

There is no blanket `EncryptionCodec` for Borsh types, so each state chooses its encryption
form.

### Where state is kept

A state UTXO's data hash commits to the full state. The state itself travels as the output's
encrypted `utxo_data`, or for a `DataUtxo<Field>` with a raw hash, wherever the application
keeps it. The data must be enough to recompute the hash: if it is lost, the UTXO and the funds
that depend on it cannot be spent.

## Circuit operations

`spr_program::circuit` re-exports `spr-circuit`'s protocol module: the types and operations
`execute` uses. They are plain Rust over `Field`, integers and byte arrays: the same code runs
natively and compiles into the circuit. Amounts are `u64`, assets 32-byte mint addresses
(`Asset`, all zeros for SOL), and public transfer accounts 32-byte account addresses. An
output's mint must be on record when the client finalizes the transaction: a spent UTXO
records its own, and an `Asset` client input records one no input carries.

### Values and hashing

| Name | What it is |
| --- | --- |
| `Field` | A BN254 scalar (Xark's). `+`, `-`, `*`, `pow` by a constant, `==`. `to_decimal`, `from_be_bytes`; `spr_program::from_bytes`, `to_bytes` and `from_decimal` convert canonically in the native build. |
| `poseidon(&[Field]) -> Result<Field, CircuitError>` | The SPP Poseidon over 1 to 12 inputs, with light-poseidon's parameters. |
| `hash_bytes(&[u8]) -> Result<Field, CircuitError>` | Bytes packed into 31-byte big-endian chunks folded with Poseidon. The length belongs to the hash domain. |
| `nonzero_hash_chain(&[Field])` | The chain `private_tx_hash` takes over the input and output hashes; later zeros are skipped. |
| `SigningPubkey` | An owner tag (`0x53`, `S`) and 32 key bytes. `identity()` is `hash_bytes(tag \|\| key)`, the value `solana_owner_identity` computes on chain. |
| `UtxoOwner` | A `SigningPubkey` and a nullifier public key. `hash()` is the owner hash. `key()`, `nullifier_pk()`; natively `from_preimage(tag, key, nullifier_pk)` and `preimage()`. |
| `ShieldedAddress` | A `UtxoOwner` and a 33-byte viewing public key. `hash()` commits to both; it derefs to its `UtxoOwner`. |
| `ArrayVec<T, N>` | Exactly `N` slots: the given items, then `T::padding()`. `ArrayVec::new(items)` refuses more than `N` with `TooManyItems`. It derefs to `[T]`. |
| `PaddedInput` | The padding value of an `ArrayVec` item: `Utxo::dummy()` for `Utxo`, `0` for `u64`. |
| `require(bool)`, `require_eq(a, b)` | A constraint in the circuit build. Natively the first failure becomes `RequirementFailed` inside `checked(|| ...)`, which the generated `prepare` and the WASM builders use, and panics outside it. Call `spr_program::checked` around `execute()` when running it yourself. |

### `Utxo`

A spent UTXO's preimage: `domain`, `owner`, `asset`, `amount`, `blinding`, `data_hash`,
`ring_data_hash`, `ring_program_id`, `tree_id` and `meta` (`UtxoMeta`: the nullifier and the
latest tree, which the SPP proof constrains). `Utxo::dummy()` is a dummy-domain slot that adds no
hash and no amount. `hash()` is the UTXO commitment. Program UTXOs use the default ring.

### `TokenUtxos`

Plain UTXOs of one owner and asset.

```rust
impl TokenUtxos {
    // No inputs; one output for what is transferred in.
    pub fn new_init(owner: &UtxoOwner, asset: &[u8; 32]) -> Self;

    // Spends every real input and outputs the change. Dummy slots add nothing. Real inputs
    // must share owner and asset and hold no data.
    pub fn new_mut(inputs: &[Utxo]) -> Result<Self, CircuitError>;

    // Allows all inputs to be dummies, using this owner and asset; real inputs must match.
    // Call before any balance operation.
    pub fn with_optional(self, owner: &UtxoOwner, asset: &[u8; 32]) -> Self;

    // Keeps a real output at a zero balance instead of an empty output.
    pub fn with_zero_output(self) -> Self;

    // No output; the balance must end at zero and incoming transfers are refused.
    pub fn close(self) -> Self;
}
```

- `new_mut` requires at least one real input when the transaction registers it, unless
  `with_optional` was called.
- A `TokenUtxos` output at a zero balance is an empty output when every output after it is
  also a zero-balance `TokenUtxos` output: it keeps its slot and derived blinding, enters
  `private_tx_hash` as 0 and creates no zero-amount UTXO. Register change that may reach zero
  last.

### `UtxoTrait`

The value operations `TokenUtxos`, `DataUtxo` and `UniqueDataUtxo` share:

```rust
pub trait UtxoTrait {
    fn owner(&self) -> UtxoOwner;
    fn asset(&self) -> [u8; 32];
    // The balance; it must fit 64 bits.
    fn amount(&self) -> Result<u64, CircuitError>;
    // Requires an open destination of the same asset and a sufficient balance.
    fn transfer(&mut self, destination: &mut impl UtxoTrait, amount: &u64) -> Result<(), CircuitError>;
    fn transfer_all(&mut self, destination: &mut impl UtxoTrait) -> Result<(), CircuitError>;
    // A public deposit from `source`, a non-zero amount.
    fn deposit(&mut self, amount: &u64, source: &[u8; 32]) -> Result<(), CircuitError>;
    // A public withdrawal to `destination`, a non-zero amount within the balance.
    fn withdraw(&mut self, amount: &u64, destination: &[u8; 32]) -> Result<(), CircuitError>;
    // Withdraws the whole, non-zero balance and returns it.
    fn withdraw_all(&mut self, destination: &[u8; 32]) -> Result<u64, CircuitError>;
}
```

A deposit or withdrawal account is the SOL account for SOL and the token account for an SPL
mint. Value moved by `transfer` must end in a UTXO the transaction registers; `check` refuses
value that leaves or enters the registered UTXOs.

### `DataUtxo<S>`

A state UTXO with data of type `S` and a balance. It derefs to `S`.

```rust
impl<S: Default> DataUtxo<S> {
    // Default state, zero SOL, no input.
    pub fn new_init(owner: &UtxoOwner) -> Self;
}

impl<S: DataHash + Clone> DataUtxo<S> {
    // Checks `input.data_hash == Poseidon(DATA, state.hash())` and spends the input.
    pub fn new_mut(input: &Utxo, state: &S) -> Result<Self, CircuitError>;
}

impl<S> DataUtxo<S> {
    // Sets the asset of a new, unused UTXO.
    pub fn with_asset(self, asset: &[u8; 32]) -> Result<Self, CircuitError>;
    // No output; the balance must end at zero and incoming transfers are refused.
    pub fn close(self) -> Self;
}

impl DataUtxo<Field> {
    // An application-provided data hash, without DATA wrapping and without output data.
    pub fn new_init_with_hash(owner: &UtxoOwner, hash: &Field) -> Self;
    pub fn new_mut_with_hash(input: &Utxo, hash: &Field) -> Result<Self, CircuitError>;
}
```

A `DataUtxo` output is a real UTXO even at a zero balance, because it holds state.

### `UniqueDataUtxo<S>`

A state UTXO at an address derived from its owner and a seed, so one address holds the state.
It derefs to `S`.

```rust
impl<S: Default> UniqueDataUtxo<S> {
    // Derives the address, reserves it in the transaction and starts with default state.
    pub fn new_init(owner: &UtxoOwner, seed: &Field) -> Result<Self, CircuitError>;
}

impl<S: DataHash + Clone> UniqueDataUtxo<S> {
    // Checks `input.data_hash == Poseidon(UNIQ, address, state.hash())` and spends the input.
    pub fn new_mut(input: &Utxo, address: &Field, state: &S) -> Result<Self, CircuitError>;
}

impl<S> UniqueDataUtxo<S> {
    pub fn with_asset(self, asset: &[u8; 32]) -> Result<Self, CircuitError>;
    pub fn address(&self) -> Field;
    // Leaves a zero-balance tombstone with data hash Poseidon(CLSD, address).
    pub fn close(self) -> Self;
    // No output; the balance must end at zero.
    pub fn burn(self) -> Self;
}
```

The output data is `address || encoded state`. Include the program id and an account
identifier in the seed to separate applications and accounts.

### `NewAddress`

An address reservation without a state output. `UniqueDataUtxo::new_init` includes its own.

```rust
impl NewAddress {
    // The owner must be a PDA owner (nullifier key Poseidon(0)).
    pub fn new(owner: &UtxoOwner, seed: &Field) -> Result<Self, CircuitError>;
    pub fn address(&self) -> Field;
}
```

### Transactions

```rust
pub struct TxContext {
    pub blinding_seed: Field,
    pub output_tree_id: u16,
    pub uses_output_tree_id: bool,
}

pub trait PublicInputs {
    fn hash(&self, transaction_hash: &Field) -> Result<Field, CircuitError>;
}

pub trait TransactionItem {
    fn register<P: PublicInputs>(self, transaction: &mut ConfidentialTransaction<'_, P>);
}

impl<'a, P: PublicInputs> ConfidentialTransaction<'a, P> {
    pub fn new(context: &'a TxContext, public: &'a P) -> Self;
    // Keeps dummy input slots in the SPP transaction instead of compact padding.
    pub fn with_dummy_padding(self) -> Self;
    // Registers a TokenUtxos, DataUtxo<S: UtxoData>, DataUtxo<Field>,
    // UniqueDataUtxo<S: UtxoData> or NewAddress. Errors surface in `check`.
    pub fn with(self, item: impl TransactionItem) -> Self;
    pub fn check(self) -> Result<CheckedTransaction, CircuitError>;
}

impl CheckedTransaction {
    pub fn private_tx_hash(&self) -> &Field;
    pub fn transaction_hash(&self) -> &Field;
    pub fn public_hash(&self) -> &Field;
}
```

`check`:

1. Requires that transfers moved no value out of or into the registered UTXOs.
2. Orders the input slots: address reservations first, then spent UTXOs with real ones before
   dummies. It requires at least one slot; the first slot's nullifier is the transaction's
   first nullifier.
3. Selects the output tree: `output_tree_id` when `uses_output_tree_id`, else the first spent
   UTXO's latest tree, which must be known.
4. Derives each output's blinding from the first nullifier, the blinding seed and the slot,
   and hashes the outputs in registration order.
5. Computes `private_tx_hash = Poseidon(chain(inputs), chain(outputs), chain(addresses),
   private_tx_blinding)`, the transaction hash (`private_tx_hash`, or
   `Poseidon(private_tx_hash, chain of public transfer hashes)` when there are public
   transfers) and the public hash `P::hash(transaction_hash)`.

`CheckedTransaction` also exposes the slots it resolved (`inputs`, `addresses`, `outputs`,
`public_transfers`, `output_tree_id`, `blinding_seed`, `first_nullifier`,
`preserve_input_slots`), which `InputRecords::finalize` reads.

### Errors

```rust
pub enum CircuitErrorKind {
    RuleBroken(&'static str),
    RequirementFailed { file: &'static str, line: u32, column: u32 },
    TooManyItems { capacity: usize, found: usize },
    UnsupportedHashArity(usize),
    NonCanonicalField,
    InvalidInput(&'static str),
}
```

`CircuitError::kind()` returns the kind and `broken_rule()` the rule of a `RuleBroken`. The
only `RuleBroken` the protocol returns is `"a transaction spends at least one input"`.

## Client

Feature `client`, native build only.

### `TransactionOptions`

```rust
pub struct TransactionOptions {
    pub blinding_seed: Option<[u8; 32]>, // None: a random seed
    pub output_tree_id: Option<u16>,     // None: the first spent UTXO's latest tree
}
```

`into_context()` returns the `TxContext`. In TypeScript it is
`{ blindingSeed?: Uint8Array; outputTreeId?: number }`.

### `InputRecords`

The native values behind the circuit values, which `finalize` resolves the checked
transaction against.

| Method | What it does |
| --- | --- |
| `new()` | Empty records. |
| `address(&mut self, &ShieldedAddress) -> Result<circuit::ShieldedAddress, ClientError>` | Converts a native address and records its viewing key for outputs to its owner. |
| `asset(&mut self, Mint) -> [u8; 32]` | Records a mint and returns its asset address. |
| `utxo(&mut self, &WalletUtxo) -> Result<Utxo, ClientError>` | Converts a wallet UTXO, checks its commitment and records it. A dummy wallet UTXO becomes `Utxo::dummy()`. |
| `utxos::<N>(&mut self, &[WalletUtxo]) -> Result<ArrayVec<Utxo, N>, ClientError>` | At most `N`, else `TooManyInputs`. |
| `bounded::<T, N>(Vec<T>) -> Result<ArrayVec<T, N>, ClientError>` | At most `N`, else `TooManyInputs`. |
| `context(&[u8; 32], Option<u16>) -> Result<TxContext, ClientError>` | A `TxContext` from a seed and an optional output tree. |
| `finalize(&self, &CheckedTransaction, sender, payer) -> Result<FinalizedTransaction, ClientError>` | Builds the SPP transaction and refuses it unless its padding-independent private hash, transaction hash and committed output hashes equal the circuit's. |
| `create_program_transaction(&self, program: &P, checked, sender, payer) -> Result<ProgramTransaction, ClientError>` | `finalize`, plus the proof inputs and the public hash. |

`finalize` resolves each output owner to a recorded address with the same owner hash, or to
the sender, and refuses an owner with none or with two. It resolves each output asset to a
recorded mint (all zeros is SOL). Dummy input slots kept by `with_dummy_padding` sit in the
first spent UTXO's tree, or the address tree for an address-only transaction. The SPP
transaction pads to the smallest SPP shape that fits.

### `ProgramTransaction` and `ProgramProofInputs`

```rust
pub struct ProgramTransaction {
    pub finalized: FinalizedTransaction, // the SPP transaction; encrypt_with_keys for its proof
    pub proof_inputs: ProgramProofInputs,
    pub public_hash: [u8; 32],
}

impl ProgramProofInputs {
    pub fn new<P: xark::Input>(program: &P, public_hash: Field) -> Self;
    pub fn encoded(&self) -> BTreeMap<String, String>; // name -> decimal value
    pub fn to_json(&self) -> serde_json::Value;
}
```

`ProgramProofInputs` implements Xark's `ProveInputs`, so
`xark::prover::circuit_at(artifact_dir).prove(inputs)` proves it, and `.check(inputs)` checks
it against the compiled circuit without proving.

### `ClientError`

```rust
pub enum ClientError {
    InvalidInput(String),
    Circuit(CircuitError),
    DataHashMismatch,
    TooManyInputs { capacity: usize, found: usize },
}
```

`Circuit` is the program's own logic refusing the inputs, for example a failed `require`.
`InvalidInput` is a value the client cannot convert or a transaction the SPP builder refuses.
`DataHashMismatch` is a data UTXO whose state does not match its commitment.

### `DataUtxo<T>` (client)

```rust
pub struct DataUtxo<T> {
    pub utxo: WalletUtxo,
    pub data: T,
    pub address: Option<[u8; 32]>, // Some for a UniqueDataUtxo
}
```

`DataUtxo::<T>::try_from(wallet_utxo)` decodes the UTXO's data with `T`'s `EncryptionCodec`,
accepts a `DATA` state or a `UNIQ` state prefixed by its address, and checks the UTXO hash. It
is not the circuit's `spr_program::circuit::DataUtxo`.

### `ProgramOwner`

A program PDA as a UTXO owner, under the fixed zero nullifier key.

| Method | What it does |
| --- | --- |
| `new(pda)`, `find(seeds, program_id)` | The owner of a PDA. |
| `pda()`, `public_key()`, `owner_hash()` | The PDA and its owner commitment. |
| `nullifier_key()`, `nullifier_pubkey()` | The zero nullifier key a PDA's UTXOs use. |
| `address(viewing_pubkey) -> ShieldedAddress` | The shielded address outputs to the PDA are encrypted to. |
| `decrypt_data_utxos::<T>(viewing_key, transactions, assets)` | Decrypts the PDA's outputs, keeps the data UTXOs that decode as `T`, minus those the same transactions spend. |
| `input(output, tree_id, leaf_index) -> WalletUtxo` | Turns an output the program's transaction created into a spendable input. |

### Proofs (`spr_program::proof`)

| Function | What it does |
| --- | --- |
| `compressed_proof(&[u8]) -> Result<CompressedProof, String>` | A Xark proof (compressed arkworks bytes) as the 128-byte `CompressedProof` an instruction carries. |
| `SolanaVerifyingKey::from_xark(&[u8])`, `as_key()` | A Xark `vk.bin` as the `Groth16Verifyingkey` `verify_groth16` takes. |
| `check_proving_key(&[u8], &[u8; 32])` | Compares the exact proving-key bytes with a trusted SHA-256 before loading them. |
| `snarkjs_proof`, `snarkjs_verifying_key` | A proof and a verifying key as snarkjs JSON. |

`CompressedProof { a: [u8; 32], b: [u8; 64], c: [u8; 32] }` needs no feature and has a wincode
layout.

## On-chain verifier

Feature `verifier`, `no_std`. `spr_program::verifier`:

| Name | What it is |
| --- | --- |
| `VerifyError` | `PublicInputs` (a value cannot be encoded) or `Proof` (malformed or invalid). Converts into `ProgramError::InvalidInstructionData` and `InvalidArgument`. |
| `Field<'a>` | A public field's on-chain value: `Integer(u128)`, `Bool(bool)`, `Hash(&[u8; 32])` or `Array(&[Field])`. Not the circuit's `spr_program::Field`. |
| `public_hash(&[Field], &[u8; 32])` | `Poseidon(fields..., transaction_hash)`, the circuit's `PublicInputs::hash`. |
| `address_hash(owner_hash, viewing_pubkey: &[u8; 33])` | The public form of a `ShieldedAddress`. |
| `verify_groth16(proof, public_hash, key)` | Verifies a ZK program proof, whose one public input is the public hash. |
| `verify_groth16_inputs::<N>(proof, &[[u8; 32]; N], key)` | Verifies a proof with `N` public inputs, for a plain circuit. Refuses a key with a commitment. |
| `integer`, `boolean`, `pack_be` | Public input encodings for hand-written verifiers. |

`spr_program::transaction_hash(private_tx_hash, transfers)` and `spr_program::PublicTransfer`
(from `spr-instruction`) compute the transaction hash on chain.

A generated `src/verifier/<program>.rs`:

```rust
include!("escrow.vk.rs"); // VERIFYINGKEY, its setup marker, ZOLANA_VK_SHA256, ZOLANA_CIRCUIT_DIGEST

pub struct PublicInputs {
    pub escrow_owner: [u8; 32],
    pub creator_identity: [u8; 32],
}

impl PublicInputs {
    pub fn hash(&self, transaction_hash: &[u8; 32]) -> Result<[u8; 32], VerifyError>;
}

pub struct Verifier<'a> {
    pub proof: &'a CompressedProof,
    pub public_inputs: PublicInputs,
    pub private_tx_hash: &'a [u8; 32],
    pub transfers: &'a [PublicTransfer],
}

impl Verifier<'_> {
    pub fn verify(&self) -> Result<(), VerifyError>;
}
```

Public field types map to `u8`..`u128`, `bool`, `[u8; 32]` for `Field`, `UtxoOwner` and
`ShieldedAddress`. `<program>.vk.rs` from a setup that is not a production ceremony contains a
`compile_error!` unless the crate enables `insecure-test-setup`.

## Build metadata

Feature `build`. `spr_program::build` is what the derives export and the CLI reads:

- `ProgramMetadata { name, rust_type, fields: Vec<(String, PublicFieldKind)> }` and
  `validate()`, which refuses a name, type path or field name that is not a plain Rust
  identifier, more than 11 fields, a byte-array field, and an array of 0 or more than 12 items
  (`MetadataError`).
- `PublicFieldKind`: `Integer { bits }`, `Bool`, `Hash`, `Array { len, item }`.
- `PublicField` (a type's kind) and `PublicInputLayout` (a struct's fields).
- `export_program(name, rust_type, layout)` writes `<name>.json` to `ZOLANA_PROGRAM_EXPORT_DIR`
  when the variable is set.

## WASM exports

Feature `wasm`. The program crate's module exports the generated functions and these:

| Export | What it does |
| --- | --- |
| `<name>Transaction(inputs, sender, payer)` | Converts the client inputs, runs `execute`, finalizes, and returns `{ finalizedTx, proofInputs, publicHash }`. |
| `<state>DataUtxo(walletUtxo)` | Decodes and checks a state UTXO: `{ utxo, data, address? }`. |
| `checkProvingKey(provingKey, expectedSha256)` | Compares proving-key bytes with a trusted digest. |
| `programProof(proof, publicInputs, expectedHash)` | Checks that a Xark proof's single public input is the transaction's `publicHash`, and returns `{ publicInputs, compressedProof }`. Verify the proof with the trusted verifying key first. |
| `compressedProgramProof(proof)` | A Xark proof as the wincode bytes of a `CompressedProof`. |
| `proofInputUtxo(wallet?)`, `proofInputAddress(bytes)`, `proofInputContext({ blindingSeed, outputTreeId })` | Wallet values in Xark's input JSON form, for `raw_client` programs. Without a wallet, a dummy UTXO. |
| `proofToSnarkjs`, `verifyingKeyToSnarkjs` | With `wasm-verify` (`--verifier`). |

With `wasm-prover`, the module also exports Xark's runtime: `ProvingSession`, `VerifyingKey`,
`preloadStreaming`, `proveStreamingPreloaded`, `verify` and the pool support.

Errors from the transaction and decoding functions are `Error`s with a `name` and a `code`:

| `name` | `code` | Cause |
| --- | --- | --- |
| `ClientError.InvalidInput` | `TRANSACTION_INVALID_INPUT` | An input that does not decode or convert, an unknown field, or a transaction the SPP builder refuses. |
| `ClientError.TooManyInputs` | `TRANSACTION_TOO_MANY_INPUTS` | More items than an `ArrayVec` holds. |
| `ClientError.DataHashMismatch` | `TRANSACTION_OUTPUT_DATA_MISMATCH` | A state that does not match its UTXO commitment. |
| `CircuitError.RequirementFailed` | `PROGRAM_REQUIREMENT_FAILED` | A failed `require` or `require_eq` in `execute`. |
| `CircuitError` | `PROGRAM_CIRCUIT_ERROR` | Any other `CircuitError` from `execute`. |

`checkProvingKey` throws `InvalidProvingKeyHash` for a digest that is not 32 bytes and
`KeyChecksumMismatch` for other key bytes. The TypeScript SDK's `bindProgramTransaction`
wraps a thrown error as the `cause` of a `TRANSACTION_PROGRAM_BUILD` `TransactionError`.

## CLI

### `zolana build-zk-program` and `zolana zk compile`

`build-zk-program` runs `zk compile`, then `cargo build-sbf`.

| Flag | Effect |
| --- | --- |
| `-p`, `--manifest-path` | The crate that defines the programs. Outputs go to `<target>/zk/<package>`. |
| `--test` | Reproducible keys from a fixed public seed. Keys are reused while the circuit digest and setup kind are unchanged. |
| `--skip-r1cs` | Reuse compiled circuit artifacts when present. |
| `--skip-keys` | Generate no keys and write no verifier modules. |
| `--skip-wasm` | Build no WASM package. |
| `--check` | Require matching cached keys, compare the regenerated verifier modules with `src/verifier` and fail on a stale, missing or orphaned module, without writing. Builds no WASM or SBF. |
| `--r1cs-features` | Features the circuits build with (default `circuits`). Discovery adds `build-circuits`. |
| `--r1cs-out` | The circuit artifact directory (default `<target>/zk/<package>`). |
| `--wasm-features` | Features of the WASM build (default `wasm`). The CLI adds `spr-program/wasm-prover` unless `--no-prover`, and `spr-program/wasm-verify` with `--verifier`. |
| `--wasm-target web\|nodejs` | The JavaScript environment (default `web`). |
| `--wasm-out` | The WASM package directory (default `<target>/zk/<package>/wasm`). A directory given here, or the default under an `--r1cs-out` directory or behind a symlink, is replaced only when it is missing, empty or `.zolana-zk-package`-marked; the default under the default build directory belongs to the CLI and is always replaced. |
| `--single-threaded` | `threads: false` in `runtime-options.json`. |
| `--no-prover` | Transactions and decoding only, without Xark's runtime; refused when a dependency still pulls in `xark-wasm`. |
| `--verifier` | Adds `proofToSnarkjs` and `verifyingKeyToSnarkjs`. |
| `--wasm-opt` | Runs wasm-opt with the crate's wasm-pack flags. |
| `--skip-sbf`, `--sbf-features`, `--sbf-out-dir` | `build-zk-program` only: the SBF build. |

A WASM package is rebuilt only when its inputs change. Its `.zolana-zk-package` marker records a
digest of the CLI binary, the Rust toolchain, wasm-pack, the `CARGO_BUILD_*`, `CARGO_PROFILE_*`,
`CARGO_TARGET_*` and rustc variables, the workspace and crate manifests and every cargo config
file that applies, the WASM flags and features, the resolved dependency graph, the circuit
artifacts and Xark's pool modules. It also records the SHA-256 of every local source file the
WASM build read, from cargo's dep-info; sources under the cargo home are pinned by the
dependency graph. When all of them match and the package still holds its module, it is left as
it is. A source modified while the build ran, or a dep-info path that is not a readable file,
leaves nothing to compare, so the next compile rebuilds.

A crate opts into generated verifiers by having a `src/verifier` directory. A crate without a
`ZkProgram` builds as one plain Xark circuit and refuses the WASM-package flags.
Its TypeScript client goes to `<target>/zk/<package>/client/<circuit>.ts`, or
`<--wasm-out>/<circuit>.ts`. The client includes its schema and imports
`@blueshift-gg/xark/client`.

### `zolana zk setup`

Generates or reuses the keys of compiled circuits (`--test`, `--out`).

### `zolana zk export-verifier`

```bash
zolana zk export-verifier -p <crate> --checksums trusted-keys.sha256 [--out <artifact dir>]
```

The manifest is in `sha256sum` format and pins every program's `vk.bin`, `pk.bin` and
`metadata.json`, with paths relative to the manifest. Every program is checked, and each
proving key matched to its verifying key, before any file is written. The setup kind comes
from the pinned metadata.

### `zolana vks check`

```bash
zolana vks check --so target/deploy/<program>.so
zolana vks check --program-id <program-id> --rpc-url <rpc-url> --expect trusted-keys.sha256
```

Reads the verifying-key setup markers from a binary or a deployed program and fails on a
binary without markers or with an insecure test setup. `--expect` also fails when a proving
key the manifest lists (a `pk.bin` line) is not embedded. It reads the digests from the
manifest; it does not hash key files.

## Limitations

1. **Fixed shape.** Array lengths and loop bounds are known when the circuit is built. A
   variable number of UTXOs is an `ArrayVec` with dummies.
2. **Branches.** A branch on a private value runs both arms in the circuit, and a requirement
   inside an arm binds only when the arm is taken. Put a check that must always hold before
   the branch. Xark's
   [`docs/subset.md`](https://github.com/ananas-block/xark/blob/cccbf88c527259620c441c1118014c749ecd582b/docs/subset.md)
   lists what the circuit build accepts.
3. **Arithmetic.** `Field` arithmetic wraps around the BN254 modulus. A `uN` input is
   range-checked to `N` bits on entry; use `uN` values with `checked_*` operations or
   `require` where overflow matters.
4. **Trusted setup.** Each circuit needs a Groth16 setup. The CLI's own setups are insecure
   test setups; a deployment uses Xark's ceremony
   ([`docs/trusted-setup.md`](https://github.com/ananas-block/xark/blob/cccbf88c527259620c441c1118014c749ecd582b/docs/trusted-setup.md)).
   Xark has no external audit yet.
5. **Data hash privacy.** A state UTXO's data hash is private and hidden by the UTXO
   commitment's blinding. A program that publishes a data hash must include private
   randomness in the state to keep the state private.
