# Swap Program

The swap program settles a confidential swap between a maker and a taker the maker chooses. The two
agree a price out of band, and the maker commits an order that escrows the
funds it is selling as a shielded UTXO in the Solana Privacy Program (SPP). The taker indexes the order
created with the create transaction, encrypted so only the taker and the maker can read its private terms.

The taker fills the order before it expires, receiving the maker's funds and paying the agreed amount
in return; if the taker declines, the maker reclaims the escrow after expiry.

The taker learns the order and may decline to fill it, but it cannot take the escrowed funds: the
program alone can move the escrow, and only by settling the committed order or refunding the maker
after expiry. Amounts and the price stay private. That a swap was created and later filled or
cancelled is public; filling reveals the taker, while a cancelled order does not.

The swap program is an SPP ZK program: it verifies a small proof of its own swap rules and delegates
the confidential transfer to SPP. It stores no state and owns no accounts.

This document specifies the swap's privacy model, the order terms, the program's instructions, and
its circuits.

## Flow

```mermaid
sequenceDiagram
    participant Maker
    participant Taker
    participant Swap as Swap Program
    participant SPP as Privacy Program

    Note over Maker: 1. Create the order (create_swap)
    Maker->>Swap: create_swap (create proof + SPP transact)
    Swap->>SPP: CPI transact -> change + escrow UTXO (swap utxo_data) + marker UTXO
    Note over SPP: spend maker source UTXO, append change + escrow UTXO + 0-value marker UTXO <br> source_asset_id public, source_amount + order terms private in utxo_data <br> escrow ciphertext encrypted to taker viewing pubkey; marker tagged to taker
    Note over Taker,SPP: taker wallet sync finds the marker (its tag), <br> decrypts the sibling escrow slot -> order opening (terms + blinding)
    Note over Maker: maker can decrypt the escrow slot via the tx viewing key it holds

    Note over Taker: 2a. Fill, before expiry (Taker holds the order opening)
    Taker->>Swap: fill_verifiable_encryption (fill proof + SPP transact)
    Swap->>SPP: CPI transact: escrow + Taker destination UTXO -> destination UTXO to maker + source UTXO to Taker
    Note over SPP: destination UTXO verifiably encrypted to the maker; escrow consumed

    Note over Maker: 2b. Cancel, after expiry
    Maker->>Swap: cancel (cancel proof + SPP transact)
    Swap->>SPP: CPI transact: escrow -> source UTXO back to the maker
    Note over SPP: escrow consumed
```

## Table of Contents

- [Glossary](#glossary)
- [Privacy Model](#privacy-model)
- [Accounts](#accounts)
- [Order Terms](#order-terms)
- [Instructions](#instructions)
  - [create_swap](#create_swap)
  - [fill](#fill)
  - [fill_verifiable_encryption](#fill_verifiable_encryption)
  - [cancel](#cancel)
- [Circuits](#circuits)
  - [Create circuit](#create-circuit)
  - [Fill circuit](#fill-circuit)
  - [Fill verifiable encryption circuit](#fill-verifiable-encryption-circuit)
  - [Cancel circuit](#cancel-circuit)

## Glossary

Types used in this document. Shared SPP types are defined in [spec.md](../../docs/spec.md#glossary).

| Type | Encoding | Definition |
| --- | --- | --- |
| `Address` | `[u8; 32]` | Solana account address. |
| `asset_id` | `u64` | Asset identifier in UTXOs; `1` is SOL, each SPL mint `≥ 2`. The mint→`asset_id` map is the SPP `Asset registry` PDA. See [spec.md](../../docs/spec.md#glossary). |
| `CompressedShieldedAddress` | `[u8; 65]` | `(owner_hash [u8;32], viewing_pk P256Pubkey[33])`. The `viewing_pk` is the verifiable-encryption target. See [spec.md](../../docs/spec.md#shielded-address). |
| `escrow UTXO` | — | The SPP [UTXO](../../docs/spec.md#utxo) holding the source funds: `asset = source_asset_id`, `amount = source_amount`, `owner = escrow-authority PDA` (seeds `[b"escrow_authority"]`), nullifier secret `= 0`, `utxo_data = order terms`. Spendable only by the swap program. See [Order Terms](#order-terms). |
| `marker UTXO` | — | A 0-value SPP [UTXO](../../docs/spec.md#utxo) owned by the taker's shielded address, appended by `create_swap` as the taker's discovery tag; its recipient ciphertext `data` carries a plaintext [`MarkerData`](#create_swap). Unenforced: a wrong marker only means the taker does not index the trade. |
| `MarkerData` | Borsh | `{ maker_address: CompressedShieldedAddress, escrow_utxo_hash: [u8;32] }`, the plaintext `create_swap` writes into the marker output's recipient ciphertext `data`. `escrow_utxo_hash` locates the escrow slot; `maker_address` is the maker's public address, the `create_swap` signer. See [create_swap](#create_swap). |
| `Order terms` | — | The fields committed in the escrow UTXO's `utxo_data` (record tag `0x02`), hashed into the escrow `utxo_hash` via `data_hash`: `destination_asset_id`, `destination_amount`, `maker_address`, `expiry`, `taker_pk_fe`. See [Order Terms](#order-terms). |
| `private_tx_hash` | `[u8; 32]` | Commitment to the SPP `transact` a swap proof authorizes — the binding between a swap proof and the SPP transaction. See [spec.md](../../docs/spec.md#zk-program-interface). |
| `CreateProof` / `CancelProof` / `FillVerifiableEncryptionProof` | `[u8; 128]` / `[u8; 192]` | Groth16 proofs verified by the swap program, each committing the transaction via `private_tx_hash`. `CreateProof` and `CancelProof` are standard Groth16, 128 B; `FillVerifiableEncryptionProof` adds a BSB22 commitment + PoK for its verifiable encryption and is 192 B (verified with `new_with_commitment`). |
| `TransactIxData` | — | SPP `transact` instruction data: the SPP proof, input nullifiers, output UTXO hashes, ciphertexts, and routing. See [spec.md](../../docs/spec.md#transact). |

## Privacy Model

What is public and what is private. The confidentiality is inherited from the SPP confidential
zone; the swap program does not try to hide which action ran.

- **Public:** `maker_address`, the `create_swap` signer, revealed at create; that a `fill_verifiable_encryption` or
  `cancel` ran (and which); `source_asset_id` at create and both `source_asset_id` and
  `destination_asset_id` at resolve (`asset_id`s are SPP public inputs); the escrow UTXO hash at
  create; the order `expiry`, revealed at resolve so the program can check it against the Clock; each
  transaction's SPP output UTXO hashes and ciphertexts; the taker's identity on `fill_verifiable_encryption`, since the
  taker signs the fill transaction.
- **Private:** `price`, `source_amount`, `destination_amount`, and the aggregate volume per asset.
  These live only inside confidential UTXOs and the escrow `utxo_data`; they are not public inputs.
  The taker's identity stays private at create and on cancel, which the taker does not sign; only
  `fill_verifiable_encryption` reveals it.
- **Unlinkable:** SPP hides the link between a created UTXO and its later spend, so an observer
  cannot pair a create with its fill or cancel.

## Accounts

The swap program owns no accounts. The order and its funds are not swap accounts; the escrow UTXO
is a leaf in the SPP trees, moved by CPI. There is no config account and no asset allow-list. The
taker's spread (the gap
between the `source_amount` it receives and the `destination_amount` it pays) is its only
compensation; there is no separate protocol fee.

## Order Terms

The order has no commitment leaf of its own: the escrow UTXO is the order. `create_swap` writes the
order terms into the escrow UTXO's `utxo_data` (record tag `0x02`), and SPP commits them into the
escrow `utxo_hash` through `data_hash` (committed unchecked, interpreted by the swap circuit — see
[spec.md](../../docs/spec.md#utxo)):

```text
order_terms = (
    destination_asset_id,   // asset_id; private until resolve
    destination_amount,     // private; price = destination_amount / source_amount is implicit and private
    maker_address,           // the maker's CompressedShieldedAddress, the create_swap signer (public): receives destination on fill and source on cancel
    expiry,                 // unix seconds; revealed at resolve and checked against the Clock by the program
    taker_pk_fe,     // the designated taker; authorizes fill
    fill_mode,       // which fill instruction may settle this escrow: 3 = fill (derived), 5 = fill_verifiable_encryption
)
data_hash = Poseidon(order_terms)        // enters the escrow utxo_hash directly
```

`fill_mode` binds the escrow to the fill instruction the maker chose: each fill circuit reconstructs
`data_hash` with its own hardcoded `fill_mode`, so settling with the wrong fill yields a mismatched
escrow hash and the proof fails. `cancel` takes `fill_mode` as an unconstrained witness and refunds
either kind.

`source_asset_id`, `source_amount`, and `owner = escrow-authority PDA` are the escrow UTXO's own
SPP fields, already committed in `utxo_hash`. The escrow's owner is the swap escrow-authority PDA
(seeds `[b"escrow_authority"]`) and its nullifier secret is hardcoded to 0, so:

```text
escrow_owner_hash = Poseidon(hash_field(escrow_authority_pda), Poseidon(0))   // a program-wide constant
nullifier         = Poseidon(utxo_hash, blinding, 0)                          // recomputed from the opening
```

Knowledge of the order opening, the order terms plus the escrow `blinding`, is the complete spend
capability: the nullifier binds the `blinding` and the in-circuit opening requires it too, so no
separate owner key exists. The opening is delivered in the create transaction (see
[create_swap](#create_swap)): the escrow output's recipient ciphertext carries the order terms other
than `maker_address`, encrypted to the taker's viewing pubkey, and the maker can decrypt the same
slot via the transaction viewing key it holds. `maker_address` is public, the `create_swap` signer,
so it needs no delivery. But holding the opening is
not by itself enough to move the escrow. SPP spends a PDA-owned UTXO only when the swap program
produces the escrow-authority signer via `invoke_signed`, which it does only through `fill` or
`fill_verifiable_encryption` (constrained to the committed payout) or `cancel` (after expiry, to
`maker_address`); a plain SPP
transfer is impossible by construction. The program derives the PDA via `find_program_address`,
checks it is present among the forwarded SPP accounts, and flips it to a signer inside the SPP CPI to
authorize the escrow spend (the escrow input's `eddsa_signer_index = 2` in the SPP slice `[payer,
tree, escrow_authority, spp_program]`); the PDA holds no data and is never a transaction-level
signer.

`maker_address` is the committed destination for both outcomes: fill pays the destination output
there, cancel returns the source output there. The maker recovers the bought output either from
`fill_verifiable_encryption`'s in-circuit encryption to `maker_address.viewing_pk`, or, under `fill`,
by reconstructing the destination blinding as `Poseidon(escrow_blinding, DOMAIN)` from the escrow
blinding it already holds, so `fill` proves no encryption. Because the destination is
committed, cancel needs no maker signature — any fee payer holding the order opening can trigger the
post-expiry refund and it can only land at `maker_address`.

`expiry` is a unix-seconds value the proof reveals as a public input and the swap program checks
against the Clock sysvar: `fill` and `fill_verifiable_encryption` require `now <= expiry`, `cancel`
requires `now > expiry`. The instructions source the revealed `expiry` differently. Both fills reuse the transact's own
`transact.expiry_unix_ts` field as the order expiry, whereas `cancel` takes the order `expiry` as a
separate instruction-data field distinct from `transact.expiry_unix_ts` (the SPP relayer deadline).
Either way the proof's public `expiry` must equal the committed order term, so neither party can
shift the window.

## Instructions

There are no admin instructions: the program has no config to initialize or update.

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 1 | [create_swap](#create_swap) | 2 | Verify the create proof and CPI SPP `transact` to escrow the source funds into the order's escrow UTXO (swap `utxo_data`). | — | SPP trees (CPI), SPL interface (CPI) | Maker signs (fee payer) |
| 2 | [fill](#fill) | 3 | Verify the fill proof (standard Groth16) and CPI SPP `transact`: spend escrow + the taker's destination UTXO, pay destination to the maker (blinding derived from the escrow blinding, standard output ciphertext) and source to the taker. | escrow_authority | SPP trees (CPI), SPL interface (CPI) | Any fee payer signs; the escrow spend is authorized by the program's escrow-authority PDA signer; the payout is constrained to the committed `maker_address` / `taker_pk_fe` |
| 3 | [fill_verifiable_encryption](#fill_verifiable_encryption) | 5 | Verify the fill proof and CPI SPP `transact`: spend escrow + the taker's destination UTXO, pay destination (verifiably encrypted) to the maker and source to the taker. | escrow_authority | SPP trees (CPI), SPL interface (CPI) | Taker signs (fee payer); the escrow spend is authorized by the program's escrow-authority PDA signer plus the `taker_pk_fe` signature the proof checks |
| 4 | [cancel](#cancel) | 4 | Verify the cancel proof and CPI SPP `transact`: after expiry, spend escrow back to `maker_address`. | escrow_authority | SPP trees (CPI), SPL interface (CPI) | Any fee payer holding the order opening signs; the program's escrow-authority PDA authorizes the escrow spend; destination is the committed `maker_address` |

---

### create_swap

Opens an order. The swap program verifies the [create proof](#create-circuit), then CPIs SPP
[`transact`](../../docs/spec.md#transact) to spend the maker's `source_asset_id` UTXO and append the
escrow UTXO, a UTXO of `source_amount` `source_asset_id` owned by the escrow-authority PDA
(seeds `[b"escrow_authority"]`), carrying the [order terms](#order-terms) in its `utxo_data` (which,
with the PDA owner, makes SPP spend it only through a swap circuit). The transact is 1-in/3-out:
the maker's source UTXO in, and three UTXOs out, a change UTXO (to the maker), the escrow UTXO, and a
0-value marker UTXO owned by the taker's shielded address.

The escrow output's recipient ciphertext (`TransferRecipientPlaintext { asset_id, amount, blinding,
zone_program_id, data }`, with `data` = the order terms other than `maker_address`) is encrypted to
the taker's viewing pubkey, so the taker recovers the private order terms and the escrow `blinding`;
the maker can decrypt the same slot via the transaction viewing key it holds. Those two parties are
exactly who can decrypt the order. `maker_address` is public, the `create_swap` signer, so it is read
from the transaction rather than encrypted in `data`. The program overwrites the marker output's
recipient ciphertext `data` with a plaintext [`MarkerData`](#glossary) `{ maker_address,
escrow_utxo_hash }` (read from transact output index 1), so ordinary wallet sync finds the trade and
can locate the sibling escrow slot to decrypt. The marker is unenforced: a wrong marker means the
taker does not index the trade.

The proof checks that the escrow output's committed terms are well-formed, without revealing them,
and commits the transaction via `private_tx_hash`. `source_asset_id` and `maker_address` (the signer)
are public; `source_amount` and the other order terms are private. The program stores no per-order
account and holds no asset allow-list.

**Accounts**

1. `maker` — spends the source UTXO; signer, writable (fee payer). Consumed by the program; everything
   after it is forwarded verbatim to the SPP `transact` CPI.
2. `tree_accounts` — SPP trees the transact touches; writable.
3. `spl_interface` — SPL interface account for `source_asset_id`; writable.
4. `asset_registry` — SPP `Asset registry` PDA for `source_asset_id`; read.
5. `spp_program` — SPP program (CPI target); must be the last account (the program checks this).

**Instruction data**

```rust
struct CreateSwapIxData {
    /// The create proof; verified by the swap program.
    proof: CreateProof,
    /// Escrowed source asset; public input to the proof and the transact.
    source_asset_id: asset_id,
    /// The maker's own CompressedShieldedAddress. Public input to the create proof
    /// (hashed to a field element) and written into the marker so the taker can fill.
    maker_address: CompressedShieldedAddress,
    /// SPP transact (1-in/3-out): maker source UTXO -> change + escrow UTXO + marker UTXO.
    transact: TransactIxData,
}
```

The maker supplies its own `maker_address`; the payer account is the fee payer and
signer only.

---

### fill

A filler settles the order before expiry with the derived-blinding proof. The swap program verifies
the [fill proof](#fill-circuit) (standard Groth16, no commitment), then CPIs SPP
[`transact`](../../docs/spec.md#transact). Shape and payout match
[`fill_verifiable_encryption`](#fill_verifiable_encryption): 2-in/2-out, escrow + the taker's
`destination_amount` `destination_asset_id` UTXO in, destination to `maker_address` and source to the
taker out. The difference is recovery: the proof fixes the destination blinding to
`Poseidon(escrow_blinding, DOMAIN)`, so the maker reconstructs and spends the bought output from the
escrow blinding and order terms alone, and that output carries an ordinary recipient ciphertext for
wallet discovery rather than a verifiable one. The proof checks no encryption and no taker
signature, so any fee payer may fill; funds still flow only to the committed `maker_address` and
taker, and the escrow's `fill_mode` forbids settling a `fill_verifiable_encryption` escrow this way.
Expiry is read from `transact.expiry_unix_ts` and checked `now <= expiry`, as in
`fill_verifiable_encryption`.

**Accounts**

Identical to [`fill_verifiable_encryption`](#fill_verifiable_encryption), except authorization rests
on the escrow-authority PDA signer alone (no `taker_pk_fe` signature).

**Instruction data**

```rust
struct FillIxData {
    /// The fill proof; verified with new (standard Groth16, no commitment).
    proof: FillProof,
    /// SPP transact (2-in/2-out): escrow + taker destination UTXO -> destination to maker,
    /// source to taker.
    transact: TransactIxData,
}
```

---

### fill_verifiable_encryption

The taker fills the order before expiry. The swap program verifies the
[fill proof](#fill-verifiable-encryption-circuit), then CPIs SPP [`transact`](../../docs/spec.md#transact). The
transact is 2-in/2-out: the escrow UTXO and the taker's exact `destination_amount`
`destination_asset_id` UTXO in; `destination_amount` `destination_asset_id` to `maker_address` and
`source_amount` `source_asset_id` to the taker out. The swap conserves value per asset, so
there is no change and no protocol fee; the taker's profit is the spread already priced
into `destination_amount`. The destination output is verifiably encrypted to
`maker_address.viewing_pk` so the maker can decrypt and spend the bought funds; the taker's
source output is sender-encrypted (the taker authored it and needs no guarantee). The taker
holds the order opening (recovered from the escrow ciphertext) and its own destination UTXO
secret, so it produces both proofs; the swap program supplies the escrow-authority PDA signer
for the escrow spend and only requires the taker as fee payer. The swap program reads
the order `expiry` from the transact's own `expiry_unix_ts` field and checks it against the Clock
sysvar (`now <= expiry`); the fill proof takes that same value as a public input.

**Accounts**

1. `taker` — fee payer; signer, writable. (Authorization is the escrow-authority PDA signer
   the program provides and the `taker_pk_fe` signature the proof checks, not this account.)
   Consumed by the program; everything after it is forwarded verbatim to the SPP `transact` CPI.
   `now` is read from the Clock sysvar via syscall, not passed as an account.
2. `escrow_authority` — escrow-authority PDA (seeds `[b"escrow_authority"]`); read-only, non-signer.
   The program flips it to a signer inside the SPP CPI to authorize the escrow spend (see
   [Order Terms](#order-terms)).
3. `tree_accounts` — SPP trees the transact touches; writable.
4. `spl_interface` — SPL interface accounts for `source_asset_id` and `destination_asset_id`;
   writable.
5. `asset_registry_source`, `asset_registry_destination` — SPP `Asset registry` PDAs; read.
6. `spp_program` — SPP program (CPI target); must be the last account (the program checks this).

**Instruction data**

```rust
struct FillVerifiableEncryptionIxData {
    /// The fill proof; verified with new_with_commitment (BSB22 commitment + PoK).
    proof: FillVerifiableEncryptionProof,
    /// SPP transact (2-in/2-out): escrow + taker destination UTXO -> destination to maker,
    /// source to taker.
    transact: TransactIxData,
}
```

---

### cancel

After expiry, the escrow is reclaimed to the committed `maker_address`. The swap program verifies
the [cancel proof](#cancel-circuit), then CPIs SPP [`transact`](../../docs/spec.md#transact). The
transact is 1-in/1-out: the escrow UTXO in, a `source_amount` `source_asset_id` UTXO to
`maker_address` out. The destination is fixed by the committed terms, so any fee payer holding the
order opening (maker or taker) can trigger the refund and it can only land at `maker_address`.
The caller supplies no escrow signature; the swap program supplies the escrow-authority PDA signer
via `invoke_signed`. The swap program reads the order `expiry` from a dedicated
instruction-data field (distinct from `transact.expiry_unix_ts`, the SPP relayer deadline) and
checks it against the Clock sysvar (`now > expiry`); the cancel proof takes that same value as a
public input.

**Accounts**

1. `caller` — fee payer; signer, writable. (Authorization is the order opening plus the program's
   escrow-authority PDA signer; the destination is the committed `maker_address`.) Consumed by the
   program; everything after it is forwarded verbatim to the SPP `transact` CPI. `now` is read from
   the Clock sysvar via syscall, not passed as an account.
2. `escrow_authority` — escrow-authority PDA (seeds `[b"escrow_authority"]`); read-only, non-signer.
   The program flips it to a signer inside the SPP CPI to authorize the escrow spend (see
   [Order Terms](#order-terms)).
3. `tree_accounts` — SPP trees the transact touches; writable.
4. `spl_interface` — SPL interface account for `source_asset_id`; writable.
5. `asset_registry` — SPP `Asset registry` PDA for `source_asset_id`; read.
6. `spp_program` — SPP program (CPI target); must be the last account (the program checks this).

**Instruction data**

```rust
struct CancelIxData {
    /// The cancel proof; verified by the swap program.
    proof: CancelProof,
    /// The committed order expiry, checked against the Clock (now > expiry) and a proof public
    /// input. Distinct from transact.expiry_unix_ts (the SPP relayer deadline).
    expiry: u64,
    /// SPP transact (1-in/1-out): escrow -> source UTXO to maker_address.
    transact: TransactIxData,
}
```

## Circuits

The swap program runs three circuits, each with its own verifying key, distinct from the SPP value
proof inside `transact`. Each circuit witnesses the SPP transaction's UTXO openings (the escrow
input, the outputs), enforces the order rules below, and commits the transaction via the public
`private_tx_hash` — the single value SPP checks to authorize spending the escrow. SPP proves
the UTXOs are in the tree and conserves value; the swap circuit needs no membership proof of its
own. `create` and `cancel` are standard Groth16; `fill_verifiable_encryption` carries a BSB22 commitment + PoK for its
verifiable encryption. Concrete shape parameters (input/output slot counts) are fixed once and
benchmarked, and must match the SPP `transact` shapes the instructions use. The circuits are small
and proven in-process through a gnark→Rust FFI binding, with no prover server; the SPP transfer proof
still comes from the existing SPP prover.

### Create circuit

Proves the escrow UTXO's committed order terms are well-formed. Matches the 1-in/3-out transact
(source UTXO in; change + escrow + marker out), padded to the SPP `(2, 3)` proving shape.

- **Public inputs:** `private_tx_hash`, `source_asset_id`, and `maker_address` (a
  `CompressedShieldedAddress` hashed to a field element).
- **Private inputs:** the remaining order terms (`destination_asset_id`, `destination_amount`,
  `expiry`, `taker_pk_fe`), the escrow UTXO opening (`source_amount`, `escrow_blinding`), and the
  change output opening (amount and blinding). The marker output hash enters as a free (unconstrained)
  witness. There is no `order_secret`: the escrow owner is the program-wide escrow-authority PDA
  constant.
- **Constraints:**
  - The `private_tx_hash` recomputation mirrors the padded transact exactly: `chain([source_input,
    0])` over inputs, `chain([change, escrow, marker])` over outputs, `chain([0, 0])` over
    addresses. The marker hash is a free witness (dummies contribute 0).
  - The escrow output committed in `private_tx_hash` is `(source_asset_id, source_amount,
    owner = escrow-authority PDA, data_hash = Poseidon(order terms), escrow_blinding)` with swap
    `utxo_data` — so the public SPP escrow output carries the committed terms. The owner is the
    program-wide escrow-authority constant.
  - The `data_hash` binds the public-input `maker_address`, and the change output committed in
    `private_tx_hash` is owned by `maker_address`. So the committed recipient equals the public
    `maker_address` and is not a hidden witness.
  - `destination_amount > 0`; `source_amount > 0`.

### Fill circuit

Standard Groth16, no commitment. Pays the destination output to the maker and checks the payout
against the committed terms, matching the 2-in/2-out transact (escrow + taker destination UTXO in;
destination-to-maker + source-to-taker out). The program enforces `now <= expiry` against the Clock;
the circuit only reveals and binds `expiry`.

- **Public inputs:** `Poseidon(private_tx_hash, expiry)`. No ciphertext input.
- **Private inputs:** the escrow UTXO opening (order terms, `source_amount`, `escrow_blinding`), the
  maker's compressed viewing pubkey (feeding `maker_address`), `taker_address`, and the two output
  blindings. No `taker_pk_fe` signature and no viewing secret.
- **Constraints:**
  - The public `expiry` equals the committed order `expiry`; the escrow `data_hash` uses the `fill`
    constant for `fill_mode`, so only a `fill`-mode escrow reconstructs.
  - The outputs committed in `private_tx_hash` are `destination_output == (destination_asset_id,
    destination_amount, maker_address)` and `source_output == (source_asset_id, source_amount,
    taker_address)`.
  - The `destination_output` blinding is fixed to `Poseidon(escrow_blinding, DOMAIN)` (reduced to 31
    bytes), so the maker recovers and spends it from the escrow blinding alone; no encryption is proven.
  - `destination_amount > 0`; `source_amount > 0`.

### Fill verifiable encryption circuit

Authorizes the taker to fill, pays and verifiably encrypts the destination output to the
maker, and checks the payout against the committed terms. Matches the 2-in/2-out transact (escrow
+ taker destination UTXO in; destination-to-maker + source-to-taker out). The program
enforces `now <= expiry` against the Clock; the circuit only reveals and binds `expiry`.

- **Public inputs:** `private_tx_hash`, `expiry`, and the `ciphertext_hash` (the Poseidon hash of the
  destination-output verifiable-encryption ciphertext; the program recomputes it from the transact's
  last output ciphertext and hashes all three into the single verifier input
  `Poseidon(private_tx_hash, expiry, ciphertext_hash)`).
- **Private inputs:** the escrow UTXO opening (incl. `utxo_data` = order terms, `source_amount`,
  `escrow_blinding`), the `taker_pk_fe` signature over the order terms, and the openings of
  the two output UTXOs. There is no `order_secret`; the escrow owner is the escrow-authority PDA
  constant and the opening carries the `escrow_blinding`.
- **Constraints:**
  - `taker_pk_fe` signature valid; the public `expiry` equals the committed order `expiry`.
  - The outputs committed in `private_tx_hash` are `destination_output == (destination_asset_id,
    destination_amount, maker_address)` and `source_output == (source_asset_id, source_amount,
    taker_address)`.
  - The `destination_output` ciphertext is a verifiable encryption of the destination UTXO to
    `maker_address.viewing_pk` (DHKEM(P-256) + Poseidon KDF + AES-256-CTR, integrity via
    `ciphertext_hash`), reusing the SPP [merge-proof](../../docs/spec.md#merge-proof---merge-zk-proof)
    scheme — the source of the BSB22 commitment. The taker's `source_output` uses ordinary
    sender encryption and is not constrained here.

### Cancel circuit

Reclaims the escrow to the committed `maker_address` after expiry. Matches the 1-in/1-out
transact (escrow in; source-to-maker out). The program enforces `now > expiry` against the Clock; the
circuit only reveals and binds `expiry`.

- **Public inputs:** `private_tx_hash`, `expiry`.
- **Private inputs:** the escrow UTXO opening (incl. `utxo_data` = order terms, `source_amount`,
  `escrow_blinding`), and the `source_output` opening. There is no `order_secret`; the escrow owner
  is the escrow-authority PDA constant and the opening carries the `escrow_blinding`.
- **Constraints:**
  - The public `expiry` equals the committed order `expiry`.
  - The output committed in `private_tx_hash` is `source_output == (source_asset_id, source_amount,
    maker_address)`.
