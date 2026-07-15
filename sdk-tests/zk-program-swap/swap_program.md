# Swap Program

The swap program settles a confidential swap between a maker and a taker the maker chooses. The two
agree a price out of band, and the maker commits an order that locks the
funds it is selling as a shielded UTXO in the Solana Privacy Program (SPP). The taker indexes the order
made with the make transaction, encrypted so only the taker and the maker can read its private terms.

The taker takes the order before it expires, receiving the maker's funds and paying the agreed amount
in return; if the taker declines, the maker reclaims the order UTXO after expiry.

The taker learns the order and may decline to take it, but it cannot take the locked funds: the
program alone can move the order UTXO, and only by settling the committed order or refunding the maker
after expiry. Amounts and the price stay private. That a swap was made and later taken or
cancelled is public; taking reveals the taker and cancelling reveals the maker, who signs it.

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

    Note over Maker: 1. Make the order (make)
    Maker->>Swap: make (make proof + SPP transact)
    Swap->>SPP: CPI transact -> change + order UTXO (swap utxo_data) + marker message
    Note over SPP: spend maker source UTXO, append change + order UTXO <br> source_asset_id public, source_amount + order terms private in utxo_data <br> order UTXO ciphertext encrypted to taker viewing pubkey; marker message tagged to taker
    Note over Taker,SPP: taker wallet sync finds the marker message (its tag), <br> decrypts the matching order UTXO slot -> order UTXO hash preimage (terms + blinding)
    Note over Maker: maker can decrypt the order UTXO slot via the tx viewing key it holds

    Note over Taker: 2a. Take, before expiry (Taker holds the order UTXO hash preimage)
    Taker->>Swap: take_verifiable_encryption (take proof + SPP transact)
    Swap->>SPP: CPI transact: order UTXO + Taker destination UTXO -> source UTXO to Taker + destination UTXO to maker
    Note over SPP: destination ciphertext checked by the take proof, decryptable via the order UTXO blinding; order UTXO consumed

    Note over Maker: 2b. Cancel, after expiry
    Maker->>Swap: cancel (maker-signed, cancel proof + SPP transact)
    Swap->>SPP: CPI transact: order UTXO -> source UTXO back to the maker
    Note over SPP: order UTXO consumed
```

## Table of Contents

- [Glossary](#glossary)
- [Privacy Model](#privacy-model)
- [Accounts](#accounts)
- [Order Terms](#order-terms)
- [Instructions](#instructions)
  - [make](#make)
  - [take](#take)
  - [take_verifiable_encryption](#take_verifiable_encryption)
  - [cancel](#cancel)
- [Circuits](#circuits)
  - [Make circuit](#make-circuit)
  - [Take circuit](#take-circuit)
  - [Take verifiable encryption circuit](#take-verifiable-encryption-circuit)
  - [Cancel circuit](#cancel-circuit)

## Glossary

Types used in this document. Shared SPP types are defined in [spec.md](../../docs/spec.md#glossary).

| Type | Encoding | Definition |
| --- | --- | --- |
| `Address` | `[u8; 32]` | Solana account address. |
| `asset_id` | `u64` | Asset identifier in UTXOs; `1` is SOL, each SPL mint `≥ 2`. The mint→`asset_id` map is the SPP `Asset registry` PDA. See [spec.md](../../docs/spec.md#glossary). |
| `CompressedShieldedAddress` | `[u8; 65]` | `(owner_hash [u8;32], viewing_pk P256Pubkey[33])`. See [spec.md](../../docs/spec.md#shielded-address). |
| `order UTXO` | — | The SPP [UTXO](../../docs/spec.md#utxo) holding the source funds: `asset = source_asset_id`, `amount = source_amount`, `owner = order-authority PDA` (seeds `[b"order_authority"]`), nullifier secret `= 0`, `utxo_data = order terms`. Spendable only by the swap program. See [Order Terms](#order-terms). |
| `marker message` | — | The SPP `transact` message (`view_tag`, `data`) `make` appends as the taker's discovery tag: `view_tag` is the taker's confidential view tag, `data` a plaintext [`MarkerData`](#make) the program writes. Committed in `private_tx_hash` via the transact's external-data hash; the `view_tag` is unenforced: a wrong tag only means the taker does not index the trade. |
| `MarkerData` | Borsh | `{ order_utxo_hash: [u8;32], maker_pubkey: [u8;32] }`, the plaintext `make` writes into the transact's single marker message. `order_utxo_hash` locates the order UTXO slot; `maker_pubkey` is the `make` signer's Solana pubkey, which the taker resolves to the maker's registered shielded address via the user registry. See [make](#make). |
| `Order terms` | — | The fields committed in the order UTXO's `utxo_data` (record tag `0x02`), hashed into the order UTXO `utxo_hash` via `data_hash`: `destination_asset_id`, `destination_amount`, `maker_address`, `expiry`, `taker_pk_fe`, `take_mode`. See [Order Terms](#order-terms). |
| `private_tx_hash` | `[u8; 32]` | Commitment to the SPP `transact` a swap proof authorizes: the link between a swap proof and the SPP transaction. See [spec.md](../../docs/spec.md#zk-program-interface). |
| `MakeProof` / `TakeProof` / `CancelProof` / `TakeVerifiableEncryptionProof` | `[u8; 128]` / `[u8; 192]` | Groth16 proofs verified by the swap program, each committing the transaction via `private_tx_hash`. `MakeProof`, `TakeProof`, and `CancelProof` are standard Groth16, 128 B; `TakeVerifiableEncryptionProof` adds a BSB22 commitment + PoK for its encryption check and is 192 B (verified with `new_with_commitment`). |
| `TransactIxData` | — | SPP `transact` instruction data: the SPP proof, input nullifiers, output UTXO hashes, ciphertexts, and routing. See [spec.md](../../docs/spec.md#transact). |

## Privacy Model

What is public and what is private. The confidentiality is inherited from the SPP confidential
zone; the swap program does not try to hide which action ran.

- **Public:** the maker's Solana signer pubkey, written into the marker at make (the taker resolves
  the maker's registered shielded address from it via the user registry) and revealed again at
  cancel, which the maker signs; which swap instruction ran; `source_asset_id` at make and both
  `source_asset_id` and `destination_asset_id` at resolve (`asset_id`s are SPP public inputs); the
  order UTXO hash at
  make; the order `expiry`, revealed at resolve so the program can check it against the Clock; each
  transaction's SPP output UTXO hashes and ciphertexts; the taker's identity on `take` and the
  taker's on `take_verifiable_encryption`, since each signs its transaction as fee payer.
- **Private:** `price`, `source_amount`, `destination_amount`, and the aggregate volume per asset.
  These live only inside confidential UTXOs and the order UTXO `utxo_data`.
  The taker's identity stays private at make and on cancel, which the maker signs.
- **Unlinkable:** SPP hides the link between a created UTXO and its later spend, so an observer
  cannot pair a make with its take or cancel.

## Accounts

The swap program owns no accounts: the order and its funds live in the order UTXO, a leaf in the
SPP trees, moved by CPI. The
taker's spread (the gap
between the `source_amount` it receives and the `destination_amount` it pays) is its only
compensation.

## Order Terms

The order UTXO holds the order terms and funds. `make` writes the
order terms into the order UTXO's `utxo_data` (record tag `0x02`), and SPP commits them into the
order UTXO `utxo_hash` through `data_hash` (committed unchecked, interpreted by the swap circuit — see
[spec.md](../../docs/spec.md#utxo)):

```text
order_terms = (
    destination_asset_id,   // asset_id; private until resolve
    destination_amount,     // private; price = destination_amount / source_amount is implicit and private
    maker_address,           // the maker's CompressedShieldedAddress, resolved by the taker from the user registry: receives destination on take and source on cancel
    expiry,                 // unix seconds; revealed at resolve and checked against the Clock by the program
    taker_pk_fe,     // the designated taker; enforced only by take_verifiable_encryption
    take_mode,       // which take instruction may settle this order UTXO: 0 = take (derived), 1 = take_verifiable_encryption
)
data_hash = Poseidon(order_terms)        // enters the order UTXO utxo_hash directly
```

`take_mode` selects the take instruction that can settle the order UTXO: each take circuit reconstructs
`data_hash` with its own hardcoded `take_mode`, so settling with the wrong take yields a mismatched
order UTXO hash and the proof fails. `cancel` takes `take_mode` as an unconstrained witness and refunds
either kind.

`source_asset_id`, `source_amount`, and `owner = order-authority PDA` are the order UTXO's own
SPP fields, already committed in `utxo_hash`. The order UTXO's owner is the swap order-authority PDA
(seeds `[b"order_authority"]`) and its nullifier secret is hardcoded to 0, so:

```text
order_utxo_owner_hash = Poseidon(hash_field(order_authority_pda), Poseidon(0))   // a program-wide constant
nullifier             = Poseidon(utxo_hash, blinding, 0)                          // recomputed from the preimage
```

Knowledge of the order UTXO hash preimage, the order terms plus the order UTXO `blinding`, is the complete
spend capability: the nullifier includes the `blinding` and the circuits need it to recompute the
order UTXO `utxo_hash`. The preimage is delivered in the make
transaction (see
[make](#make)): the order UTXO output's recipient ciphertext contains the order terms other
than `maker_address`, encrypted to the taker's viewing pubkey, and the maker can decrypt the same
slot via the transaction viewing key it holds. The taker resolves `maker_address`
from the user registry via the marker's `maker_pubkey`, the `make`
signer, and verifies the resolution by recomputing the order UTXO `utxo_hash`. Moving the order UTXO also
requires the program: SPP spends a PDA-owned UTXO only when the swap program
produces the order-authority signer via `invoke_signed`, which it does only through `take` or
`take_verifiable_encryption` (constrained to the committed payout) or `cancel` (after expiry,
maker-signed, to `maker_address`). The swap
circuits leave the order UTXO owner a free witness; SPP enforces the PDA ownership at spend time, when
the order UTXO input's owner must match the order-authority signer. The program derives the PDA via
`find_program_address`, checks it is present among the forwarded SPP accounts, and flips it to a
signer inside the SPP CPI to authorize the order UTXO spend (the client sets the order UTXO input's
`eddsa_signer_index = 2`, the PDA's position in the forwarded SPP slice
`[payer, tree, order_authority, spp_program]`); the PDA is a bare address and signs only inside
the CPI.

`maker_address` is the committed destination for both outcomes: take pays the destination output
there, cancel returns the source output there. Either way the maker recovers the bought output from
the order UTXO blinding it already holds: `take_verifiable_encryption` proves a ciphertext keyed from
it, and `take` fixes the destination blinding to `Poseidon(order_utxo_blinding, DOMAIN)`.
Cancel requires the maker: it signs the cancel transaction, and the cancel
proof checks `hash_field` of the signer's pubkey against the order's
`maker_owner_hash`. The refund can only land at `maker_address`.

`expiry` is a unix-seconds value the proof reveals as a public input and the swap program checks
against the Clock sysvar: `take` and `take_verifiable_encryption` require `now <= expiry`, `cancel`
requires `now > expiry`. The instructions source the revealed `expiry` differently. Both takes reuse the transact's own
`transact.expiry_unix_ts` field as the order expiry, whereas `cancel` takes the order expiry as a
separate `order_expiry` instruction-data field distinct from `transact.expiry_unix_ts` (the SPP
relayer deadline).
Either way the proof's public `expiry` must equal the committed order term, so neither party can
shift the window.

## Instructions

| # | Instruction | Tag | Description | Accounts Read | Accounts Modified | Access control |
|---|-------------|-----|-------------|---------------|-------------------|----------------|
| 1 | [make](#make) | 2 | Verify the make proof and CPI SPP `transact` to lock the source funds into the order UTXO (swap `utxo_data`) and write the taker's marker message. | — | SPP trees (CPI) | Maker signs (fee payer) |
| 2 | [take](#take) | 3 | Verify the take proof (standard Groth16) and CPI SPP `transact`: spend the order UTXO + a matching destination UTXO, pay destination to the maker (blinding derived from the order UTXO blinding, standard output ciphertext) and source to the taker. | order_authority | SPP trees (CPI) | Any fee payer signs; the order UTXO spend is authorized by the program's order-authority PDA signer; the maker payout is constrained to the committed `maker_address` |
| 3 | [take_verifiable_encryption](#take_verifiable_encryption) | 5 | Verify the take proof and CPI SPP `transact`: spend the order UTXO + the taker's destination UTXO, pay destination (with a proof-checked ciphertext) to the maker and source to the taker. | order_authority | SPP trees (CPI) | Taker signs (fee payer); the order UTXO spend is authorized by the program's order-authority PDA signer; the circuit checks the taker-side input's owner against the committed `taker_pk_fe` |
| 4 | [cancel](#cancel) | 4 | Verify the cancel proof and CPI SPP `transact`: after expiry, spend the order UTXO back to `maker_address`. | order_authority | SPP trees (CPI) | Maker signs; the proof checks the signer against the committed `maker_owner_hash`; the program's order-authority PDA authorizes the order UTXO spend |

---

### make

Opens an order. The swap program verifies the [make proof](#make-circuit), then CPIs SPP
[`transact`](../../docs/spec.md#transact) to spend the maker's `source_asset_id` UTXO and append the
order UTXO, a UTXO of `source_amount` `source_asset_id` owned by the order-authority PDA
(seeds `[b"order_authority"]`), with the [order terms](#order-terms) in its `utxo_data` (which,
with the PDA owner, makes SPP spend it only through a swap circuit). The transact is 1-in/2-out
(the maker's source UTXO in; a change UTXO to the maker and the order UTXO out) plus a marker
message tagged to the taker.

The order UTXO output's recipient ciphertext (`TransferRecipientPlaintext { asset_id, amount, blinding,
zone_program_id, data }`, with `data` = the order terms other than `maker_address`) is encrypted to
the taker's viewing pubkey, so the taker recovers the private order terms and the order UTXO `blinding`;
the maker can decrypt the same slot via the transaction viewing key it holds. Those two parties are
exactly who can decrypt the order. The taker resolves `maker_address`
from the user registry via the marker's `maker_pubkey` and verifies the resolution by
recomputing the order UTXO `utxo_hash`. The program requires exactly one transact message, with empty
`data`, and writes a plaintext [`MarkerData`](#glossary) `{ order_utxo_hash,
maker_pubkey }` into it (the order UTXO hash read from transact output index 1, the pubkey from the
signer), so ordinary wallet sync finds the trade and
can locate the matching order UTXO slot to decrypt. The message is committed in `private_tx_hash` via
the external-data hash, so the SPP proof only verifies if the maker proved over the exact
`MarkerData` the program writes; only the marker's `view_tag` is unenforced: a wrong tag means the
taker does not index the trade.

The proof checks the order UTXO output against the order rules (see the [make
circuit](#make-circuit)) without revealing the terms, and commits the transaction via
`private_tx_hash`, its sole public input. The source asset, the
amounts, and the other order terms are private at the swap layer (the transact's own `asset_id`
public inputs still reveal `source_asset_id` at the SPP layer).

**Accounts**

1. `maker` — spends the source UTXO; signer, writable (fee payer). Consumed by the program (its
   pubkey enters the marker); everything after it is forwarded verbatim to the SPP `transact` CPI.
2. `payer` — the SPP fee payer (the maker again); signer, writable.
3. `tree_accounts` — SPP trees the transact touches; writable.
4. `spp_program` — SPP program (CPI target); must be the last account (the program checks this).

**Instruction data**

```rust
struct MakeIxData {
    /// The make proof; verified by the swap program against the transact's
    /// `private_tx_hash` as the sole public input.
    proof: MakeProof,
    /// SPP transact (1-in/2-out): maker source UTXO -> change + order UTXO;
    /// includes the marker message.
    transact: TransactIxData,
}
```

---

### take

A taker settles the order before expiry with the derived-blinding proof. The swap program verifies
the [take proof](#take-circuit) (standard Groth16, no commitment), then CPIs SPP
[`transact`](../../docs/spec.md#transact). Shape and payout match
[`take_verifiable_encryption`](#take_verifiable_encryption): 2-in/2-out, the order UTXO + a
`destination_amount` `destination_asset_id` UTXO in, source to that input's owner and destination to
`maker_address` out. The difference is recovery and authorization: the proof fixes the destination
blinding to `Poseidon(order_utxo_blinding, DOMAIN)`, so the maker reconstructs and spends the bought
output from the
order UTXO blinding and order terms alone, and that output includes an ordinary recipient ciphertext for
wallet discovery rather than a verifiable one. The circuit checks only the payout and the blinding
derivation, so any holder of the order UTXO hash preimage and a matching destination UTXO may
take; the maker payout still flows only to the committed `maker_address`, and the order UTXO's
`take_mode` forbids settling a `take_verifiable_encryption` order UTXO this way.
Expiry is read from `transact.expiry_unix_ts` and checked `now <= expiry`, as in
`take_verifiable_encryption`.

**Accounts**

Identical to [`take_verifiable_encryption`](#take_verifiable_encryption), except any fee payer may
sign: authorization rests on the order-authority PDA signer alone.

**Instruction data**

```rust
struct TakeIxData {
    /// The take proof; verified with new (standard Groth16, no commitment).
    proof: TakeProof,
    /// SPP transact (2-in/2-out): order UTXO + destination UTXO -> source to the taker,
    /// destination to the maker.
    transact: TransactIxData,
}
```

---

### take_verifiable_encryption

The taker takes the order before expiry. The swap program verifies the
[take proof](#take-verifiable-encryption-circuit), then CPIs SPP [`transact`](../../docs/spec.md#transact). The
transact is 2-in/2-out: the order UTXO and the taker's exact `destination_amount`
`destination_asset_id` UTXO in; `source_amount` `source_asset_id` to the taker and
`destination_amount` `destination_asset_id` to `maker_address` out. The destination is the last
output; the program hashes its ciphertext into the public input. The swap conserves value per
asset; the taker's profit is the spread already priced
into `destination_amount`. The destination output's ciphertext is checked by the take proof and
keyed from the order UTXO blinding, so the maker can decrypt and spend the bought funds; the taker's
source output is sender-encrypted. The taker
holds the order UTXO hash preimage (recovered from the order UTXO ciphertext) and its own destination UTXO
secret, so it produces both proofs; the circuit checks the taker-side input's owner against the
committed `taker_pk_fe`, and SPP requires that owner to sign as the fee payer, so only the designated taker
can take. The swap program supplies the order-authority PDA signer for the order UTXO spend, reads
the order `expiry` from the transact's own `expiry_unix_ts` field and checks it against the Clock
sysvar (`now <= expiry`); the take proof takes that same value as a public input.

**Accounts**

1. `taker` — fee payer; signer, writable. Consumed by the program; everything after it is forwarded
   verbatim to the SPP `transact` CPI. `now` is read from the Clock sysvar via syscall.
2. `payer` — the SPP fee payer (the taker again); signer, writable. SPP checks the taker-side
   input's owner against this signer.
3. `tree_accounts` — SPP trees the transact touches; writable.
4. `order_authority` — order-authority PDA (seeds `[b"order_authority"]`); read-only, non-signer.
   The program flips it to a signer inside the SPP CPI to authorize the order UTXO spend (see
   [Order Terms](#order-terms)).
5. `spp_program` — SPP program (CPI target); must be the last account (the program checks this).

**Instruction data**

```rust
struct TakeVerifiableEncryptionIxData {
    /// The take proof; verified with new_with_commitment (BSB22 commitment + PoK).
    proof: TakeVerifiableEncryptionProof,
    /// SPP transact (2-in/2-out): order UTXO + taker destination UTXO -> source to taker,
    /// destination to maker (last output).
    transact: TransactIxData,
}
```

---

### cancel

After expiry, the order UTXO is reclaimed to the committed `maker_address`. The swap program verifies
the [cancel proof](#cancel-circuit), then CPIs SPP [`transact`](../../docs/spec.md#transact). The
transact is 1-in/1-out: the order UTXO in, a `source_amount` `source_asset_id` UTXO to
`maker_address` out. The maker signs as a dedicated readonly signer; the program includes
`hash_field` of its pubkey in the proof's public input and the circuit checks it against the
committed
`maker_owner_hash`, so only the maker can cancel, and the maker knows the refund blinding it chose.
The swap program supplies the order-authority PDA signer
via `invoke_signed` and reads the order `expiry` from the dedicated `order_expiry`
instruction-data field (distinct from `transact.expiry_unix_ts`, the SPP relayer deadline) and
checks it against the Clock sysvar (`now > expiry`); the cancel proof takes that same value as a
public input.

**Accounts**

1. `caller` — fee payer; signer, writable. Consumed by the program. `now` is read from
   the Clock sysvar via syscall.
2. `maker` — the maker's Solana signer; read-only, signer. Consumed by the program, which includes
   `hash_field(maker)` in the cancel proof's public input; everything after it is forwarded
   verbatim to the SPP `transact` CPI.
3. `payer` — the SPP fee payer; signer, writable.
4. `tree_accounts` — SPP trees the transact touches; writable.
5. `order_authority` — order-authority PDA (seeds `[b"order_authority"]`); read-only, non-signer.
   The program flips it to a signer inside the SPP CPI to authorize the order UTXO spend (see
   [Order Terms](#order-terms)).
6. `spp_program` — SPP program (CPI target); must be the last account (the program checks this).

**Instruction data**

```rust
struct CancelIxData {
    /// The cancel proof; verified by the swap program.
    proof: CancelProof,
    /// The committed order expiry, checked against the Clock (now > expiry) and a proof public
    /// input. Distinct from transact.expiry_unix_ts (the SPP relayer deadline).
    order_expiry: u64,
    /// SPP transact (1-in/1-out): order UTXO -> source UTXO to maker_address.
    transact: TransactIxData,
}
```

## Circuits

The swap program runs four circuits, each with its own verifying key, distinct from the SPP value
proof inside `transact`. Each circuit witnesses the SPP transaction's UTXO hash preimages (the order UTXO
input, the outputs), enforces the order rules below, and commits the transaction via
`private_tx_hash`: `make` exposes it as the public input itself, the other circuits hash it with
their public values into a single public input. SPP proves
the UTXOs are in the tree and conserves value; the swap circuits rely on that rather than proving
membership themselves. `make`, `take`, and `cancel` are standard Groth16; `take_verifiable_encryption` adds a BSB22 commitment + PoK for its
encryption check. Concrete shape parameters (input/output slot counts) are fixed once and
benchmarked, and must match the SPP `transact` shapes the instructions use. The circuits are small
and proven in-process through a gnark→Rust FFI binding; the SPP transfer proof
still comes from the existing SPP prover.

### Make circuit

Proves the order UTXO output commits the order terms. Matches the 1-in/2-out transact
(source UTXO in; change + order UTXO out), padded to the SPP `(2, 2)` proving shape. The marker message
enters `private_tx_hash` through the free external-data hash and is enforced
by the SPP proof.

- **Public inputs:** `private_tx_hash` only; the program feeds
  it to the verifier straight from `TransactIxData`.
- **Private inputs:** the order terms (`destination_asset`, `destination_amount`, the maker's
  owner hash and viewing pubkey, `expiry`, `taker_pk_fe`, `take_mode`) and the fully witnessed
  order UTXO and change output UTXOs. The order UTXO owner is a free witness
  (the order-authority PDA, which SPP enforces at spend time).
- **Constraints:**
  - The `private_tx_hash` recomputation mirrors the padded transact exactly: `chain([source_input,
    0])` over inputs, `chain([change, order_utxo])` over outputs, `chain([0, 0])` over
    addresses. The source input hash and external-data hash are free witnesses; the change slot
    contributes 0 when the change amount is 0.
  - The order UTXO output committed in `private_tx_hash` has `data_hash = Poseidon(order terms)`
    with `maker_address` hashed in as a field element, zone fields 0, and a nonzero amount, so the
    public SPP order UTXO output commits the terms.
  - The change output is constrained to the order UTXO's asset and to `maker_owner_hash`, with empty
    data.
  - `destination_amount > 0` (64-bit range-checked); `take_mode` is boolean.

### Take circuit

Standard Groth16, no commitment. Pays the destination output to the maker and checks the payout
against the committed terms, matching the 2-in/2-out transact (order UTXO + destination UTXO in;
source + destination-to-maker out). The program enforces `now <= expiry` against the Clock;
the circuit only reveals `expiry` and checks it equals the committed term.

- **Public inputs:** `Poseidon(private_tx_hash, expiry)`.
- **Private inputs:** the order UTXO hash preimage (order terms, `source_amount`,
  `order_utxo_blinding`), the maker's compressed viewing pubkey (feeding `maker_address`), the taker's
  destination-side input UTXO, and the two output UTXO hash preimages.
- **Constraints:**
  - The public `expiry` equals the committed order `expiry`; the order UTXO `data_hash` uses the `take`
    constant for `take_mode`, so only a `take`-mode order UTXO reconstructs.
  - The destination-side input is `(destination_asset_id, destination_amount)`; the outputs
    committed in `private_tx_hash` are `destination_output == (destination_asset_id,
    destination_amount, maker_owner_hash)` and `source_output == (source_asset_id, source_amount)`
    owned by the destination-side input's owner, so the taker pays itself the source funds.
  - The `destination_output` blinding is fixed to the low 248 bits (31 bytes) of
    `Poseidon(order_utxo_blinding, DOMAIN)`, so the maker recovers and spends it from the order UTXO
    blinding alone.
  - `destination_amount > 0` (64-bit range-checked); the order UTXO amount is nonzero.

### Take verifiable encryption circuit

Authorizes the designated taker to take, proves the destination-output ciphertext, and checks the
payout against the committed terms. Matches the 2-in/2-out transact (order UTXO + taker destination
UTXO in; source-to-taker + destination-to-maker out). The program
enforces `now <= expiry` against the Clock; the circuit only reveals `expiry` and checks it equals
the committed term.

- **Public inputs:** `private_tx_hash`, `expiry`, and the `ciphertext_hash` (the Poseidon hash of the
  destination-output ciphertext; the program recomputes it from the transact's
  last output ciphertext and hashes all three into the single verifier input
  `Poseidon(private_tx_hash, expiry, ciphertext_hash)`).
- **Private inputs:** the take circuit's core (the order UTXO hash preimage incl. `utxo_data` =
  order terms, `source_amount`, `order_utxo_blinding`; the taker's destination-side input; the hash
  preimages of the two output UTXOs) plus the taker's nullifier pubkey. The order UTXO
  owner is the order-authority PDA constant and the preimage includes the `order_utxo_blinding`.
- **Constraints:**
  - The taker-side input's owner equals `Poseidon(taker_pk_fe, taker_nullifier_pk)`; SPP requires
    that owner to sign as the fee payer, so the spent input belongs to the committed taker. The
    public `expiry` equals the committed order `expiry`; the order UTXO `data_hash` uses the
    `take_verifiable_encryption` constant for `take_mode`.
  - The outputs committed in `private_tx_hash` are `destination_output == (destination_asset_id,
    destination_amount, maker_owner_hash)` and `source_output == (source_asset_id, source_amount)`
    owned by the taker-side input's owner.
  - The `destination_output` ciphertext is AES-256-CTR over `destination_amount ||
    destination_asset || destination blinding`, key and nonce Poseidon-KDF-derived from
    `Poseidon(order_utxo_blinding, KDF_DOMAIN)`, integrity via `ciphertext_hash`; this reuses the SPP
    [merge-proof](../../docs/spec.md#merge-proof---merge-zk-proof) symmetric scheme, the source of
    the BSB22 commitment. Holders of the order UTXO hash preimage, the maker and the taker, can
    decrypt. The taker's `source_output` uses ordinary
    sender encryption.

### Cancel circuit

Reclaims the order UTXO to the committed `maker_address` after expiry. Matches the 1-in/1-out
transact (order UTXO in; source-to-maker out). The program enforces `now > expiry` against the Clock; the
circuit only reveals `expiry` and checks it equals the committed term.

- **Public inputs:** `Poseidon(private_tx_hash, expiry, maker_owner_pk_field)`, where
  `maker_owner_pk_field` is `hash_field` of the maker signer's pubkey, fed by the program.
- **Private inputs:** the order UTXO hash preimage (incl. `utxo_data` = order terms,
  `source_amount`, `order_utxo_blinding`), the `source_output` hash preimage, and the maker's
  `(maker_owner_pk_field,
  maker_nullifier_pk)`, the preimage of the committed `maker_owner_hash`. The order UTXO owner is the
  order-authority PDA constant and the order UTXO preimage
  includes the `order_utxo_blinding`.
- **Constraints:**
  - The public `expiry` equals the committed order `expiry`; `take_mode` is an unconstrained
    witness, so either order UTXO kind refunds.
  - `Poseidon(maker_owner_pk_field, maker_nullifier_pk)` equals the committed `maker_owner_hash`,
    so the proof verifies only with the maker signer the program supplies.
  - The output committed in `private_tx_hash` is `source_output == (source_asset_id, source_amount,
    maker_owner_hash)`.
</content>
</invoke>
