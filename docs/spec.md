# Spec

## Table of Contents

- [Abstract](#abstract)
- [Architecture](#architecture)
  - [Operations](#operations)
    - [User](#user)
    - [Protocol](#protocol)
  - [Concurrency](#concurrency)
  - [Wallet](#wallet)
    - [request_transfer](#request_transfer)
  - [Client SDK](#client-sdk)
    - [create_payment_request](#create_payment_request)
    - [send_transaction](#send_transaction)
  - [Default Pocket](#default-pocket)
    - [Shield with Proof](#shield-with-proof)
    - [Shield without Proof](#shield-without-proof)
    - [Transfer](#transfer)
    - [Unshield](#unshield)
  - [Policy Pockets](#policy-pockets)
    - [Shield with Proof](#shield-with-proof-1)
    - [Shield without Proof](#shield-without-proof-1)
    - [Transfer](#transfer-1)
    - [Unshield](#unshield-1)
    - [Enter and Exit Pocket](#enter-and-exit-pocket)
- [SPP Proof - Shielded Pool ZK Proof](#spp-proof---shielded-pool-zk-proof)
- [View Tags](#view-tags)
- [Output UTXO Serialization](#output-utxo-serialization)
  - [Transfer](#transfer-2)
    - [Plaintext Layout](#plaintext-layout)
    - [Instruction Data Layout](#instruction-data-layout)
  - [UTXO Split](#utxo-split)
- [Transaction Viewing Key](#transaction-viewing-key)
- [SPP - Shielded Pool Program](#spp---shielded-pool-program)
  - [Accounts](#accounts)
  - [Instructions](#instructions)
    - [transact](#transact)
- [Policy Program Interface](#policy-program-interface)
- [RPC](#rpc)
  - [Photon Indexer](#photon-indexer)
  - [Pocket RPC](#pocket-rpc)
  - [Merge Service](#merge-service)
- [Notes](#notes)
- [Request Payment Flow Default Pocket](#request-payment-flow-default-pocket)
- [First Time Sync Wallet](#first-time-sync-wallet)

## Abstract

A Solana program for shielded transfers. Users retain custody and can disclose
per-transaction viewing keys on request. UTXOs can enter pockets; each pocket has
auditors, authorities, and a config (freeze authority, co-signer, permanent
delegate).

# Architecture

![Architecture](diagrams/architecture.png)

Source: [`diagrams/architecture.dot`](diagrams/architecture.dot). Regenerate with `just render-diagrams`.

1. Users — own wallets, build encrypted transactions, sign with P256.
2. Photon Indexer — indexes trees + encrypted UTXOs; default-pocket users fetch ciphertexts here.
3. Pocket RPC (with auditor) — RPC with auditor keys; decrypts and serves UTXOs to policy-pocket users.
4. Prover — generates Groth16 proofs. Users can generate client side proofs as well.
5. Relayer — fee-payer; submits transactions to SPP (default pocket) or to a Policy program (policy pocket).
6. Forester — drains the nullifier queue into the nullifier tree.
7. SPP (Shielded Pool Program) — verifies proofs, updates trees, moves SPL to and from the vaults.
8. Policy Programs (1..N) — config programs; verify policy proofs and CPI into SPP.
9. SPL interface vaults — per-mint SPL / Token-22 vaults holding all shielded tokens.
10. Tree accounts — co-located UTXO tree, nullifier tree, and nullifier queue.

Per-flow sequence diagrams are in the [User Flows](#user-flows) section below.


## Operations

### User

| # | Name | Description | Privacy |
| --- | --- | --- | --- |
| 1 | shield | Deposit SPL tokens into the shielded pool; existing UTXOs can be merged in the same transaction. | sender + amount visible; recipient hidden |
| 2 | proofless_shield | Public deposit without a proof. Allows shielding dynamic amounts, for example for the flow unshield, swap, shield. | fully public |
| 3 | unshield | Withdraw SPL tokens from the shielded pool to a public account. | sender hidden (relayer); recipient + amount visible |
| 4 | shielded transfer | Transfer value between shielded balances. | fully shielded (sender, recipient, amount) |

### Protocol

| # | Name | Description |
| --- | --- | --- |
| 1 | create_spl_interface | Initialize SPL/Token-22 pool escrow per token mint |
| 2 | create_tree | Initialize new Tree account (nullifier tree + queue and UTXO tree, co-located) |
| 3 | create_protocol_config | Initialize protocol config (pause authority) |
| 4 | update_protocol_config | Rotate protocol config authority |
| 5 | pause_tree | Freeze writes to a Tree account |


## Concurrency

1. A balance can be used concurrently when it is split up between a number of utxos.
2. To keep the balance spendable in one transaction we split it in up to X utxos

## Wallet

Signs transactions (P256 signature verified inside the SPP proof) and decrypts UTXOs encrypted to the user's pubkey.

Sender nonces are used to prevent replay of signed transactions with server prover and efficient fetching from the indexer.
Recipient nonces are used to index requested utxos from requested transfers efficiently.

**Seed secret derivations:**

`wallet_seed` is the BIP-39 mnemonic seed: `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" || passphrase, c=2048, dkLen=64)`.

1. P256 Keypair — derived from `wallet_seed` via BIP-32-style hierarchical derivation on the P-256 curve.
2. Nullifier Secret: `HKDF-SHA256(salt=∅, IKM=wallet_seed, info="zolana/nullifier", L=32)`
3. Sender View Tag Secret: `HKDF-SHA256(salt=∅, IKM=wallet_seed, info="zolana/sender_view_tag", L=32)`
4. Recipient View Tag Secret: `HKDF-SHA256(salt=∅, IKM=wallet_seed, info="zolana/recipient_view_tag", L=32)`
5. Ephemeral Secret: `HKDF-SHA256(salt=∅, IKM=wallet_seed, info="zolana/ephemeral", L=32)`

`get_sender_view_tag(tx_count)` and `get_recipient_request_view_tag(tx_count)` are indexed by the per-wallet `TxCount` counter (advanced on every outgoing transaction and on every `request_transfer`). `get_ephemeral_keypair(first_nullifier)` is *not* counter-indexed; it is bound to the first nullifier of the transaction's spent inputs, so the keypair is deterministic given the input UTXO set and unique per on-chain transaction (nullifier uniqueness implies keypair uniqueness).

### Methods:
1. sign_p256(msg)
2. encrypt
3. decrypt
4. encrypt_poseidon
5. decrypt_poseidon
6. `get_sender_view_tag(tx_count) = HKDF-SHA256(salt=∅, IKM=sender_view_tag_secret, info="zolana/sender_view_tag/" || u64_be(tx_count), L=32)`
7. `get_recipient_request_view_tag(tx_count) = HKDF-SHA256(salt=∅, IKM=recipient_view_tag_secret, info="zolana/recipient_request_view_tag/" || u64_be(tx_count), L=32)`
8. `send_pair_view_tag(counterparty_pubkey, i)`:
    1. `shared := ECDH(self.owner_sk, counterparty_pubkey)`
    2. `domain := HKDF-SHA256(salt=∅, IKM=shared, info="zolana/pair-domain/" || counterparty_pubkey, L=32)`
    3. `return HKDF-SHA256(salt=∅, IKM=domain, info="zolana/pair-hint/" || u64_be(i), L=32)`

    Used when sending to `counterparty_pubkey`. The direction label `counterparty_pubkey` in the inner HKDF binds the tag to "this direction has counterparty as recipient."
9. `receive_pair_view_tag(counterparty_pubkey, i)`:
    1. `shared := ECDH(self.owner_sk, counterparty_pubkey)`
    2. `domain := HKDF-SHA256(salt=∅, IKM=shared, info="zolana/pair-domain/" || self.owner_pubkey, L=32)`
    3. `return HKDF-SHA256(salt=∅, IKM=domain, info="zolana/pair-hint/" || u64_be(i), L=32)`

    Used when scanning for incoming from `counterparty_pubkey`. The direction label `self.owner_pubkey` binds the tag to "this direction has self as recipient."

    ECDH symmetry yields `send_pair_view_tag(B, i)` from Alice's wallet byte-equal to `receive_pair_view_tag(A, i)` from Bob's wallet — both compute `HKDF(HKDF(shared_AB, "...||B_pubkey"), "...||i")`. The reverse direction uses `"...||A_pubkey"` and produces a disjoint tag.
10. request_transfer(`asset_mint`, `amount`, `pocket_program_id`, `expiry_unix_ts`, `memo`)
11. `get_ephemeral_keypair(first_nullifier)`:
    1. `seed64 := HKDF-SHA256(salt=first_nullifier, IKM=ephemeral_secret, info="zolana/ephemeral", L=64)`
    2. `ephemeral_sk := int(seed64) mod n` where `n` is the P-256 group order
    3. `ephemeral_pubkey := ephemeral_sk · G` (SEC1-compressed)
    4. `return (ephemeral_sk, ephemeral_pubkey)`

    `first_nullifier` is the nullifier of the first spent input UTXO in the transaction (lexicographic position 0 in the circuit's input slots). Schemes that encrypt always have at least one real spent input, so `first_nullifier` is always defined when this function is called. A shared-account variant MAY substitute a shared secret for `ephemeral_secret`; the input parameter (`first_nullifier`) is unchanged.
12. sync(`start_timestamp`)
  1. sync default pocket loop: derive 1k sender_view_tags, request encrypted utxos based on tags, repeat until no matches
  2. sync policy pockets loop: for every pocket request balance

### State:
1. Utxos(optional)
2. TxCount (including requested payments)
3. last synced
4. `counterparties: map<their_pubkey → CounterpartyState>` where `CounterpartyState { sent_counter: u64, received_counter: u64 }`. Populated lazily: a new entry is created the first time the wallet sends to or receives from a counterparty. View-tag domains are re-derived on demand via `send_pair_view_tag` / `receive_pair_view_tag` (see [Wallet methods](#wallet)).

### request_transfer

Builds a payment request that a recipient hands to a sender out of band. The sender uses `recipient_request_view_tag` to stamp the recipient's ciphertext so the recipient can pull the payment by exact byte match from the indexer (see [Request Payment Flow](#request-payment-flow)).

**Inputs**

```rust
fn request_transfer(
    /// Solana SPL / Token-22 mint pubkey.
    asset_mint: [u8; 32],
    /// In units of `asset_mint`.
    amount: u64,
    /// All-zero = default pocket.
    pocket_program_id: [u8; 32],
    /// Recipient's promise to honor the request until this time.
    expiry_unix_ts: u64,
    /// Application-defined; opaque to the protocol; UTF-8, max 1024 bytes.
    memo: String,
) -> PaymentRequest
```

**Algorithm**

1. `tx_count := state.TxCount`
2. `recipient_request_view_tag := get_recipient_request_view_tag(tx_count)`
3. `state.TxCount += 1`
4. `return PaymentRequest { version=0, recipient_pubkey, recipient_request_view_tag, pocket_program_id, asset_mint, amount, expiry_unix_ts, memo }`

`TxCount` is incremented unconditionally — even if the sender never pays. Reusing a nonce across two outstanding requests would let the indexer link them.

**Output: `PaymentRequest`**

Canonical big-endian byte layout used on the wire. Packed, no length prefixes (`memo_len` precedes the variable-length `memo` tail).

```rust
/// 148 + memo.len() bytes total. Multi-byte integers are big-endian.
/// Wire format prefixes `memo` with its u16 BE byte length (0 if absent, max 1024).
struct PaymentRequest {
    /// Currently `0`.
    version: u8,
    /// P256 SEC1-compressed (1-byte prefix + 32 B X).
    recipient_pubkey: [u8; 33],
    recipient_request_view_tag: [u8; 32],
    /// All-zero = default pocket.
    pocket_program_id: [u8; 32],
    /// Solana SPL / Token-22 mint pubkey.
    asset_mint: [u8; 32],
    /// In units of `asset_mint`.
    amount: u64,
    expiry_unix_ts: u64,
    /// UTF-8; max 1024 bytes.
    memo: String,
}
```

## Client SDK

Higher-level methods built on top of [Wallet](#wallet) and [RPC](#rpc). The SDK does not touch the network; it assembles artifacts the caller submits via the RPC layer.

### create_payment_request

Recipient-side helper. Wraps [Wallet.request_transfer](#request_transfer) to produce a `PaymentRequest` for the recipient to share out of band with a prospective sender.

**Inputs**

```rust
fn create_payment_request(
    /// Solana SPL / Token-22 mint pubkey.
    asset_mint: [u8; 32],
    /// In units of `asset_mint`.
    amount: u64,
    /// `None` = default pocket.
    pocket_program_id: Option<[u8; 32]>,
    /// Request validity deadline.
    expiry_unix_ts: u64,
    /// Application-defined; UTF-8, max 1024 bytes.
    memo: Option<String>,
    /// Caller's wallet (see Wallet).
    wallet: &mut Wallet,
) -> PaymentRequest
```

**Algorithm**

1. `request := wallet.request_transfer(asset_mint, amount, pocket_program_id.unwrap_or(zero32), expiry_unix_ts, memo.unwrap_or(""))`
2. `return request`

**Output**

`PaymentRequest` — canonical 148 + `memo_len` byte layout (see [request_transfer](#request_transfer)).

**Notes**

1. Thin wrapper for API symmetry with [send_transaction](#send_transaction). The heavy lifting (nonce derivation, `TxCount` advance, byte layout) lives in [Wallet.request_transfer](#request_transfer).
2. The caller serializes the returned `PaymentRequest` to its canonical bytes and ships it OOB (QR, deeplink, NFC, messaging). Suggested base64-url encoding.
3. `wallet.TxCount` is advanced even if the request is never delivered or paid.

### send_transaction

Builds the SPP `transact` instruction data and the `encrypted_utxos` blob for a transfer. Encryption happens client-side; the wallet's `get_ephemeral_keypair` stays private to the SDK.

**Inputs**

```rust
fn send_transaction(
    /// Addressing info (see Recipient below).
    recipient: Recipient,
    /// In units of `recipient.asset_mint`.
    amount: u64,
    /// Caller's wallet (see Wallet).
    wallet: &mut Wallet,
) -> (Instruction, Vec<u8>)

struct Recipient {
    /// Recipient's P256 SEC1-compressed or Solana pubkey.
    pubkey: [u8; 33],
    /// Solana SPL / Token-22 mint pubkey.
    asset_mint: [u8; 32],
    /// Recipient-supplied view tag from a payment request; `None` triggers
    /// the unsolicited path (bootstrap or pair domain — see View Tags).
    recipient_request_view_tag: Option<[u8; 32]>,
    /// `None` = default pocket.
    pocket_program_id: Option<[u8; 32]>,
}
```

**Algorithm**
0. check wallet is synced.
1. `asset_id := AssetRegistry[recipient.asset_mint]` (via SPP [Asset registry](#accounts)).
2. `tx_count := wallet.TxCount`; `wallet.TxCount += 1`.
3. `sender_view_tag := wallet.get_sender_view_tag(tx_count)`.
4. Select sender input UTXOs covering `amount` + fees from wallet state; compute `change_amount`.
5. Compute `first_nullifier` from the first selected input UTXO (lexicographic input position 0).
6. `(ephemeral_sk, ephemeral_pubkey) := wallet.get_ephemeral_keypair(first_nullifier)` (private).
7. Pick random 31-byte `change_blinding_seed` and `recipient_blinding`.
8. Build the recipient output: `(owner=recipient.pubkey, asset_id, amount, blinding_seed=recipient_blinding_seed)`.
9. Build the sender change output: `(owner=sender_pubkey, asset_id, amount=change_amount, blinding_seed=change_blinding_seed, nullifier_data)`.
10. Encrypt each ciphertext with `AES-GCM(key = KDF(ECDH(ephemeral_sk, owner_pubkey)), plaintext)`. The sender ciphertext's `view_tag` is `sender_view_tag` (carried in `transact` ix data, not repeated in the blob). Each recipient ciphertext's `view_tag` is computed per [View Tags § Sender prefix selection](#view-tags); side effects on `wallet.counterparties` are applied as specified there. Concatenate per the [Transfer](#transfer-1) layout into `encrypted_utxos`.
11. `recipient_binding := sign_p256(Sha256BE(recipient.nonce || recipient.pubkey || amount || recipient_blinding_seed))` — consumed by the SPP proof.
12. compute zk proof tx hash
13. sign tx hash
14. Fetch the ZK proof (via the prover RPC or client-side prover).
15. Assemble the SPP `transact` instruction (see [transact](#transact)): `expiry_unix_ts`, `sender_view_tag`, `proof`, `relayer_fee`, `output_utxo_hashes`, `nullifier_root_index`, `tx_hash`, `msg_hash`, `public_sol_amount`, `public_spl_amount`, `encrypted_utxos`.
16. `return (instruction, encrypted_utxos)`.

**Output**

| Field | Type | Notes |
| --- | --- | --- |
| `instruction` | `Instruction` | Solana Instruction that can be sent to a relayer |
| `encrypted_utxos` | `Vec<u8>` | the ciphertext blob (also embedded in `message`; returned separately for callers that index or preview ciphertexts) |

**Notes**
1. `wallet.TxCount` is advanced once per call regardless of whether the caller ultimately submits. How do eth wallets do it?

## Default Pocket

The default pocket is similar to zcash and has no policy.
Users invoke the SPP directly.
The merge service is optional and can be used for performance and improved UX.

### Shield with Proof

```mermaid
sequenceDiagram
    participant Client as Client<br>(Wallet + Swaps)
    participant PocketRPC as Pocket RPC<br>(Photon / Prover / Relayer)
    participant Policy as Policy Program
    participant System as System Program<br>(Shielded Pool)
    participant Trees as Tree accounts
    participant Token as SPL Token Program
    participant SplInterface as SPL Interface Accounts<br>(PDA-owned token account)
    participant UserToken as User Token Account

    Note over Client: Build transaction
    Client->>PocketRPC: fetch_encrypted_utxos
    PocketRPC-->>Client: encrypted UTXOs
    Note over Client: 1. decrypt UTXOs <br> 2. select UTXOs (in) <br> 3. create new UTXOs (out) <br> 4. sign in and out utxos
    Client->>PocketRPC: fetch_proofs
    PocketRPC-->>Client: ZKP

    Note over Client: Submit transaction
    Client->>System: submit tx<br>transact

    Note over System: shield transfers SPL tokens<br>from user token account to SPL interface (PDA-owned)
    System->>Token: transfer (CPI)
    Token->>UserToken: debit
    Token->>SplInterface: credit

    Note over System: merges existing UTXOs + new deposit<br>updates trees<br>emits encrypted outputs
    System-->>Trees: update trees
    System-->>PocketRPC: index encrypted UTXOs
```

### Shield without Proof

```mermaid
sequenceDiagram
    participant Client as Client<br>(Wallet + Swaps)
    participant PocketRPC as Pocket RPC<br>(Photon / Prover / Relayer)
    participant System as System Program<br>(Shielded Pool)
    participant Trees as Tree accounts
    participant Token as SPL Token Program
    participant SplInterface as SPL Interface Accounts<br>(PDA-owned token account)
    participant UserToken as User Token Account

    Note over Client: Build transaction

    Note over Client: Submit transaction
    Client->>System: submit tx<br>transact

    Note over System: shield transfers SPL tokens<br>from user token account to SPL interface (PDA-owned)
    System->>Token: transfer (CPI)
    Token->>UserToken: debit
    Token->>SplInterface: credit

    Note over System: verifies proofs<br>updates trees<br>emits encrypted outputs
    System-->>Trees: update trees
    System-->>PocketRPC: index encrypted UTXOs
```

### Transfer

```mermaid
sequenceDiagram
    participant Client as Client<br>(Wallet + Swaps)
    participant PocketRPC as Pocket RPC<br>(Photon / Prover / Relayer)
    participant System as System Program<br>(Shielded Pool)
    participant Trees as Tree accounts

    Note over Client: Build transaction
    Client->>PocketRPC: fetch_encrypted_utxos
    PocketRPC-->>Client: encrypted UTXOs
    Note over Client: 1. decrypt UTXOs <br> 2. select UTXOs (in) <br> 3. create new UTXOs (out) <br> 4. sign in and out utxos
    Client->>PocketRPC: send transaction <br>(in utxos, out utxos, signature)
    PocketRPC->>System: submit tx<br>transact

    Note over System: verify ZKP
    System-->>Trees: update trees
    System-->>PocketRPC: index encrypted UTXOs
```

### Unshield

```mermaid
sequenceDiagram
    participant Client as Client<br>(Wallet + Swaps)
    participant PocketRPC as Pocket RPC<br>(Photon / Prover / Relayer)
    participant System as System Program<br>(Shielded Pool)
    participant Trees as Tree accounts
    participant Token as SPL Token Program
    participant SplInterface as SPL Interface Accounts<br>(PDA-owned token account)
    participant UserToken as User Token Account

    Note over Client: Build transaction
    Client->>PocketRPC: fetch_encrypted_utxos
    PocketRPC-->>Client: encrypted UTXOs
    Note over Client: 1. decrypt UTXOs <br> 2. Set unshield amount <br> 3. select UTXOs (in) <br> 4. create new UTXOs (out) <br> 5. sign in and out utxos

    Client->>PocketRPC: send transaction <br>(in utxos, out utxos, signature)
    PocketRPC->>System: submit tx<br>transact

    Note over System: unshield transfers SPL tokens<br>from SPL interface (PDA-owned) to recipient token account
    System->>Token: transfer (CPI)
    Token->>SplInterface: debit
    Token->>UserToken: credit

    Note over System: spends input UTXOs, emits change UTXO<br>updates trees<br>emits encrypted outputs
    System-->>Trees: update trees
    System-->>PocketRPC: index encrypted UTXOs
```

## Policy Pockets

A logical grouping of UTXOs governed by a policy program. Each pocket has its own auditor, authorities, and config.

| # | Name | Description |
| --- | --- | --- |
| 1 | Non-Custodial | Pockets are non-custodial. Control remains with user; auditor reads all UTXOs but cannot sign or spend |
| 2 | Extended UTXO schema | Includes state + extension fields (pocket address, ...); extensions is any data that is not part of the standard UTXO schema |
| 3 | Enter Pocket | A pocket can be entered by shield from an SPL token account, the standard shielded pool, or another pocket in a shielded transfer |
| 4 | Exit Pocket | A pocket can be exited by unshield to an SPL token account, the standard shielded pool, or another pocket in a shielded transfer |
| 5 | Merge Service | Opt-in backend service that merges a user's UTXOs into fewer larger UTXOs (see [Merge Service](#merge-service) section below). |

**Notes:**

1. The pocket config is a compressed account so it can be used inside the `pocket_transact` UTXO proof without revealing which pocket the user is in. As a PDA it would require an extra public account, making the pocket visible.
    1. by extending the attestation program and adding a verifyingkey upload we can make a generalized policy program.

### Shield with Proof

```mermaid
sequenceDiagram
    participant Client as Client<br>(Wallet + Swaps)
    participant PocketRPC as Pocket RPC<br>(Photon / Prover / Relayer)
    participant Policy as Policy Program
    participant System as System Program<br>(Shielded Pool)
    participant Trees as Tree accounts
    participant Token as SPL Token Program
    participant SplInterface as SPL Interface Accounts<br>(PDA-owned token account)
    participant UserToken as User Token Account

    Note over Client: Build transaction
    Client->>PocketRPC: get_balance
    PocketRPC-->>Client: balance
    Note over Client: 1. select UTXOs (in) <br> 2. create new UTXOs (out) <br> 3. sign in and out utxos
    Client->>PocketRPC: fetch_proofs
    PocketRPC-->>Client: ZKP

    Note over Client: Submit transaction
    Client->>Policy: submit tx<br>policy_transact
    Policy->>System: CPI: transact

    Note over System: shield transfers SPL tokens<br>from user token account to SPL interface (PDA-owned)
    System->>Token: transfer (CPI)
    Token->>UserToken: debit
    Token->>SplInterface: credit

    Note over System: merges existing UTXOs + new deposit<br>updates trees<br>emits encrypted outputs
    System-->>Trees: update trees
    System-->>PocketRPC: index encrypted UTXOs
    Note over PocketRPC: Decrypt UTXOs

```

### Shield without Proof

```mermaid
sequenceDiagram
    participant Client as Client<br>(Wallet + Swaps)
    participant PocketRPC as Pocket RPC<br>(Photon / Prover / Relayer)
    participant Policy as Policy Program
    participant System as System Program<br>(Shielded Pool)
    participant Trees as Tree accounts
    participant Token as SPL Token Program
    participant SplInterface as SPL Interface Accounts<br>(PDA-owned token account)
    participant UserToken as User Token Account

    Note over Client: Build transaction

    Note over Client: Submit transaction
    Client->>Policy: submit tx<br>policy_transact
    Policy->>System: CPI: transact

    Note over System: shield transfers SPL tokens<br>from user token account to SPL interface (PDA-owned)
    System->>Token: transfer (CPI)
    Token->>UserToken: debit
    Token->>SplInterface: credit

    Note over System: verifies proofs<br>updates trees<br>emits encrypted outputs
    System-->>Trees: update trees
    System-->>PocketRPC: index encrypted UTXOs
    Note over PocketRPC: Decrypt UTXOs
```

### Transfer

```mermaid
sequenceDiagram
    participant Client as Client<br>(Wallet + Swaps)
    participant PocketRPC as Pocket RPC<br>(Photon / Prover / Relayer)
    participant Policy as Policy Program
    participant System as System Program<br>(Shielded Pool)
    participant Trees as Tree accounts

    Note over Client: Build transaction
    Client->>PocketRPC: get_balance
    PocketRPC-->>Client: balance
    Note over Client: 1. Set amount <br> 2. set recipient address (in) <br> 4. sign recipient address and amount
	  Client->>PocketRPC: send transaction <br>(recipient, amount, signature)
    PocketRPC-->>Policy: submit tx<br>policy_transact
    Policy->>System: CPI: transact

    Note over System: verify ZKP
    System-->>Trees: update trees
    System-->>PocketRPC: index encrypted UTXOs
    Note over PocketRPC: Decrypt UTXOs
```

### Unshield

```mermaid
sequenceDiagram
    participant Client as Client<br>(Wallet + Swaps)
    participant PocketRPC as Pocket RPC<br>(Photon / Prover / Relayer)
    participant Policy as Policy Program
    participant System as System Program<br>(Shielded Pool)
    participant Trees as Tree accounts
    participant Token as SPL Token Program
    participant SplInterface as SPL Interface Accounts<br>(PDA-owned token account)
    participant UserToken as User Token Account

    Note over Client: Build transaction
    Client->>PocketRPC: get_balance
    PocketRPC-->>Client: balance
    Note over Client: 1. Set unshield amount <br> 2. set Recipient SPL Account (in) <br> 3. create new UTXOs (out) <br> 4. sign recipient SPL account and amount

	  Client->>PocketRPC: send transaction <br>(in utxos, out utxos, signature)
    PocketRPC-->>Policy: submit tx<br>policy_transact
    Policy->>System: CPI: transact

    Note over System: unshield transfers SPL tokens<br>from user token account to SPL interface (PDA-owned)
    System->>Token: transfer (CPI)
    Token->>UserToken: credit
    Token->>SplInterface: debit

    Note over System: merges existing UTXOs + new deposit<br>updates trees<br>emits encrypted outputs
    System-->>Trees: update trees
    System-->>PocketRPC: index encrypted UTXOs
    Note over PocketRPC: Decrypt UTXOs
```

### Enter and Exit Pocket

1. Enter, shield or transfer from default pocket
2. Exit, unshield or transfer from policy pocket

# SPP Proof - Shielded Pool ZK Proof

**Public Inputs**

| Input | Source |
| --- | --- |
| nullifiers | derived in-circuit from spent input UTXOs |
| output_utxo_hashes | instruction data |
| nullifier_root | resolved from `nullifier_root_index` against on-chain root cache |
| tx_hash | instruction data |
| public_sol_amount | instruction data |
| public_spl_amount | instruction data |
| public_spl_asset_pubkey | derived by SPP from the vault token account's mint |
| ProgramIDHashchain | instruction data |
| SolanaPubkeyHash | `Sha256BE(solana_signer)` derived by SPP from `payer` |
| data_hash | instruction data |
| policy_data | instruction data |

**UTXO Hash**

| # | Name | Description |
| --- | --- | --- |
| 1 | domain |  |
| 2 | owner | Owner pubkey as PoseidonPubkey |
| 3 | asset_id | Sha256BE |
| 4 | asset_amount |  |
| 5 | blinding | 31 random bytes |
| 6 | data_hash | Application data hash unconstrained in SPP proof. |
| 7 | policy_data | Policy data hash unconstrained in SPP proof. |
| 8 | policy_program_id |  |

**Nullifier Hash**

Nullifier hash: `H(utxo_hash, randomized_nullifier_key)`

1. `randomized_nullifier_key = Poseidon(utxo_hash, nullifier_secret)`
2. `nullifier_secret` is the wallet-derived Nullifier Secret (see [Wallet](#wallet)).

**Checks**

| Check | Description |
| --- | --- |
| UTXO Ownership | Spent input UTXOs MUST be authorized by their owner, either with a P256 signature verified in circuit or a Solana signer checked by SPP. The P256 signature binds `sender_view_tag` and `expiry_unix_ts` alongside the input UTXOs to prevent prover replay. Pubkeys are encoded as Poseidon(pubkey_low, pubkey_high). |
| Inclusion | Spent input UTXOs MUST exist in the UTXO tree. |
| Nullifier non-inclusion | Input nullifiers MUST NOT exist in the nullifier tree before the transaction. |
| Nullifiers | Public nullifiers MUST be well formed from the spent input UTXOs. |
| Output UTXOs | Output UTXOs MUST be well formed and match the public output commitments. |
| Balance Conservation | For each active asset, inputs plus public deposits MUST equal outputs plus public withdrawals and fees. |
| Transaction hash | Poseidon(input utxo hash chain, output utxo hash chain, external data hash, expiry_unix_ts).<br>Binds SPP, policy, and third-party proofs to the same transaction data, so all circuits prove statements about the same state transition. |
| Program ownership | UTXOs owned by a policy program MUST be authorized by a PDA signer of that program. Policy proofs are checked by the policy program before CPI into SPP. |
| Dummy input or output | ZK circuits are fixed size; dummy UTXOs allow a transaction to use fewer real inputs or outputs. Ownership, inclusion, nullifier non-inclusion, output, and balance checks are skipped for dummy UTXOs. |

**Utxo Ownership Check:**
1. EDDSA signer checked by SPP. User must sign the Solana transaction. 
2. P256 signature over recipient and recipient amount. The prover server can select UTXOs. UTXOs cannot have program data.
3. P256 signature over tx hash (Signs the full transaction.) UTXOs can have program data.

**Circuit Combinations**

| Circuit | Use | Shape |
| --- | --- | --- |
| 1 in 1 out | Shield with merge | 1 existing UTXO in, 1 combined output (existing balance + new deposit) |
| 1 in 2 out | Single-input transfer | 1 sender input UTXO, 1 recipient output, 1 change output; gas fees are sponsored |
| 3 in 3 out | Standard transfer | 1 SOL fee UTXO, 2 sender input UTXOs, 1 recipient output, 1 SPL change output, 1 SOL change output |
| 5 in 3 out | Higher concurrency | 1 SOL fee UTXO, 4 sender input UTXOs, 1 recipient output, 1 SPL change output, 1 SOL change output |
| 1 in 8 out | Split UTXO | Split 1 UTXO into up to 8 equal parts; equal parts reduce encrypted data |

# View Tags

A view tag is a 32-byte value prefixed to an encrypted slot so a wallet can locate its own ciphertexts on the indexer by byte-filter instead of trial-decrypting every slot. Recipients filter the indexer's `view_tag` column; the sender filters the same column to recover its own change. Monero introduced 1-byte probabilistic view tags in 2022; Zolana uses 32 bytes for deterministic exact match.

**Cases**

| # | Role | Pair state | View tag value |
| --- | --- | --- | --- |
| 1 | sender | — | `sender_view_tag` (own change) |
| 2.1.1 | recipient | first transfer, request issued | `recipient_request_view_tag` |
| 2.1.2 | recipient | first transfer, no request | `recipient_bootstrap_view_tag` |
| 2.2 | recipient | bootstrapped | `recipient_pair_view_tag` |

**Derivations**

| View tag | Derivation |
| --- | --- |
| `sender_view_tag` | `get_sender_view_tag(tx_count)` over `sender_view_tag_secret` |
| `recipient_request_view_tag` | `get_recipient_request_view_tag(tx_count)` over `recipient_view_tag_secret` |
| `recipient_pair_view_tag` | sender writes `send_pair_view_tag(counterparty_pubkey, i)`; recipient scans `receive_pair_view_tag(counterparty_pubkey, i)`. ECDH symmetry makes the two byte-equal across the pair. |
| `recipient_bootstrap_view_tag` | `Sha256BE(recipient_pubkey)` — SHA-256 of recipient's SEC1-compressed P256 pubkey |

Both helpers compute two chained HKDFs (see [Wallet](#wallet)):

```
HKDF(IKM=HKDF(IKM=ECDH(self.owner_sk, counterparty_pubkey),
              info="zolana/pair-domain/" || R_pubkey),
     info="zolana/pair-hint/" || u64_be(i))
```

`R_pubkey` is the recipient of the direction — `counterparty_pubkey` on the sender side (`send_pair_view_tag`), `self.owner_pubkey` on the recipient side (`receive_pair_view_tag`). ECDH symmetry plus the matched direction label produces the same byte value across the pair.

**Sender prefix selection**

```
prefix(recipient) :=
    if recipient.recipient_request_view_tag is Some:            # case 2.1.1
        ensure_counterparty(recipient.pubkey)
        return recipient.recipient_request_view_tag
    elif wallet.counterparties[recipient.pubkey] exists:        # case 2.2
        cp := wallet.counterparties[recipient.pubkey]
        tag := send_pair_view_tag(recipient.pubkey, cp.sent_counter)
        cp.sent_counter += 1
        return tag
    else:                                                       # case 2.1.2 — bootstrap
        ensure_counterparty(recipient.pubkey)
        return Sha256BE(recipient.pubkey)   # recipient_bootstrap_view_tag

ensure_counterparty(their_pubkey) :=
    if wallet.counterparties[their_pubkey] is None:
        wallet.counterparties[their_pubkey] := CounterpartyState(
            sent_counter = 0, received_counter = 0,
        )
```

Both bootstrap paths (2.1.1 and 2.1.2) create a sender-side counterparty entry. Subsequent transfers to the same recipient in either case fall into case 2.2. On the recipient side, the entry is created once they decrypt the first incoming bundle and read `sender_pubkey`. The first transfer in either direction bootstraps the pair.

**Recipient sync lookup**

```
# Case 2.1.1: outstanding payment requests
filter view_tag IN {recipient_request_view_tag_i for i in outstanding_requests}

# Case 2.1.2: any unsolicited bootstrap incoming
filter view_tag == Sha256BE(self.recipient_pubkey)    # recipient_bootstrap_view_tag

# Case 2.2: per-counterparty gap-limit walk
for cp in wallet.counterparties:
    gap_limit_walk(
        receive_pair_view_tag(cp.pubkey, j)
        for j in cp.received_counter ..,
        gap = 10_000,
    )
```

**Sender change recovery (case 1)**

```
gap_limit_walk(
    get_sender_view_tag(tx_count)
    for tx_count in wallet.TxCount ..,
    gap = 10_000,
)
# each recovered change carries nullifier_data for the spent inputs
```

SPP enforces single-use of `sender_view_tag` by inserting it into the nullifier tree alongside the input nullifiers (see [transact](#transact) check 7).

**Properties**

1. `recipient_bootstrap_view_tag` is a public function of `recipient_pubkey`, so all bootstrap transfers (case 2.1.2) to the same recipient are publicly linkable. Cases 2.1.1 and 2.2 are unlinkable to outside observers.
2. Direction-separated: `sender → recipient` and `recipient → sender` share the same ECDH secret but produce disjoint view tags, because the recipient-pubkey term in the inner HKDF info string flips with direction.
3. Gap limit `10 000` matches the convention from [First Time Sync Wallet](#first-time-sync-wallet). A counterparty silent for 10 000 or more consecutive transfers stops being tracked until the next bootstrap.
4. Disclosure of either party's `owner_sk` reveals the shared `domain` and the full pair-hint history in both directions. Same scope as owner-key disclosure.

# Output UTXO Serialization

Defines the layout of the `encrypted_utxos` blob carried by `transact`. SPP treats the blob as opaque; serialization is a default-pocket convention. Policy pockets define their own.

Both schemes apply AES-GCM encryption; keys are derived per recipient via `ECDH(ephemeral_sk, owner.pubkey)`. One `ephemeral_pubkey` is shared across all recipients in a transaction. The sender derives `(ephemeral_sk, ephemeral_pubkey)` from `get_ephemeral_keypair(first_nullifier)` (see [Wallet](#wallet)). Nullifier uniqueness on-chain implies a unique ephemeral keypair per transaction. Encryption is always sender-side. Slot prefixes (`view_tag`) are view tag values; see [View Tags](#view-tags).

Two schemes:

1. Transfer — confidential value movement; per-recipient AES-GCM bundles.
2. UTXO Split — one ciphertext for M equal-amount outputs under the same owner.

## Transfer

Confidential value transfer. One AES-GCM ciphertext per owner: one for the sender's change, `R` for the recipients. Variables used below: `R` = recipient count, `N` = spent-input count.

The recipient ciphertext additionally carries `sender_pubkey` so the recipient can bootstrap the [View Tags](#view-tags) pair domain. The sender change ciphertext additionally carries `nullifier_data` so that the optional senders indexer service can link the spent inputs.

### Plaintext Layout

Fields packed in declaration order with no length prefixes (the variable-length tail in the sender bundle is sized from `N`, known from the [transact](#transact) instruction).

#### Recipient

```rust
/// 114 B plaintext → 130 B ciphertext (after the 16-byte GCM tag).
struct TransferRecipientPlaintext {
    /// Recipient pubkey (1-byte prefix + P256 SEC1-compressed).
    owner_pubkey: [u8; 34],
    /// Sender's owner pubkey; bootstraps the View Tags pair domain.
    sender_pubkey: [u8; 33],
    /// `1` for SOL; SPL via per-mint Asset registry (`asset_id ≥ 2`).
    asset_id: u64,
    /// In units of `asset_id`.
    amount: u64,
    /// Random blinding for the single output.
    blinding: [u8; 31],
}
```

#### Sender

The sender change bundle carries two outputs (SPL change + SOL change). Per-output blindings derive from a single seed:

```
blinding_i = Sha256BE(blinding_seed || u8(position_i))
```

with `position = 0` for the SPL output and `position = 1` for the SOL output.

```rust
/// 89 + 32*N B plaintext → 105 + 32*N B ciphertext (after the 16-byte GCM tag).
struct TransferSenderPlaintext {
    /// Sender's owner pubkey (1-byte prefix + P256 SEC1-compressed).
    owner_pubkey: [u8; 34],
    /// Per-mint Asset registry; `0` if no SPL change.
    spl_asset_id: u64,
    /// `0` if no SPL change.
    spl_amount: u64,
    /// `0` if no SOL change.
    sol_amount: u64,
    /// Seed for the two per-output blindings (formula above).
    blinding_seed: [u8; 31],
    /// One full nullifier per spent input;
    nullifier_data: Vec<[u8; 32]>,
}
```

### Instruction Data Layout

The bytes the sender writes into the `encrypted_utxos` field of the [transact](#transact) instruction. Fields are packed in declaration order with no length prefixes.

```rust
/// Total on-wire size: 36 + (105 + 32*N) + 162*R bytes.
struct TransferEncryptedUtxos {
    /// Discriminator (TRANSFER).
    type_prefix: u8,
    /// Shared P256 pubkey for ECDH key derivation (1-byte prefix + SEC1-compressed).
    ephemeral_pubkey: [u8; 34],
    /// Number of recipient_slots that follow ciphertext_sender. Equals R.
    num_recipients: u8,
    /// Sender change bundle ciphertext: 89 + 32*N bytes plaintext + 16-byte GCM tag.
    /// View tag for this ciphertext is `sender_view_tag` from the transact
    /// instruction data, not carried in this blob.
    ciphertext_sender: Vec<u8>,
    /// R recipient slots packed back-to-back.
    recipient_slots: Vec<RecipientSlot>,
}
```

#### Recipient slot

```rust
/// 162 bytes total.
struct RecipientSlot {
    /// View tag value; see View Tags chapter for the four variants and selection rules.
    view_tag: [u8; 32],
    /// 114-byte recipient plaintext + 16-byte GCM tag.
    ciphertext: [u8; 130],
}
```

#### Sender

The sender ciphertext sits inline at offset 36 with no slot wrapper. Its view tag is `sender_view_tag`, carried in the [transact](#transact) instruction data — not in `encrypted_utxos`.

#### Sizes

`R` = number of recipients, `N` = number of spent inputs.

Total: `36 + 105 + 32·N + 162·R` bytes. Standard single-recipient transfer: `R = 1`, total `303 + 32·N`.

Blob size by recipient count (single-input transfer, `N = 1`; total = `173 + 162·R`):

| R | Bytes |
| --- | --- |
| 1 | 335 |
| 2 | 497 |
| 4 | 821 |
| 8 | 1469 |

## UTXO Split

All M outputs share owner, amount, and asset, so a single ciphertext encodes them. Each output UTXO derives a unique blinding from the blinding seed:

```
blinding_i = Sha256BE(blinding_seed || u8(i))
```

for `i = 0 .. M-1`.

### Plaintext Layout

```rust
/// 82 B plaintext → 98 B ciphertext (after the 16-byte GCM tag).
struct SplitBundlePlaintext {
    /// Shared owner of all M outputs (1-byte prefix + P256 SEC1-compressed).
    owner_pubkey: [u8; 34],
    /// M — number of equal-amount outputs.
    num_outputs: u8,
    /// `1` for SOL; SPL via per-mint Asset registry (`asset_id ≥ 2`).
    asset_id: u64,
    /// Shared across all M outputs.
    asset_amount: u64,
    /// Seed for the M per-output blindings (formula above).
    blinding_seed: [u8; 31],
}
```

### Instruction Data Layout

```rust
/// 133 bytes total. Packed, no length prefixes.
/// Owner-side view tag is `sender_view_tag` from the transact instruction data
/// (all M outputs share the sender as owner).
struct SplitEncryptedUtxos {
    /// Discriminator (SPLIT).
    type_prefix: u8,
    /// Shared P256 pubkey for ECDH key derivation (1-byte prefix + SEC1-compressed).
    ephemeral_pubkey: [u8; 34],
    /// 82-byte plaintext + 16-byte GCM tag.
    ciphertext: [u8; 98],
}
```

# Transaction Viewing Key

Every ciphertext in a transaction is encrypted under a single empheral key so that the secret key of the emphemeral key can decrypt both the senders change and recipient utxos of the transaction.

**Properties**

- **Scope**: one transaction.
- **Read-only**: viewing keys grant decryption only.
- **Derivable on demand**: viewing keys are derived on demand from the shielded transaction with `get_ephemeral_keypair(first_nullifier)`.

# SPP - Shielded Pool Program

## Accounts

| Account | Description |
| --- | --- |
| Tree account | Contains the nullifier tree (`light-batched-merkle-tree`, H=40), nullifier queue, and UTXO tree (sparse Merkle tree, H=26). |
| SPL interface vault | Per-mint SPL / Token-22 vault holding all shielded SPL tokens. |
| Asset registry | PDA derived from the mint, set at `create_spl_interface` time. Stores the `asset_id: u64` assigned to that mint (used as the compact asset identifier inside UTXOs and ciphertexts). `asset_id = 1` is reserved for native SOL and has no `Asset registry` entry; SPL mints get `asset_id ≥ 2`. |
| Asset counter | Singleton account holding the monotonic `next_asset_id: u64`. Initialized to `2` (since `1` is reserved for SOL) and incremented on each `create_spl_interface`. |
| Protocol config | Singleton account; pause authority and protocol-wide settings. |

## Instructions

| Instruction | Description |
| --- | --- |
| transact | Tag 0; carries shield/unshield/shielded transfer; verifies proofs, updates trees |
| proofless_shield | Tag 1; public deposit; hashes UTXO and inserts into UTXO tree |
| pocket_transact | Tag 2; carries shield/unshield/shielded transfer; verifies proofs, updates trees; verifies encrypted UTXOs are properly encrypted to pocket auditor + recipients |
| pocket_authority_transact | Tag 3; proves correctness of a state transition by a pocket authority (freeze, thaw, transaction with permanent delegate, ...) |
| create_spl_interface | Tag 6; admin; reads + bumps the `Asset counter`, creates the per-mint SPL interface vault and writes the assigned `asset_id` into the per-mint `Asset registry` PDA. |
| create_tree | Tag 7; admin; initializes the shared Tree account (nullifier tree + queue, UTXO tree) |
| create_protocol_config | Tag 9; admin |
| update_protocol_config | Tag 10; admin |
| pause_tree | Tag 11; admin can pause and unpause trees |
| create_pocket_config | Tag 12; creates a new pocket config; fields: owner, pocket_authority_transact_is_enabled |
| update_pocket_config_owner | Tag 13; transfers ownership of a pocket config; only callable by current owner. TBD: spec out semantics. |
| update_pocket_config | Tag 14; toggles whether pocket_authority_transact_is_enabled is enabled. If disabled and the config owner is burned, the policy program cannot rug the user (no permanent delegate). |

### `transact`

**Discriminator:** 0

**Description.** Implements shield, unshield, or shielded transfer. Verifies the proof, nullifies input UTXOs by inserting nullifiers into the nullifier queue, and appends output UTXOs to the UTXO tree.

**Accounts**

| # | Name | W | S | Notes |
| --- | --- | --- | --- | --- |
| 1 | tree_account | x |   | nullifier queue + nullifier tree + UTXO tree |
| 2 | payer |   | x | relayer (transfer/unshield) or user (shield) |

**Instruction data**

`M` = number of output UTXOs, `N` = number of spent inputs.

```rust
struct TransactIxData {
    /// Unix timestamp in seconds.
    expiry_unix_ts: u64,
    /// View tag from sender's `get_sender_view_tag(tx_count)` (see Wallet);
    /// signed alongside the input UTXOs (prover-replay protection) and
    /// inserted into the nullifier tree (reuse protection).
    sender_view_tag: [u8; 32],
    /// Compressed Groth16 proof.
    proof: [u8; 192],
    /// Zero on shield (payer = user).
    relayer_fee: u16,
    /// One per output; appended to the UTXO tree. Length M.
    output_utxo_hashes: Vec<[u8; 32]>,
    /// Ref into nullifier-tree root cache. Length N.
    nullifier_root_index: Vec<u16>,
    tx_hash: Option<[u8; 32]>,
    /// Required for P256 sig verification. Program hashes Sha256(msg_hash)
    /// because that's expensive in the zk proof. We sign either msg_hash
    /// or tx_hash. If msg_hash is Some, it is used as the public input
    /// regardless of whether tx_hash is set.
    msg_hash: Option<[u8; 32]>,
    /// `Some` for shield/unshield SOL, `None` for shielded transfer.
    public_sol_amount: Option<u64>,
    /// `Some` for shield/unshield SPL, `None` for shielded transfer.
    public_spl_amount: Option<u64>,
    /// Opaque ciphertext blob; not checked by the program.
    /// Layout per Output UTXO Serialization.
    encrypted_utxos: Vec<u8>,
}
```

Size by circuit shape (total tx size, ciphertext included)\*:

| Circuit | N (nullifiers) | M (output utxo hashes) | ciphertext (B) | tx overhead (B)\*\* | shield / unshield (B) | transfer (B) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 in 1 out | 1 | 1 | 51 | 206 | 643 | — |
| 1 in 2 out | 1 | 2 | 335 | 206 | 959 | 877 |
| 3 in 3 out | 3 | 3 | 399 | 206 | 1059 | 977 |
| 5 in 3 out | 5 | 3 | 463 | 206 | 1127 | 1045 |
| 1 in 8 out | 1 | 8 | 133 | 206 | 949 | 867 |

\* assumes `msg_hash = Some` (33 B; sender signs over the recipient binding) and `tx_hash = None` (1 B). Transfer ciphertext sizes assume `R = 1` recipient, per the [Output UTXO Serialization § Transfer](#transfer-2) layout. Add 162 B per extra recipient.
\*\* assumes ALT for `tree_account`, `payer` and `program_id` inline; overhead = 64 (signature) + 3 (message header) + 65 (inline account keys: compact-u16 count + 2 × 32-byte pubkeys for `payer` and `program_id`) + 32 (recent blockhash) + 36 (ALT section: compact-u16 count + 32-byte ALT pubkey + writable count + writable index + readonly count) + 6 (instruction body: program_id_index + account_indices + data_len_varint). Shield/unshield totals add 66 B (`+64` for inline `user_spl_token_account` and `vault_spl_token_account` pubkeys, `+2` for their indices in the instruction body) because these accounts vary per transaction and cannot be served from the ALT.

**Checks**

1. `current_unix_ts <= expiry_unix_ts` (Solana `Clock.unix_timestamp`)
2. Each `nullifier_root_index` references a non-stale root.
3. `tree_account` is not paused.
4. Proof verifies against public inputs.
5. Append each `output_utxo_hashes[i]` to the UTXO sparse Merkle tree.
6. Insert each nullifier into the nullifier queue.
7. Insert `sender_view_tag` into the nullifier queue. Rejects on duplicate, which guarantees each sender `tx_count` slot is used at most once on-chain. The wallet is trusted to use the same value to prefix the sender's change ciphertext in `encrypted_utxos`; SPP does not check the ciphertext.
8. If `public_sol_amount` is `Some`, transfer `public_sol_amount + relayer_fee` lamports of SOL between `payer` and the pool (shield: payer → pool; unshield: pool → recipient). The `relayer_fee` portion compensates the relayer.
9. If `public_spl_amount` is `Some`, CPI the token program to transfer SPL between the user and the vault token account (shield: user → vault; unshield: vault → recipient).

# Policy Program Interface

**Accounts**

Accounts can be Solana or compressed accounts.

| # | Name | Description |
| --- | --- | --- |
| 1 | Pocket config | Configures authorities and features of a pocket |
| 2 | User config | Configures a shared encryption key |

**Instructions**

A policy program is free to implement the following instructions and more. Tags are local to each policy program.

| Instruction | Description |
| --- | --- |
| transact | Tag 0; verify policy proof, CPI SPP `pocket_transact` |
| proofless_shield | Tag 1; public deposit; no encryption; CPI SPP `proofless_shield` |
| authority_transact | Tag 3; proves correctness of a state transition by a pocket authority (freeze, thaw, transaction with permanent delegate, ...). Merge UTXOs on behalf of the user. Pocket authority has full access to all UTXOs owned by the pocket. The access is constrained by the policy program implementation. CPI SPP `pocket_authority_transact` |
| create_pocket_config | Tag 4; admin: creates account for a pocket; the config is public, sets auditor P256 key, pocket authority, freeze authority, permanent authority, co-signer |
| update_pocket_config | Tag 5; admin: pocket authority updates the pocket config |

**Notes:**

1. If the recipient does not have a config account the output UTXO is encrypted to the recipient.

# RPC

All RPC services can be run independently. RPC providers can offer the endpoints of the services in a bundled API.

## Photon Indexer

The rpc or pocket rpc have two purposes providing balance information and sending transactions.

**Methods:**

1. get_encrypted_utxos
2. get_proof
3. send_transaction
    
    Modes:
    
    1. server built proof inputs
        1. msg_hash(recipient + amount)
        The user does not care which utxos are used.
        Self-custody is guaranteed by the zkp.
    2. client built proof inputs
        1. msg_hash(TX_HASH)
        TX_HASH includes all in and out utxos public amounts etc
        The user sets all proof parameters and which UTXOs are used.

**Storage: `shielded_utxos`**

One row per ciphertext, sourced from either:

- the `encrypted_utxos` blob of a `transact` / `pocket_transact` instruction (one row per recipient slot, plus one for the sender change), or
- the `proofless_shield` instruction (one row per deposited output; `view_tag = NULL`, `ciphertext = NULL`, owner and amount are read from instruction data with `blinding = 0` inferred).

Spend state is intentionally absent: UTXOs are private and the indexer cannot link nullifier insertions back to UTXOs. Users derive their own spent set client-side after decrypting (sender change ciphertexts carry `nullifier_data: [u8;32] × N`).

UTXO tree leaves and Merkle witnesses live in the existing `state_trees` table
and are joined back from `shielded_utxos.leaf_indices`.

```sql
CREATE TABLE shielded_utxos (
    id                BIGSERIAL PRIMARY KEY,
    slot              BIGINT     NOT NULL,                  -- from Blocks
    tx_signature      BYTEA(64)  NOT NULL,
    tx_index          INT        NOT NULL,                  -- within slot
    ciphertext_index  SMALLINT   NOT NULL,                  -- 0 = sender bundle for transfers
    scheme            SMALLINT   NOT NULL,                  -- 0=transfer, 1=split, 2=proofless_shield
    tree              BYTEA(32)  NOT NULL,                  -- Tree account pubkey
    pocket_program_id BYTEA(32),                            -- NULL = default pocket
    leaf_indices      BIGINT[]   NOT NULL,                  -- UTXO tree leaves this ciphertext describes
    ephemeral_pubkey  BYTEA(34),                            -- schemes 0 and 1 only
    view_tag          BYTEA(32),                            -- see View Tags chapter
    ciphertext        BYTEA                                  -- NULL for proofless_shield
);
```

`get_encrypted_utxos(filters: [(offset, values: Vec<bytes>)], cursor, limit)`
maps each byte filter to an indexed column above based on `(scheme, offset)`.
`values` is a non-empty list — the column matches if it equals **any** of the
listed values (SQL `IN`). Multiple filters on **different** columns are
intersected (AND). Filters on unindexed offsets MAY be rejected. Servers MUST
accept at least 10 000 values per filter on `view_tag`; larger
batches MAY be rejected with a documented limit.

## Pocket RPC

**Methods:**

1. get_decrypted_utxos
2. get_balance
3. get_instruction (for shield the user must sign directly)

## Merge Service

The shielded pool program has merge service registry accounts. Users can whitelist one or more merge service accounts (opt-in).

**Enable merge service,** a user creates a nullifier H(user_pubkey, merge_service_pda) in a dedicated merge service tree.

**Merge UTXOs,** a merge service proves that a nullifier exists and that the user utxos are merged and encrypted correctly.

**Disable merge service**, user removes nullifier from merge service tree.

**Caveats:**

1. The merge service needs to be able to decrypt user UTXOs.

**Questions:**

1. How is merge service paid?
(You don't want to pay based on tx that creates weird incentives.)

# Notes

1. policy pockets can only be entered and exited from and to the default pocket
2. by default every pocket that is deployed creates a new program, later we can deploy a standard pocket program that has a set of extensions.
3. **We need to expose nullifier data with the encrypted utxos so that the RPC knows which utxos were spent based on decrypted outputs**
4. By publishing the cleartext output utxo data we would essentially do compressed token transfers.

# Request Payment Flow Default Pocket

Recipient-pull flow. The recipient supplies a one-time `view_tag` that the sender stamps onto the recipient's ciphertext, so the recipient can pull the payment by exact byte-match instead of grinding every transfer.

```mermaid
sequenceDiagram
    participant Recipient as Recipient Client
    participant Sender as Sender Client
    participant RPC as RPC<br/>(Photon Indexer / Relayer)

    Note over Recipient: send payment request<br> (out of band)
    Recipient->>Sender: 

    Note over Sender: (message, encrypted_utxos) =<br/>sdk.send_transaction(recipient, amount, wallet)
    Sender->>RPC: send_transaction
    RPC-->>Sender: signature

    Note over Recipient: Poll for payment tx
    Recipient->>RPC: get_encrypted_utxos<br/>filter: view_tag == recipient_request_view_tag
    RPC-->>Recipient: ciphertext
    Note over Recipient: Decrypt<br/>recover output UTXO

    Note over Sender: Poll for payment tx
    Sender->>RPC: get_encrypted_utxos<br/>filter: view_tag == sender_view_tag
    RPC-->>Sender: ciphertext
    Note over Sender: Decrypt<br/>recover change UTXO + spent nullifiers
```

Notes:

1. The payment request is transferred out of band (QR code, deeplink, message). Zolana does not standardize this channel.
2. The sender's `view_tag` is independent from the recipient's — they come from different per-wallet view-tag secrets.
3. Without a payment request, the recipient has no `view_tag` to filter on and would have to fetch every transfer ciphertext since their cursor. Unsolicited transfers in this scheme are unsupported.
4. Payment requests advance the tx counter without sending a tx which could result in a conflict, maybe we should add separate domains for user tx and requested tx.


# First Time Sync Wallet

Restores `Utxos`, `TxCount`, and `last_synced` from a BIP-39 mnemonic. Fetches from known Pocket RPCs and the Photon Indexer in parallel, decrypting UTXO ciphertexts as they arrive.

```text
def first_time_sync(wallet, indexer, known_pockets):
    # 1. Derive seed secrets from mnemonic.
    wallet.derive_seeds()       # P256, nullifier_secret, sender_view_tag_secret,
                                # recipient_view_tag_secret, ephemeral_secret

    # 2. Launch all fetches concurrently.
    pocket_futures = {
        pid: spawn(connect_pocket_rpc(pid).get_decrypted_utxos_and_balance())
        for pid in known_pockets
    }
    confidential_future = spawn(indexer.get_encrypted_utxos(
        view_tag_in=[Sha256BE(wallet.recipient_pubkey)]
    ))
    indexer_stream = spawn(gap_limit_scan(wallet, indexer, request_size=10_000))

    # 3. Decrypt indexer ciphertexts as they stream in (parallel workers).
    utxos = {}
    spent_nullifiers = []
    for ct in parallel_decrypt(chain(indexer_stream, [confidential_future.await()])):
        key       = KDF(ECDH(wallet.owner_sk, ct.ephemeral_pubkey))
        plaintext = AES_GCM_decrypt(key, ct.body)
        utxo      = parse_utxo(plaintext, ct.scheme)
        utxos[utxo.hash] = utxo
        if ct.is_sender_change:
            spent_nullifiers += plaintext.nullifier_data    # [u8;32] × N

    # 4. Discover counterparties from incoming ciphertexts (each incoming
    #    recipient bundle carries sender_pubkey; see Encryption Schemes § Transfer)
    #    and walk their pair-domain view tags. Repeat until convergence.
    counterparties = {}                                     # their_pubkey -> CounterpartyState
    pending = {utxo.sender_pubkey for utxo in utxos.values() if utxo.role == "incoming"}
    while pending:
        next_pending = set()
        for cp in pending:
            cursor = 0
            while True:
                tags = [wallet.receive_pair_view_tag(cp, i) for i in range(cursor, cursor + 10_000)]
                hits = indexer.get_encrypted_utxos(view_tag_in=tags)
                if not hits: break
                for ct in parallel_decrypt(hits):
                    plaintext = AES_GCM_decrypt(KDF(ECDH(wallet.owner_sk, ct.ephemeral_pubkey)), ct.body)
                    utxo = parse_utxo(plaintext, ct.scheme)
                    utxos[utxo.hash] = utxo
                    if utxo.sender_pubkey not in counterparties:
                        next_pending.add(utxo.sender_pubkey)
                cursor += 10_000
            counterparties[cp] = CounterpartyState(
                sent_counter=0, received_counter=cursor,
            )
        pending = next_pending - counterparties.keys()

    # 5. Reconstruct historical spent set locally.
    for nf in spent_nullifiers:
        if nf in utxos:
            utxos[nf].spent = True

    # 6. Join policy-pocket fetches.
    pocket_state = {pid: f.await() for pid, f in pocket_futures.items()}

    # 7. Persist.
    wallet.Utxos          = utxos
    wallet.counterparties = counterparties
    wallet.TxCount        = max_observed_tx_count(utxos) + 1
    wallet.last_synced    = current_slot()
    return wallet, pocket_state


def gap_limit_scan(wallet, indexer, request_size):
    # Two-axis gap-limit walk; yields ciphertexts as they arrive.
    cursor = 0
    sender_done, recipient_done = False, False
    while not (sender_done and recipient_done):
        queries = {}
        if not sender_done:
            tags = [wallet.get_sender_view_tag(i) for i in range(cursor, cursor + request_size)]
            queries["sender"] = indexer.get_encrypted_utxos(view_tag_in=tags)
        if not recipient_done:
            tags = [wallet.get_recipient_request_view_tag(i) for i in range(cursor, cursor + request_size)]
            queries["recipient"] = indexer.get_encrypted_utxos(view_tag_in=tags)
        results = await_parallel(queries)
        sender_done    = sender_done    or len(results.get("sender", []))    == 0
        recipient_done = recipient_done or len(results.get("recipient", [])) == 0
        yield from sum(results.values(), [])
        cursor += request_size
```

**Sync Time Estimates**

Assumptions:

1. Indexer request size: `10 000` view tags per `view_tag IN (...)` query.
2. Indexer RTT: 100 ms.
3. ECDH P-256 per ciphertext: 100 μs.
4. Decrypt and request in parallel.

| Tx history size | Windows / axis | Concurrent RTTs | Decrypt (sequential) | Total (sequential) | Total (parallel, ≥10 threads) |
| --- | --- | --- | --- | --- | --- |
| 10 | 1 hit + 1 confirm | 2 | < 1 ms | ~200 ms | ~200 ms |
| 1 000 | 1 + 1 | 2 | ~100 ms | ~200 ms | ~200 ms |
| 10 000 | 1 + 1 | 2 | ~1 s | ~1.2 s | ~250 ms |
| 100 000 | 10 + 1 | 11 | ~10 s | ~10 s | ~1.2 s |
| 1 000 000 | 100 + 1 | 101 | ~100 s | ~100 s | ~10–12 s |


# TODO:
1. keep wallet synced user flow (answer is polling for the next X view_tags, and other decryption hints)
2. remove simplified signature
3. add merge delegate to utxo hash, merge circuit, merge user flow.
