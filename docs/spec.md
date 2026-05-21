# Spec

## Table of Contents

- [Abstract](#abstract)
- [Architecture](#architecture)
  - [Operations](#operations)
    - [User](#user)
    - [Protocol](#protocol)
  - [Concurrency](#concurrency)
  - [Wallet](#wallet)
    - [Methods](#methods)
    - [State](#state)
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
  - [Sender View Tag](#sender-view-tag)
  - [Recipient view tag](#recipient-view-tag)
  - [Derivations](#derivations)
- [Output UTXO Serialization](#output-utxo-serialization)
  - [Transfer](#transfer-2)
    - [Plaintext Layout](#plaintext-layout)
    - [Instruction Data Layout](#instruction-data-layout)
  - [UTXO Split](#utxo-split)
    - [Plaintext Layout](#plaintext-layout-1)
    - [Instruction Data Layout](#instruction-data-layout-1)
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
  - [Registry](#registry)
  - [Sync Delegate](#sync-delegate)
- [Notes](#notes)
- [User Flows](#user-flows)
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
5. Relayer — fee-payer; submits transactions to SPP (default pocket), to the ZK Swap program, or to a Policy program (policy pocket).
6. Forester — processes the nullifier queue into the nullifier tree.
7. SPP (Shielded Pool Program) — verifies proofs, updates trees, moves SPL to and from the vaults.
8. ZK Swap Program — settles a swap by CPI into a Policy program or directly into SPP.
9. Policy Programs (1..N) — config programs; verify policy proofs and CPI into SPP.
10. SPL interface vaults — per-mint SPL / Token-22 vaults holding all shielded tokens.
11. Tree accounts — co-located UTXO tree, nullifier tree, and nullifier queue.

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

Sender view tags index the sender's own change ciphertexts for sync and are inserted into the nullifier tree to guarantee single-use per `TxCount` slot. Recipient request view tags index incoming ciphertexts from payment requests and are not guaranteed single use.

**ShieldedPubkey.** A wallet identity is a pair `ShieldedPubkey = (signing_pk, encryption_pk)`:

- `(owner_sk, signing_pk)` — P-256 keypair verified in-circuit by the SPP. Owns UTXOs (controls spend), signs transactions. Synonym in older prose: `(owner_sk, owner_pubkey)`.
- `(encryption_sk, encryption_pk)` — P-256 keypair used for every sender→recipient ECDH: [View Tags](#view-tags) derivation and [Output UTXO Serialization](#output-utxo-serialization) AES-GCM key derivation. The wallet decrypts incoming ciphertexts with `encryption_sk`; senders encrypt to `encryption_pk`.

The wallet publishes `ShieldedPubkey` via the [Registry](#registry); senders translate a Solana address into `ShieldedPubkey` by registry lookup (see [Wallet Transfer User Flows](#wallet-transfer-user-flows)).

**Seed secret derivations:**

`wallet_seed` is the BIP-39 mnemonic seed: `PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" || passphrase, c=2048, dkLen=64)`.

1. Owner P256 Keypair `(owner_sk, signing_pk)` — derived from `wallet_seed` via BIP-32-style hierarchical derivation on the P-256 curve.
2. Nullifier Secret: `HKDF-SHA256(salt=∅, IKM=owner_sk, info="zolana/nullifier", L=32)`. Used to compute `randomized_nullifier_key` per spent UTXO; lets the wallet mark its own UTXOs as spent during sync.
3. Ephemeral Secret: `HKDF-SHA256(salt=∅, IKM=wallet_seed, info="zolana/ephemeral", L=32)`. Used by the sender to derive `(ephemeral_sk, ephemeral_pubkey)` on each outgoing transaction.
4. Encryption P256 Keypair `(encryption_sk, encryption_pk)` — `encryption_sk := owner_sk`, `encryption_pk := signing_pk`. The `ShieldedPubkey` has two slots; for now both are set to the owner key.
5. View tag secrets — see [View Tags § Derivations](#view-tags). Both `sender_view_tag_secret` and `recipient_view_tag_secret` derive from `encryption_sk`.

Counter sources for view-tag derivations:

- `get_sender_view_tag(tx_count)` — `TxCount`, advanced on every outgoing transaction.
- `get_recipient_request_view_tag(request_count)` — `RequestCount`, advanced on every `request_transfer`.
- `send_shared_view_tag(recipient_pubkey, i)` — `known_recipients[recipient_pubkey]`, advanced on every send to that recipient that uses this tag.
- `derive_shared_view_tag(sender_pubkey, i)` — `known_senders[sender_pubkey]`, advanced as the wallet's incoming scan for that sender consumes successive `i` values.

`get_ephemeral_keypair(first_nullifier)` is *not* counter-indexed; it is bound to the first nullifier of the transaction's spent inputs, so the keypair is deterministic given the input UTXO set and unique per Solana transaction (nullifier uniqueness implies keypair uniqueness).

### Methods:

**Signing:**

1. `sign_p256(msg) -> P256Signature` — P256 ECDSA over `msg` with `owner_sk`; SHA-256 digest per ECDSA-P256. All in-circuit-verified signatures sign `private_tx_hash`, which covers every input, every output, the external-data hash, and `expiry_unix_ts`; no separate per-field signatures.
2. `build_transact_witness(inputs, outputs, expiry_unix_ts, sender_view_tag, external_data_hash) -> ProverWitness` — assembles every private value the prover needs (input UTXO openings and blindings, per-input `randomized_nullifier_key`, output commitments, the P256 signature over `private_tx_hash`).

**Encryption:**

3. `begin_tx(first_nullifier) -> TxHandle` — derives `(ephemeral_sk, ephemeral_pubkey)` from `HKDF(salt=first_nullifier, IKM=ephemeral_secret, info="zolana/ephemeral")` and returns an opaque handle plus the public `ephemeral_pubkey`. The `ephemeral_sk` is held inside the handle and reused across all recipients of the same transaction.
4. `encrypt_to_recipient(handle, recipient_encryption_pk, plaintext) -> Ciphertext` — AES-GCM seal with key `KDF(ECDH(handle.ephemeral_sk, recipient_encryption_pk))`.
5. `decrypt(ciphertext, ephemeral_pubkey, key_index) -> Result<Plaintext>` — AES-GCM open with key `KDF(ECDH(encryption_sk_{key_index}, ephemeral_pubkey))`. `key_index` selects the registry entry's encryption key for historic decryption; default = current.

**Nullifier fingerprinting:**

6. `randomized_nullifier_key(utxo) -> [u8; 32]` — `Poseidon(utxo_hash, nullifier_secret)`.
7. `randomized_nullifier_keys(utxos: &[Utxo]) -> Vec<[u8; 32]>` — batch variant for sync.

**View tags:**

Each method takes `key_index` (defaults to the current encryption key) and returns the 32-byte tag value.

8. `get_sender_view_tag(key_index, tx_count)` — see [View Tags § Derivations](#view-tags).
9. `get_recipient_request_view_tag(key_index, request_count)` — see [View Tags § Derivations](#view-tags).
10. `send_shared_view_tag(key_index, counterparty_pubkey, i)` — sender-side `recipient_shared_view_tag`.
11. `derive_shared_view_tag(key_index, counterparty_pubkey, i)` — recipient-side `recipient_shared_view_tag`.
12. `view_tag_range(kind, key_index, range, counterparty_pubkey: Option<P256Pubkey>) -> Vec<[u8; 32]>` — batch variant for sync queries; `kind` selects the underlying method above.

**Payment requests & sync:**

13. `request_transfer(asset_mint, amount, pocket_program_id, expiry_unix_ts, memo) -> PaymentRequest` — see [request_transfer](#request_transfer).
14. `sync(start_timestamp)`:
    1. sync default pocket loop: derive sender_view_tags, request encrypted utxos based on tags, repeat until no matches
    2. sync policy pockets loop: for every pocket request balance

One ephemeral keypair is shared across all recipients of a transaction (see [Output UTXO Serialization](#output-utxo-serialization)); `begin_tx` returns one handle per transaction. A shared-account variant MAY substitute a shared secret for `ephemeral_secret`; `first_nullifier` is unchanged.

### State:
1. `Utxos: Vec<Utxo>` (optional cache; can be rebuilt from sync).
2. `TxCount: u64` — outgoing transaction counter under the current encryption key; indexes `get_sender_view_tag`. Resets to 0 on encryption-key rotation; [First Time Sync](#first-time-sync-wallet) rebuilds per-key history.
3. `RequestCount: u64` — `request_transfer` counter under the current encryption key; indexes `get_recipient_request_view_tag`. Resets to 0 on encryption-key rotation.
4. `last_synced: Timestamp`
5. `known_senders: map<sender_pubkey → received_counter: u64>` — next index to scan in `derive_shared_view_tag(sender_pubkey, i)` under the current encryption key. Populated lazily on first receipt from a new sender. Resets on encryption-key rotation; [First Time Sync](#first-time-sync-wallet) rebuilds per-key history.
6. `known_recipients: map<recipient_pubkey → sent_counter: u64>` — next index to use in `send_shared_view_tag(recipient_pubkey, i)` under the current encryption key. Populated lazily on first send to a new recipient. Resets on encryption-key rotation.

### request_transfer

Builds a payment request that a recipient hands to a sender out of band. The sender writes `recipient_request_view_tag` into the recipient's ciphertext slot so the recipient can pull the payment by exact byte match from the indexer (see [Request Payment Flow](#request-payment-flow)).

**Inputs**

```rust
fn request_transfer(
    /// Solana SPL / Token-22 mint pubkey.
    asset_mint: [u8; 32],
    /// In units of `asset_mint`.
    amount: u64,
    /// All-zero = default pocket.
    pocket_program_id: [u8; 32],
    /// Unix seconds after which the recipient considers the request expired.
    expiry_unix_ts: u64,
    /// Application-defined; not parsed by SPP; UTF-8, max 1024 bytes.
    memo: String,
) -> PaymentRequest
```

**Algorithm**

1. `request_count := state.RequestCount`
2. `recipient_request_view_tag := get_recipient_request_view_tag(request_count)`
3. `state.RequestCount += 1`
4. `return PaymentRequest { version=0, recipient_pubkey, recipient_request_view_tag, pocket_program_id, asset_mint, amount, expiry_unix_ts, memo }`

`RequestCount` is incremented unconditionally — even if the sender never pays. Reusing a nonce across two outstanding requests would let the indexer link them.

**Output: `PaymentRequest`**

Canonical big-endian byte layout. Packed, no length prefixes (`memo_len` precedes the variable-length `memo` tail).

```rust
/// 148 + memo.len() bytes total. Multi-byte integers are big-endian.
/// Wire format prefixes `memo` with its u16 BE byte length (0 if absent, max 1024).
struct PaymentRequest {
    /// Currently `0`.
    version: u8,
    /// P256 SEC1-compressed (1-byte prefix + 32 B X).
    recipient_pubkey: Address,
    recipient_request_view_tag: [u8; 32],
    /// All-zero = default pocket.
    pocket_program_id: Option<[u8; 32]>,
    /// Solana SPL / Token-22 mint pubkey.
    mint: Address,
    /// In units of `asset_mint`.
    amount: u64,
    expiry_unix_ts: u64,
    /// UTF-8; max 1024 bytes.
    memo: String,
}
```

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
    /// the unsolicited path (bootstrap or shared view tag — see View Tags).
    recipient_request_view_tag: Option<[u8; 32]>,
    /// `None` = default pocket.
    pocket_program_id: Option<[u8; 32]>,
}
```

**Algorithm**
0. check wallet is synced.
1. `asset_id := AssetRegistry[recipient.asset_mint]` (via SPP [Asset registry](#accounts)).
2. `tx_count := wallet.TxCount`; `wallet.TxCount += 1`.
3. `sender_view_tag := wallet.get_sender_view_tag(current_key, tx_count)`.
4. Select sender input UTXOs covering `amount` + fees from wallet state; compute `change_amount`.
5. Compute `first_nullifier` from the first selected input UTXO (lexicographic input position 0).
6. `(handle, ephemeral_pubkey) := wallet.begin_tx(first_nullifier)`. The handle owns `ephemeral_sk` for the rest of this transaction.
7. Pick random 31-byte `change_blinding_seed` and `recipient_blinding`.
8. Build the recipient output: `(owner=recipient.pubkey, asset_id, amount, blinding_seed=recipient_blinding_seed)`.
9. Build the sender change output: `(owner=sender_pubkey, asset_id, amount=change_amount, blinding_seed=change_blinding_seed, nullifier_data := wallet.randomized_nullifier_keys(inputs))`.
10. For each output, `ciphertext := wallet.encrypt_to_recipient(handle, owner.encryption_pk, plaintext)`. The sender ciphertext's `view_tag` is `sender_view_tag` (included in `transact` instruction data, not repeated in the blob). Each recipient ciphertext's `view_tag` is selected per [View Tags § Recipient view tag selection](#view-tags); updates to `wallet.known_recipients` are applied as specified there. Concatenate per the [Transfer](#transfer-1) layout into `encrypted_utxos`.
11. compute `private_tx_hash = Poseidon(input utxo hash chain, output utxo hash chain, external data hash, expiry_unix_ts)`
12. `signature := wallet.sign_p256(private_tx_hash)`
13. `witness := wallet.build_transact_witness(inputs, outputs, expiry_unix_ts, sender_view_tag, external_data_hash)`. Either run the prover locally on `witness`, or ship `witness` (no secrets) to a prover RPC and receive a `proof` in return.
14. Assemble the SPP `transact` instruction (see [transact](#transact)): `expiry_unix_ts`, `sender_view_tag`, `proof`, `relayer_fee`, `output_utxo_hashes`, `nullifier_root_index`, `private_tx_hash`, `public_sol_amount`, `public_spl_amount`, `encrypted_utxos`.
15. `return (instruction, encrypted_utxos)`.

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

    Note over System: merges existing UTXOs + new deposit<br>updates trees<br>writes encrypted outputs
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

    Note over System: verifies proofs<br>updates trees<br>writes encrypted outputs
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

    Note over System: spends input UTXOs, writes change UTXO<br>updates trees<br>writes encrypted outputs
    System-->>Trees: update trees
    System-->>PocketRPC: index encrypted UTXOs
```

## Policy Pockets

A logical grouping of UTXOs whose state transitions are checked by a policy program. Each pocket has its own auditor, authorities, and config.

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

    Note over System: merges existing UTXOs + new deposit<br>updates trees<br>writes encrypted outputs
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

    Note over System: verifies proofs<br>updates trees<br>writes encrypted outputs
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

    Note over System: merges existing UTXOs + new deposit<br>updates trees<br>writes encrypted outputs
    System-->>Trees: update trees
    System-->>PocketRPC: index encrypted UTXOs
    Note over PocketRPC: Decrypt UTXOs
```

### Enter and Exit Pocket

1. Enter, shield or transfer from default pocket
2. Exit, unshield or transfer from policy pocket

# SPP Proof - Shielded Pool ZK Proof

**Requirement.** The circuit MUST NOT take any wallet secret as a witness input.

**Public Inputs**

| Input | Source |
| --- | --- |
| nullifiers | derived in-circuit from spent input UTXOs |
| output_utxo_hashes | instruction data |
| nullifier_root | resolved from `nullifier_root_index` against the SPP root cache |
| private_tx_hash | instruction data |
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

**external_data_hash**

Hash over the public fields of the `transact` instruction and the Solana token accounts the proof must commit to. Included in `private_tx_hash` so the owner's signature covers the entire transaction.

```
external_data_hash := Sha256BE(
    sender_view_tag                                  ||
    u16_be(relayer_fee)                              ||
    u64_be(public_sol_amount.unwrap_or(0))           ||
    u64_be(public_spl_amount.unwrap_or(0))           ||
    user_spl_token_account.unwrap_or([0; 32])        ||
    spl_token_interface.unwrap_or([0; 32])           ||
    encrypted_utxos
)
```

**Checks**

| Check | Description |
| --- | --- |
| UTXO Ownership | Spent input UTXOs MUST be authorized by their owner, either with a P256 signature verified in circuit or a Solana signer checked by SPP. The P256 signature covers `sender_view_tag`, `expiry_unix_ts`, and the input UTXOs, so a prover cannot replay the proof under different public inputs. Pubkeys are encoded as Poseidon(pubkey_low, pubkey_high). |
| Inclusion | Spent input UTXOs MUST exist in the UTXO tree. |
| Nullifier non-inclusion | Input nullifiers MUST NOT exist in the nullifier tree before the transaction. |
| Nullifiers | Public nullifiers MUST be well formed from the spent input UTXOs. |
| Output UTXOs | Output UTXOs MUST be well formed and match the public output commitments. |
| Balance Conservation | For each active asset, inputs plus public deposits MUST equal outputs plus public withdrawals and fees. |
| Private transaction hash | `private_tx_hash = Poseidon(input utxo hash chain, output utxo hash chain, external data hash, expiry_unix_ts)`.<br>The owner signs this value (see [UTXO Ownership Check](#utxo-ownership-check)). SPP, policy, and third-party proofs all take `private_tx_hash` as a public input, so every circuit proves statements about the same transaction data. |
| Program ownership | UTXOs owned by a policy program MUST be authorized by a PDA signer of that program. Policy proofs are checked by the policy program before CPI into SPP. |
| Dummy input or output | ZK circuits are fixed size; dummy UTXOs allow a transaction to use fewer real inputs or outputs. Ownership, inclusion, nullifier non-inclusion, output, and balance checks are skipped for dummy UTXOs. |

**Utxo Ownership Check:**
1. Ed25519 Solana signer checked by SPP. Used when the input UTXO's owner is the Solana payer (shield path).
2. P256 signature over `private_tx_hash` verified in the SPP proof. The hash covers every input, every output, the external-data hash, and `expiry_unix_ts`, so the proof cannot be replayed with different state.

**Circuit Combinations**

| Circuit | Use | Shape |
| --- | --- | --- |
| 1 in 1 out | Shield with merge | 1 existing UTXO in, 1 combined output (existing balance + new deposit) |
| 1 in 2 out | Single-input transfer | 1 sender input UTXO, 1 recipient output, 1 change output; gas fees are sponsored |
| 3 in 3 out | Standard transfer | 1 SOL fee UTXO, 2 sender input UTXOs, 1 recipient output, 1 SPL change output, 1 SOL change output |
| 5 in 3 out | Higher concurrency | 1 SOL fee UTXO, 4 sender input UTXOs, 1 recipient output, 1 SPL change output, 1 SOL change output |
| 1 in 8 out | Split UTXO | Split 1 UTXO into up to 8 equal parts; equal parts reduce encrypted data |

# View Tags

A view tag is a 32-byte value attached to a ciphertext. Wallets sync by querying the indexer for exact view-tag matches and decrypt only their own transactions. Derivation splits into two cases — tags the sender derives for themselves to discover their own change UTXOs, and tags the sender derives for the recipient to discover incoming transfers.

Throughout this section, `counterparty_pubkey` / `recipient_pubkey` / `sender_pubkey` refer to the counterparty's `encryption_pk` from their [ShieldedPubkey](#wallet); shared view tags and AES-GCM keys are derived from ECDH over the encryption keypair, never the signing keypair.

**Uniqueness.** View tags are not globally unique across transactions. Only `sender_view_tag` is enforced single-use by SPP — it is inserted into the nullifier tree on `transact` and duplicates are rejected. The other variants may collide; the indexer returns all ciphertexts matching a tag value, and the recipient decrypts each.

For transfers, view tags need to be shared between the sender and recipient. A wallet cannot pre-derive shared tags for every possible sender, and the wallet needs to know which senders to derive view tags for. The first transfer between a new sender-recipient pair therefore uses a tag the recipient can find without prior knowledge of the sender: either `recipient_request_view_tag` (recipient minted, shared out-of-band) or `recipient_bootstrap_view_tag = recipient_pubkey.X` (publicly linkable, no coordination). This first transfer establishes the pair: on decryption the recipient reads `sender_pubkey` from the ciphertext and derives the shared ECDH key, and subsequent transfers from this sender use `recipient_shared_view_tag` and are found via `scan_view_tags`. `sender → recipient` and `recipient → sender` produce disjoint tags.

### Sender View Tag

1. **`sender_view_tag`**
  - Derived by: the sender, to index her change utxos.
  - Tx sent by: the sender
  - Indexed by: the sender

### Recipient view tag

2. **`recipient_shared_view_tag`**
    - Derived by: the sender and recipient independently. Sender via `send_shared_view_tag` to send the tx, the recipient via `derive_shared_view_tag` to index the tx.
    - Tx sent by: the sender.
    - Indexed by: the recipient.
3. **`recipient_request_view_tag`**
    - Derived by: the recipient. The recipient shares the tag with the sender out-of-band as a `PaymentRequest`.
    - Tx sent by: the sender.
    - Indexed by: the recipient. Once the recipient decrypts this transfer, subsequent transfers from the same sender can be indexed by `recipient_shared_view_tag`.
4. **`recipient_bootstrap_view_tag`**
    - Derived by: anyone — `recipient_pubkey.X` (the 32-byte X-coordinate of the recipient's `encryption_pk`).
    - Tx sent by: the sender.
    - Indexed by: the recipient. Once the recipient decrypts this transfer, subsequent transfers from the same sender can be indexed by `recipient_shared_view_tag`.


```mermaid
flowchart TD
    Start([prefix recipient]) --> Q1{prior transfer with recipient?}
    Q1 -->|Yes| Case22[2. recipient_shared_view_tag]
    Q1 -->|No| Q2{request view tag from recipient?}
    Q2 -->|Yes| Case211[3. recipient_request_view_tag]
    Q2 -->|No| Case212[4. recipient_bootstrap_view_tag]
```

"Prior transfer with recipient?" is decided by `recipient_pubkey ∈ wallet.known_recipients`.

**Sender-side updates to `wallet.known_recipients[recipient_pubkey]`:**

- Case 2 (`recipient_shared_view_tag`): use `i = known_recipients[recipient_pubkey]`, then `known_recipients[recipient_pubkey] += 1`.
- Case 3 (`recipient_request_view_tag`): if absent, insert `known_recipients[recipient_pubkey] = 0`. No increment.
- Case 4 (`recipient_bootstrap_view_tag`): if absent, insert `known_recipients[recipient_pubkey] = 0`. No increment.

### Derivations

Tag secrets are derived from `encryption_sk` to enable encryption-key rotation:

```
sender_view_tag_secret    := HKDF-SHA256(salt=∅, IKM=encryption_sk, info="zolana/sender_view_tag",    L=32)
recipient_view_tag_secret := HKDF-SHA256(salt=∅, IKM=encryption_sk, info="zolana/recipient_view_tag", L=32)
```

`get_sender_view_tag(tx_count)`:

```
HKDF-SHA256(
    salt = ∅,
    IKM  = sender_view_tag_secret,
    info = "zolana/sender_view_tag/" || u64_be(tx_count),
    L    = 32,
)
```

`get_recipient_request_view_tag(request_count)`:

```
HKDF-SHA256(
    salt = ∅,
    IKM  = recipient_view_tag_secret,
    info = "zolana/recipient_request_view_tag/" || u64_be(request_count),
    L    = 32,
)
```

`recipient_shared_view_tag(counterparty_pubkey, i)` — two chained HKDFs over the ECDH shared secret. Sender computes it as `send_shared_view_tag`; recipient computes the same byte value as `derive_shared_view_tag`:

```
shared := ECDH(self.encryption_sk, counterparty_pubkey)
domain := HKDF-SHA256(salt = ∅, IKM = shared,
                     info = "zolana/pair-domain/" || R_pubkey, L = 32)
return    HKDF-SHA256(salt = ∅, IKM = domain,
                     info = "zolana/pair-hint/"   || u64_be(i), L = 32)
```

`counterparty_pubkey` is the counterparty's `encryption_pk`. `R_pubkey` is the recipient of the direction:

- Sender side (`send_shared_view_tag`): `R_pubkey = counterparty_pubkey`.
- Recipient side (`derive_shared_view_tag`): `R_pubkey = self.encryption_pk`.

ECDH symmetry plus the matched direction label produces the same byte value across the pair.

`recipient_bootstrap_view_tag(recipient_pubkey)`:

```
recipient_pubkey.X    // 32-byte X-coordinate of the recipient's encryption_pk
```

The recipient's `encryption_pk` is SEC1-compressed (1-byte sign prefix + 32 B X); the bootstrap tag drops the sign byte. Two recipients sharing the same X (≈ 2⁻²⁵⁶ collision probability) both observe each other's ciphertexts at the indexer; only the intended recipient can decrypt.


# Output UTXO Serialization

Defines the layout of the `encrypted_utxos` blob included in shielded transactions. SPP does not parse the blob; serialization is a default-pocket convention. Policy pockets define their own.

Both schemes apply AES-GCM encryption; keys are derived per recipient via `ECDH(ephemeral_sk, recipient.encryption_pk)`. One `ephemeral_pubkey` is shared across all recipients in a transaction. The sender derives `(ephemeral_sk, ephemeral_pubkey)` from `get_ephemeral_keypair(first_nullifier)` (see [Wallet](#wallet)). Nullifier uniqueness in the nullifier tree implies a unique ephemeral keypair per transaction. Encryption is always sender-side. Slot prefixes (`view_tag`) are view tag values; see [View Tags](#view-tags).

Two schemes:

1. Transfer — confidential value movement; per-recipient AES-GCM bundles.
2. UTXO Split — one ciphertext for M equal-amount outputs under the same owner.

## Transfer

Confidential value transfer. One AES-GCM ciphertext per owner: one for the sender's change, `R` for the recipients. Variables used below: `R` = recipient count, `N` = spent-input count.

The recipient ciphertext includes `sender_pubkey` so the recipient learns the sender's pubkey on first contact and can derive the shared ECDH key used for `recipient_shared_view_tag` on subsequent transfers (see [View Tags](#view-tags)). The sender change ciphertext includes `nullifier_data`: one `randomized_nullifier_key` per spent input. The wallet re-derives the same value for each owned UTXO and intersects to mark spent UTXOs during sync; the optional senders indexer uses the field to link spends.

### Plaintext Layout

Fields packed in declaration order with no length prefixes (the variable-length tail in the sender bundle is sized from `N`, known from the [transact](#transact) instruction).

#### Recipient

```rust
/// 114 B plaintext → 130 B ciphertext (after the 16-byte GCM tag).
struct TransferRecipientPlaintext {
    /// Recipient `signing_pk` (UTXO owner, controls spend);
    /// 1-byte prefix + P256 SEC1-compressed.
    owner_pubkey: [u8; 34],
    /// Sender's `encryption_pk`; lets the recipient derive the shared ECDH key
    /// used for `recipient_shared_view_tag` on later transfers from this sender.
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

The sender change bundle encodes two outputs (SPL change + SOL change). Per-output blindings derive from a single seed:

```
blinding_i = Sha256BE(blinding_seed || u8(position_i))
```

with `position = 0` for the SPL output and `position = 1` for the SOL output.

```rust
/// 89 + 32*N B plaintext → 105 + 32*N B ciphertext (after the 16-byte GCM tag).
struct TransferSenderPlaintext {
    /// Sender's `signing_pk` (UTXO owner for the change outputs);
    /// 1-byte prefix + P256 SEC1-compressed.
    owner_pubkey: [u8; 34],
    /// Per-mint Asset registry; `0` if no SPL change.
    spl_asset_id: u64,
    /// `0` if no SPL change.
    spl_amount: u64,
    /// `0` if no SOL change.
    sol_amount: u64,
    /// Seed for the two per-output blindings (formula above).
    blinding_seed: [u8; 31],
    /// `randomized_nullifier_key` per spent input.
    nullifier_data: Vec<[u8; 32]>,
}
```

### Instruction Data Layout

The bytes the sender writes into the `encrypted_utxos` field of the [transact](#transact) instruction. Fields are packed in declaration order with no length prefixes.

```rust
/// Total size: 36 + (105 + 32*N) + 162*R bytes.
struct TransferEncryptedUtxos {
    /// Discriminator (TRANSFER).
    type_prefix: u8,
    /// Shared P256 pubkey for ECDH key derivation (1-byte prefix + SEC1-compressed).
    ephemeral_pubkey: [u8; 34],
    /// Number of recipient_slots that follow ciphertext_sender. Equals R.
    num_recipients: u8,
    /// Sender change bundle ciphertext: 89 + 32*N bytes plaintext + 16-byte GCM tag.
    /// View tag for this ciphertext is `sender_view_tag` from the transact
    /// instruction data, not included in this blob.
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

The sender ciphertext sits inline at offset 36 with no slot wrapper. Its view tag is `sender_view_tag`, included in the [transact](#transact) instruction data, not in `encrypted_utxos`.

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
| transact | Tag 0; implements shield/unshield/shielded transfer; verifies proofs, updates trees |
| proofless_shield | Tag 1; public deposit; hashes UTXO and inserts into UTXO tree |
| pocket_transact | Tag 2; implements shield/unshield/shielded transfer; verifies proofs, updates trees; checks that the encrypted UTXOs decrypt under the pocket auditor key and the recipient keys named in the policy proof |
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
    /// Poseidon(input utxo hash chain, output utxo hash chain,
    /// external data hash, expiry_unix_ts). Public input to the SPP proof;
    /// the owner's P256 signature over this value is verified in-circuit.
    private_tx_hash: [u8; 32],
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
| 1 in 1 out | 1 | 1 | 51 | 206 | 641 | — |
| 1 in 2 out | 1 | 2 | 335 | 206 | 957 | 875 |
| 3 in 3 out | 3 | 3 | 399 | 206 | 1057 | 975 |
| 5 in 3 out | 5 | 3 | 463 | 206 | 1125 | 1043 |
| 1 in 8 out | 1 | 8 | 133 | 206 | 947 | 865 |

\* `private_tx_hash` is 32 B. Transfer ciphertext sizes assume `R = 1` recipient, per the [Output UTXO Serialization § Transfer](#transfer-2) layout. Add 162 B per extra recipient.
\*\* assumes ALT for `tree_account`, `payer` and `program_id` inline; overhead = 64 (signature) + 3 (message header) + 65 (inline account keys: compact-u16 count + 2 × 32-byte pubkeys for `payer` and `program_id`) + 32 (recent blockhash) + 36 (ALT section: compact-u16 count + 32-byte ALT pubkey + writable count + writable index + readonly count) + 6 (instruction body: program_id_index + account_indices + data_len_varint). Shield/unshield totals add 66 B (`+64` for inline `user_spl_token_account` and `spl_token_interface` pubkeys, `+2` for their indices in the instruction body) because these accounts vary per transaction and cannot be served from the ALT.

**Checks**

1. `current_unix_ts <= expiry_unix_ts` (Solana `Clock.unix_timestamp`)
2. Each `nullifier_root_index` references a non-stale root.
3. `tree_account` is not paused.
4. Proof verifies against public inputs.
5. Append each `output_utxo_hashes[i]` to the UTXO sparse Merkle tree.
6. Insert each nullifier into the nullifier queue.
7. Insert `sender_view_tag` into the nullifier queue. Rejects on duplicate, so each sender `tx_count` slot is used at most once in the nullifier tree. SPP does not check the contents of `encrypted_utxos`; a wallet that writes an inconsistent blob only harms itself (sync will fail to decrypt).
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
2. get_shielded_transactions
3. get_proof
4. send_transaction

    The client selects input UTXOs, computes `private_tx_hash = Poseidon(input utxo hash chain, output utxo hash chain, external data hash, expiry_unix_ts)`, signs it, and either builds the proof locally or ships the witness to a stateless prover. Self-custody is guaranteed by the ZK proof binding `private_tx_hash` to every input, every output, the external-data hash, and `expiry_unix_ts`.

**Storage: `shielded_utxos`**

One row per ciphertext, sourced from either:

- the `encrypted_utxos` blob of a `transact` / `pocket_transact` instruction (one row per recipient slot, plus one for the sender change), or
- the `proofless_shield` instruction (one row per deposited output; `view_tag = NULL`, `ciphertext = NULL`, owner and amount are read from instruction data with `blinding = 0` inferred).

Spend state is intentionally absent: UTXOs are private and the indexer cannot link nullifier insertions back to UTXOs. Users derive their own spent set client-side after decrypting (sender change ciphertexts include the `randomized_nullifier_key` of each spent input in `nullifier_data: [u8;32] × N`).

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

`get_shielded_transactions(tags: Vec<[u8; 32]>)` returns, for every transaction with at least one ciphertext whose `view_tag` matches one of `tags`, all `shielded_utxos` rows of that transaction ordered by `(tx_signature, ciphertext_index)`. Servers MUST accept at least 10 000 tags per call. Sync uses this in place of `get_encrypted_utxos` so a single round trip returns both the matched ciphertext and its sibling recipient slots — letting the wallet derive `ephemeral_sk` from the spent inputs and decrypt the siblings to discover the recipients of its own outgoing transactions, without a second fetch.

## Pocket RPC

**Methods:**

1. get_decrypted_utxos
2. get_balance
3. get_instruction (for shield the user must sign directly)

## Merge Service

The shielded pool program has merge service registry accounts. Users can whitelist one or more merge service accounts (opt-in).
- separate merge service address tree
- merge service proof needs to do two proofs in the merge service address tree, inclusion of the user whitelist and non inclusion of the user revoke commitment. + domain separation for multiple back and forth. publishes encrypted to the merge service that it is whitelisted. Registry also publishes that the merge service is whitelisted so that senders can set the merge service correctly. If senders set a non whitelisted service that service cannot do anything.

**Enable merge service,** a user creates a nullifier H(user_pubkey, merge_service_pda) in a dedicated merge service tree.

**Merge UTXOs,** a merge service proves that a nullifier exists and that the user utxos are merged and encrypted correctly.

**Disable merge service**, user removes nullifier from merge service tree.

**Caveats:**

1. The merge service needs to be able to decrypt user UTXOs.

**Questions:**

1. How is merge service paid?
(You don't want to pay based on tx that creates weird incentives.)

## Registry

Out-of-protocol service. For each user's Solana pubkey, the registry publishes their [ShieldedPubkey](#wallet) and current sync delegate.

### Record

```rust
struct Record {
    /// The user's Solana pubkey.
    owner: Address,
    /// Static. Used as the signing key, and as the encryption key while no
    /// delegate is set.
    owner_p256: P256Pubkey,
    /// Solana pubkey of the current sync delegate, or none.
    delegate: Option<Address>,
    /// Append-only list of delegate entries.
    entries: Vec<Entry>,
}

struct Entry {
    /// Delegate's P-256 ECDH pubkey.
    sync_pk: P256Pubkey,
    /// Shared encryption pubkey published to senders for this entry:
    /// `KDF(ECDH(owner_sk, sync_pk)) · G`.
    encryption_pk: P256Pubkey,
    /// Unix seconds; set at the moment the entry is appended.
    created_at: i64,
}
```

Invariants:

- The current delegate is set if and only if `entries` is non-empty.
- `entries` is append-only: never modified or removed.

The current `ShieldedPubkey` projects from the record:

- (owner P-256, latest entry's encryption pubkey) while a delegate is set.
- (owner P-256, owner P-256) while standalone.

### Operations

Writes MUST be authenticated by the named signer. Reads are unauthenticated.

Proof-of-possession over the published P-256 keys is not required. A malformed entry only harms the registrant — senders following it produce ciphertexts no one can decrypt. Wallets MAY warn when their record's published keys disagree with what they expect.

#### `get_record`

Reads the record for a Solana pubkey. Unauthenticated.

```rust
struct GetRecordRequest {
    owner: Address,
}

struct GetRecordResponse {
    record: Option<Record>,
}
```

#### `register`

Creates a record with the given owner P-256 pubkey, no delegate, and no entries. Fails if a record for `owner` already exists.

Authorized signer: `owner`.

```rust
struct RegisterRequest {
    owner_p256: P256Pubkey,
}
```

#### `set_delegate`

Appoints or replaces the current delegate. Appends a new entry. The appointment rotates `encryption_sk`; the wallet resets `TxCount`, `RequestCount`, `known_senders`, and `known_recipients`.

Authorized signer: `owner`.

```rust
struct SetDelegateRequest {
    delegate: Address,
    sync_pk: P256Pubkey,
    encryption_pk: P256Pubkey,
}
```

#### `rotate_delegate_key`

Appends a new entry under the same delegate. The record's `delegate` field is unchanged. Like `set_delegate`, this rotates `encryption_sk` and resets the wallet's per-key counters and `known_*` maps.


Authorized signer: current delegate.

```rust
struct RotateDelegateKeyRequest {
    sync_pk: P256Pubkey,
    encryption_pk: P256Pubkey,
}
```

#### `revoke`

Removes the current delegate. `entries` is not modified. `encryption_sk` reverts to `owner_sk` (standalone); the wallet resets per-key counters and `known_*` maps for the new standalone key.

Authorized signer: `owner` or current delegate.

```rust
struct RevokeRequest {}
```

#### `close`

Removes the record. Fails unless `entries` is empty.

Authorized signer: `owner`.

```rust
struct CloseRequest {}
```

### Lookup and decryption

A sender translating a Solana address to a `ShieldedPubkey` reads the record and uses its current `ShieldedPubkey`. An absent record is a registry miss; the sender falls back to no-registry behaviour ([Wallet Transfer User Flows](#wallet-transfer-user-flows), Scenarios 5–6).

A recipient restoring from mnemonic decrypts ciphertexts entry by entry:

- Ciphertexts received while the record was standalone decrypt with `encryption_sk = owner_sk`.
- Ciphertexts received under a delegate entry decrypt with `encryption_sk = KDF(ECDH(owner_sk, entry.sync_pk))`. The cached `entry.encryption_pk` lets the recipient match a ciphertext to its entry without trying every ECDH.

## Sync Delegate

A sync delegate scans view tags and decrypts ciphertexts on the wallet's behalf. Appointment is via [Registry § `set_delegate`](#set_delegate); the delegate's `sync_sk` and the wallet's `owner_sk` jointly derive the shared `encryption_sk` (see [Wallet](#wallet)).

**Handover on appointment (TBD, optional).** A delegate's `sync_sk` derives `encryption_sk_k` only for `entries` created with its own `sync_pk`. On appointment of a new delegate, the wallet implementation picks one of two behaviors; the protocol does not enforce either:

- **(a) Hand-over.** The wallet ships the new delegate `[(key_index, encryption_sk_k)]` for prior entries via an out-of-band channel (TLS, e2e-encrypted). The new delegate can scan the full history.
- **(b) Forward-only.** No hand-over. The new delegate scans only entries it originated; prior entries remain decryptable by the wallet, which can always derive `encryption_sk_k` from `owner_sk + entries[k].sync_pk`.

# Notes

1. policy pockets can only be entered and exited from and to the default pocket
2. by default every pocket that is deployed creates a new program, later we can deploy a standard pocket program that has a set of extensions.
3. **We need to expose nullifier data with the encrypted utxos so that the RPC knows which utxos were spent based on decrypted outputs**
4. By publishing the cleartext output utxo data we would essentially do compressed token transfers.

# User Flows

## Request Payment Flow Default Pocket

Recipient-pull flow. The recipient supplies a one-time `view_tag` that the sender writes onto the recipient's ciphertext slot, so the recipient can pull the payment by exact byte-match instead of scanning every transfer.

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


## First Time Sync Wallet

Restores a fresh wallet including fetching and decrypting all user UTXOs from a BIP-39 mnemonic.

1. **Initialize the wallet** from the mnemonic (derives `owner_sk`, `nullifier_secret`, `ephemeral_secret` in-process). Read the [Registry](#registry) record for the wallet's Solana pubkey to enumerate encryption keys: the standalone key (active while `entries` is empty or before the first entry) plus each delegate entry.

2. **For each encryption key `k` in parallel:**
    1. **Phase 1 — scan own view tags (concurrent within `k`).** All derivations run through wallet methods; secrets stay in the wallet.
        1. **Fetch loop** in batches of 10 000 until first empty batch, scoped to `k`'s `[created_at, next.created_at)` window:
            1. `tags := wallet.view_tag_range(sender, k, i..i+10_000) ∪ wallet.view_tag_range(recipient_request, k, i..i+10_000)`. `indexer.get_shielded_transactions(tags)`.
            2. fetch ciphertexts tagged with `recipient_bootstrap_view_tag` (`encryption_pk_k.X`, public — no wallet call needed).
            3. fetch ciphertexts or decrypted UTXOs from every known policy-pocket RPC.
            4. fetch proofless shields cleartext UTXOs.
        2. **Decrypt and store.** For each ciphertext, `plaintext := wallet.decrypt(ciphertext, ephemeral_pubkey, k)`. Store the UTXOs and their `nullifier_data`.
    2. **Phase 2 — scan known_senders and known_recipients view tags (concurrent within `k`).**
        1. **Fetch loop** in batches of 10 000 until first empty batch:
            1. for each known sender `s`, `tags := wallet.view_tag_range(shared_derive, k, i..i+10_000, Some(s))`; fetch matching ciphertexts.
            2. for each known recipient `r`, `tags := wallet.view_tag_range(shared_send, k, i..i+10_000, Some(r))`; fetch matching ciphertexts.
        2. **Decrypt and store.** Decrypt via `wallet.decrypt(...)` and store UTXOs; repeat the fetch loop for any newly discovered senders.

3. **Merge** UTXOs, `nullifier_data`, `known_senders`, `known_recipients` across encryption keys.

4. **Mark spent utxos.** Mark each UTXO whose `randomized_nullifier_key` appears in any stored `nullifier_data` as spent.

5. **Set wallet state**: `Utxos`, `known_senders`, `known_recipients`, per-key counters `TxCount`, `RequestCount` (the current key's `max(observed index) + 1`), `last_synced = current_timestamp()`.

**Sync Time Estimates**

Assumptions:

1. Indexer request size: `10 000` view tags per `view_tag IN (...)` query.
2. Indexer RTT: 100 ms.
3. ECDH P-256 per ciphertext: 100 μs.
4. Per-key scans run concurrently. Within a key, Phase 1 (`sender_view_tag`, `recipient_request_view_tag`, `recipient_bootstrap_view_tag`) runs concurrently, and Phase 2 per-sender / per-recipient scans run concurrently.
5. Each known sender has < 10 000 incoming transfers per key; each known recipient has < 10 000 outgoing transfers per key.

Figures below are **per encryption key**. With `E` keys (1 standalone + delegate entries), sequential totals multiply by `E`; parallel totals add ECDH cost only since RTTs overlap.

| Tx history | Known senders | Phase 1 RTTs | Phase 2 RTTs | Total RTTs | Decrypt (sequential) | Total (sequential) | Total (parallel, ≥10 threads) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 10 | 1 | 2 | 2 | 4 | < 1 ms | ~400 ms | ~400 ms |
| 1 000 | 100 | 2 | 2 | 4 | ~100 ms | ~500 ms | ~400 ms |
| 10 000 | 1 000 | 2 | 2 | 4 | ~1 s | ~1.4 s | ~500 ms |
| 100 000 | 10 000 | 11 | 2 | 13 | ~10 s | ~11 s | ~1.5 s |
| 1 000 000 | 100 000 | 101 | 2 | 103 | ~100 s | ~110 s | ~12 s |

## Wallet Transfer User Flows

Scenario X from the single and advanced flows maps to the respective scenario in the privacy guarantee matrix.

**Terminology:**

**Single player** cover user flows that are backwards compatible with any Solana wallets.
**Advanced** cover ideal user flows between private wallets.
**Registry** maps Solana public keys to a shielded pubkey.
**ShieldedPubkey**(signing P256 Pubkey, encryption P256 Pubkey) the signing key and the encryption key can be the same key, for example for a cypherpunk user. A user who has a shared key with an auditor would use different keys, a user owned signing key and a shared encryption key.

**Single Player flows:**

1. **Recipient:**
    1. shares Solana Pubkey
2. **Sender:**
    1. wallet doesn’t support shielded transfers
        1. SPL transfer **(Scenario 1)**
    2. wallet supports shielded transfers
        1. lookup recipient ShieldedPubkey from registry
        2. lookup success:
            1. Sender has shielded funds
                1. is the first transfer to recipient: confidential shielded transfer
                (pubkey public, amount & asset private) **(Scenario 2)**
                2. is not the first transfer to recipient: anonymous shielded transfer **(Scenario 3)**
            2. Sender doesn’t have shielded funds
                1. proofless shield to recipient **(Scenario 4)**
        3. lookup negative:
            1. Sender has shielded funds:
                1. unshield **(Scenario 5)**
            2. Sender doesn’t have shielded funds
                1. SPL transfer **(Scenario 6)**

**Advanced flows:**

Sender and recipient wallets both support shielded transfers.

1. **Recipient:**
    1. shares ShieldedPubkey + handshake decryption hint
2. **Sender:**
    1. Sender has shielded funds
        1. anonymous shielded transfer **(Scenario 7)**
    2. Sender doesn’t have shielded funds
        1. shield to recipient (with proof) **(Scenario 8)**

### Privacy Guarantee Matrix

| # | Scenario | Resulting transfer | Sender identity | Recipient identity | Amount | Asset | Sender ↔ recipient linkable? |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | **Single player** · sender wallet doesn't support shielded | SPL transfer | Public | Public | Public | Public | Yes |
| 2 | **Single player** · sender supports shielded · registry hit · sender has shielded funds · first transfer to recipient | Confidential shielded transfer | Private | Public | Private | Private | No |
| 3 | **Single player** · sender supports shielded · registry hit · sender has shielded funds · not first transfer | Anonymous shielded transfer | Private | Private | Private | Private | No |
| 4 | **Single player** · sender supports shielded · registry hit · sender has no shielded funds | Proofless shield to recipient | Public | Public | Public | Public | Yes |
| 5 | **Single player** · sender supports shielded · registry miss · sender has shielded funds | Unshield to recipient | Private | Public | Public | Public | Partial — recipient visible exiting pool |
| 6 | **Single player** · sender supports shielded · registry miss · sender has no shielded funds | SPL transfer | Public | Public | Public | Public | Yes |
| 7 | **Advanced** · both wallets shielded · sender has shielded funds | Anonymous shielded transfer | Private | Private | Private | Private | No |
| 8 | **Advanced** · both wallets shielded · sender has no shielded funds | Shield to recipient (with proof) | Public | Private | Public | Public | Partial — sender visible entering pool |

# TODO:
2. add merge delegate to utxo hash, merge circuit, merge user flow.
4. add swap user flow (unshield, swap, shield)
5. add private zk swap user flow
6. add registry docs, registry pda should include a hint whether whats the latest tx count. Updating the pda will leak some information though you can correlate activity. The wallet should store this so that we can fetch backwards.
7. benchmarks of wallet sync flow.
