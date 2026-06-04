# Squads Zone Program

The Squads Zone Program configures a zone on the Solana Privacy Protocol (TSPP), which provides private transfers in a single Solana transaction. The zone adds compliance features, a co-signer, and smart-account support.
TODO: lookup requirements again and tick all boxes in the intro.

For compliance, the zone program configures an auditor encryption key and verifies a zk proof in every transfer instruction. The zone zk proof shows that all balance updates encrypted to an auditor-readable key, so the auditor can decrypt and index all balances.

For smart accounts, the program supports asynchronous execution and user accounts with shared encryption keys. Asynchronous execution uses a proposal buffer that a co-signer or relayer executes after approval. User accounts store encryption keys shared between the auditor and one or more smart account holders. The auditor key and user keys can be safely migrated unilaterally by proving the new shared key was encrypted correctly.

Balances are stored in unspent transaction outputs (UTXOs). For a seamless account-like experience, the auditor consolidates fragmented UTXO balances so users can spend their full balance in one transfer. The squads zone depends on its backend and co-signer for liveness. To ensure that users can withdraw funds without the Squads backend, users can sync their wallets from RPC data alone, decrypt locally, and withdraw without a co-signer.

This document specifies how the zone program fits into the TSPP architecture, shared viewing keys between smart account holders and auditors, the program's accounts, its zone proof, its instructions, its zone-specific encrypted UTXO serialization, and transaction sizes.


## Table of Contents

- [Glossary](#glossary)
- [Architecture](#architecture)
- [Operations](#operations)
- [Shared Viewing Keys](#shared-viewing-keys)
- [Asynchronous Transfers](#asynchronous-transfers)
- [Concurrency](#concurrency)
- [Auditor](#auditor)
- [Squads Backend](#squads-backend)
  - [Backend API](#backend-api)
- [Squads Zone Program](#squads-zone-program)
  - [Accounts](#accounts)
    - [Viewing Key Account](#viewing-key-account)
    - [Proposal](#proposal)
    - [Key Update Proposal](#key-update-proposal)
    - [Zone Config](#zone-config)
  - [Zone ZK Proofs](#zone-zk-proofs)
    - [Zone Proof](#zone-proof)
    - [Viewing Key Encryption Proof](#viewing-key-encryption-proof)
    - [Key Rotation Proof](#key-rotation-proof)
  - [Instructions](#instructions)
  - [Encrypted UTXO Serialization](#encrypted-utxo-serialization)

## Glossary

Types used in this document.

| Type | Encoding | Definition |
| --- | --- | --- |
| `Address` | `[u8; 32]` | Solana account address. |
| `Signature` | `[u8; 64]` | Ed25519 Solana transaction signature. |
| `Instruction` | — | Solana SDK instruction. |
| `P256Pubkey` | `[u8; 33]` | SEC1-compressed P-256 public key: 1-byte parity prefix + 32-byte x-coordinate. |
| `asset_id` | `u64` | Asset identifier in UTXOs and ciphertexts. `1` is SOL; each SPL mint gets a distinct `asset_id ≥ 2`, set in a per-mint PDA at SPL interface creation. |
| `Spp` | `[u8; 192]` | Solana privacy program. |
| `ZoneProof` | `[u8; 192]` | Compressed Groth16 zone proof with commitment. |
| `SppProof` | `[u8; 192]` | Compressed Groth16 SPP proof with commitment; verified in SPP. |
| `SharedKeyCiphertext` | `[u8; 81]` | HPKE-wrapped shared viewing private key: 33-byte ephemeral P-256 key + 32-byte AES-GCM ciphertext + 16-byte GCM tag. |
| `ProposalCiphertext` | `[u8; 88]` | Operation amount and blinding encrypted to the shared viewing key: 33-byte ephemeral P-256 key + 39-byte AES-GCM ciphertext (8-byte amount + 31-byte blinding) + 16-byte GCM tag. |
| `SenderCiphertext` | `[u8; 32]` | Sender change ciphertext: 16-byte plaintext (`amount`, `asset_id`) + 16-byte GCM tag. |
| `RecipientCiphertext` | `[u8; 63]` | Recipient output ciphertext: 47-byte plaintext (`amount`, `asset_id`, 31-byte `blinding`) + 16-byte GCM tag. |
| `Shielded Keypair` | `` | |
| `Shielded Address` | `` | |


## Architecture

![Squads Zone Program architecture](diagrams/squads_policy_program.png)

Source: [`diagrams/squads_policy_program.dot`](diagrams/squads_policy_program.dot). Regenerate with `just render-diagrams`.

The squads program builds on top of the Solana Privacy Program (SPP). The backend (indexer, prover, relayer, and auditor) builds balances and proofs; the user signs; the squads program verifies the [zone proof](#zone-proof) and CPIs SPP. Execution is either synchronous ([transact](#transact)) or asynchronous with a [proposal](#asynchronous-transfers) user flow.
The squads policy program has full control over the features exposed from the SPP and balances of zone users. The SPP ensures correct state transitions, that all UTXOs are fully backed by spl tokens and only the owner of the balance can spend it. 

## Operations

### User

A user is anyone using the zone. Every user has a [viewing key account](#viewing-key-account).

| # | Name | Description | Privacy |
| --- | --- | --- | --- |
| 1 | deposit | Deposit and merge deposited amount into an existing UTXO | sender, recipient, amount public, existing account amount private   |
| 2 | proofless_deposit | Public deposit without a proof. | fully public |
| 3 | withdraw | Exit the zone to a public account. | sender visible, withdrawn asset and amount public, remaining account amount private |
| 4 | transfer | Transfer between zone balances. | sender + recipient public, asset + amount private |
| 5 | full_withdrawal | Escape-hatch exit without a co-signer or the backend. | amount + sender + recipient public |
| 6 | create_viewing_key_account | Create an account that registers a shared viewing key (published encrypted to the auditor) and whitelist the merge service. |
| 7 | update_viewing_key_account | Update the recovery keys or rotate the shared viewing key; re-encrypts the shared secret with a key rotation proof. |
| 8 | toggle_viewing_key_account | Block or unblock transfers and key updates. While blocked, only full_withdrawal is possible. |
| 9 | close_viewing_key_account | Close the viewing key account and reclaim rent. |
| 10 | create_proposal | Create a proposal account to queue a deposit, withdraw or transfer operation for later execution. |
| 11 | cancel_proposal | Cancel a queued operation for later execution. |

### Squads

Roles operated by Squads: the auditor, the merge service, the zone creator, and the relayer/co-signer.

| # | Name | Description |
| --- | --- | --- |
| 1 | create_zone_config | Create the zone — set the auditor key and co-signer. |
| 2 | update_zone_config | Rotate the auditor key, co-signer, or authority; burning the authority freezes the config. |
| 3 | execute_proposal | Relayer/co-signer settles an approved proposal. |
| 4 | merge_transact | Merge service consolidates a user's fragmented zone UTXOs. |
| 5 | index (audit) | Auditor decrypts every zone UTXO via each user's shared viewing secret; cannot sign or spend. |
| 6 | migrate_viewing_key_account | Permissionless re-encryption of a viewing key account to a rotated auditor key after `update_zone_config`. |
| 7 | execute_key_update | Backend settles an approved key update proposal with the key rotation proof. |


## Shared Viewing Keys

An auditor and a smart account with multiple keys need a shared viewing key so every key holder can view its UTXOs.

Viewing key accounts create, distribute, and store shared viewing keys. At creation several viewing keys are declared, one per smart account key holder plus the auditor(s). The account stores the shared key's public key and its private key encrypted separately to each declared viewing key. At account creation and with any key rotations a zero knowledge proof proves that the encrypted private keys are correctly encrypted to all individual encryption keys. Each key holder and the auditor can then recover the shared private key independently.

UTXOs transferred to and from the account are encrypted to the shared key, so any eligible viewer can decrypt them. Verifiable encryption proves each UTXO is encrypted to the shared key. A viewing key account is required for sender and recipient of any operation in the squads zone.

## Asynchronous Transfers

Smart accounts controlled by several keys with an approval threshold need to collecting signatures over multiple transactions for a proposal. The proposal cannot contain a SPP zk proof because SPP proofs reference a recent Merkle tree root which are only valid for a short time. To address this issue the Squads policy program implements a proposal user flow. 

A key holder creates a proposal that commits to a single operation (deposit, withdrawal, or transfer) and encrypts the amount to the shared viewing key. The remaining signers approve the proposal through the smart account.

Once the threshold is met, a co-signer or relayer holding the shared viewing key decrypts the proposal, builds the proof, and executes the transaction. The proposer can cancel a proposal before it executes, and a proposal expires at a set Unix timestamp.

The zone program does not verify the smart-account threshold itself. Approval is enforced by the smart account program that votes on the `create_proposal` instruction. The zone program treats an existing `Proposal` account as an approved operation; `execute_proposal` checks only the co-signer and the proof.

## Concurrency

A private balance consists out of one or multiple UTXOs. Every UTXO can be spent independently or multiple UTXOs can be spent in the same transaction.

**Incoming transactions** are parallel without limit. Each transfer creates a new UTXO for the recipient, so transfers to a user run in parallel without limit. at the cost of fragmentation: the balance spreads across many UTXOs. The backend merges incoming UTXOs on demand so the user can spend their full balance in one transfer.

**Outgoing transactions** are limited by the number of UTXOs the user balance is composed of. The default is for every account to only hold one UTXO of every asset. To send multiple transfers in parallel from one keypair, a user splits their balance into several UTXOs in one transaction, then spends each in separate parallel transactions.

## UTXO Balance Consolidation without User Interaction

Incoming transfers and proofless deposits create new UTXOs. In a standard private transfer we spend two UTXOs.
To achieve user experience similar to accounts the user balances should be a single or few UTXOs per asset so that the complete balance can be spent in a single Solana transaction.

Whitelisted authorities can consolidate user balances in a specialized merge circuit which does not require the user to sign and merges UTXOs of a single user into one. Merge transactions cannot destroy, transfer value or encrypt UTXOs in an invalid way.
Merge authorities do not necesarily hold encryption keys thus cannot perform any actions without the backend or user revealing UTXOs to merge.
The merge feature is native to the SPP, the squads program has complete control to configure or disable this feature.


## Auditor 

A P256 public key stored in `ZoneConfig`. The auditor key is held by the backend.

1. **Keys held** — P-256 encryption keypair.
2. **Can do** — Decrypt every zone UTXO via the shared viewing secret in each [viewing key account](#viewing-key-account).
3. **Cannot do** — Sign, spend, block transfers.
4. **Key rotation** — Rotates with `update_zone_config`.

## Squads Backend

The Squads backend indexes decrypted UTXOs, provides balances to users, runs the prover and merges users' UTXOs.

1. **Keys held** — `zone_authority` (Solana keypair) and `auditor` (P256 encryption) keypairs.
2. **Can do** — Decrypt every zone UTXO via the shared viewing secret in each [viewing key account](#viewing-key-account); censor users, order transactions. Merge user UTXOs.
3. **Cannot do** — Transfer user tokens without their signature, change user transactions.

### Backend API

JSON-RPC. The backend decrypts a user's UTXOs and proposals with the shared viewing key, and builds the proof-bearing transactions. Instructions without a proof — `create_proposal` and `update_viewing_key_account` — are built client-side and need no endpoint.

Any request that returns decrypted data (`getUtxos`, `getBalances`, `getProposals`) includes a `signature` by the viewing key account owner (or a smart account key holder); the backend rejects reads of another user's data.

A `request*` call returns the built instruction for a smart account to wrap and submit; for a keypair owner the backend sends the transaction and sets `signature`.

#### `getUtxos`

Returns the user's UTXOs, decrypted with the shared viewing key.

```rust
struct GetUtxosRequest {
    viewing_key_account: Address,
    signature: [u8; 64],
}

struct GetUtxosResponse {
    utxos: Vec<DecryptedUtxo>,
}

struct DecryptedUtxo {
    utxo_hash: [u8; 32],
    asset_id: u64,
    amount: u64,
    blinding: [u8; 31],
}
```

#### `getBalances`

Returns the user's total balance per requested mint, summed by the backend from the decrypted UTXOs. `balances[i]` is the total for `mints[i]`.

```rust
struct GetBalancesRequest {
    viewing_key_account: Address,
    mints: Vec<Address>,
    signature: [u8; 64],
}

struct GetBalancesResponse {
    balances: Vec<u64>,
}
```

#### `getProposals`

Returns the pending proposals for a viewing key account, decrypted.

```rust
struct GetProposalsRequest {
    viewing_key_account: Address,
    signature: [u8; 64],
}

struct GetProposalsResponse {
    proposals: Vec<DecryptedProposal>,
}

struct DecryptedProposal {
    pda: Address,
    /// deposit | withdraw | transfer
    op: u8,
    asset_id: u64,
    amount: u64,
    recipient: Address,
    expiry: i64,
    commitment_hash: [u8; 32],
}
```

#### `requestCreateViewingKeyAccount`

Builds the [viewing key encryption proof](#viewing-key-encryption-proof) and the `create_viewing_key_account` instruction. Without `owner_signature`, the created account is only encrypted to the auditor key.

```rust
struct RequestCreateViewingKeyAccountRequest {
    owner: Address,
    recovery_keys: Vec<P256Pubkey>,
    owner_signature: Option<[u8; 64]>,
}

struct RequestCreateViewingKeyAccountResponse {
    viewing_key_account: Address,
    instruction: Instruction,
    signature: Option<Signature>,
}
```

#### `requestTransfer`

Builds the zone proof, the SPP proof, and the `transact` instruction for a transfer.

```rust
struct RequestTransferRequest {
    sender_viewing_key_account: Address,
    recipient_viewing_key_account: Address,
    asset_id: u64,
    amount: u64,
}

struct RequestTransactResponse {
    instruction: Instruction,
    signature: Option<Signature>,
}
```

#### `requestDeposit`

Builds the proofs and the `transact` instruction for a deposit. Returns `RequestTransactResponse`.

```rust
struct RequestDepositRequest {
    viewing_key_account: Address,
    asset_id: u64,
    amount: u64,
    spl_source: Address,
}
```

#### `requestWithdraw`

Builds the proofs and the `transact` instruction for a withdrawal. Returns `RequestTransactResponse`.

```rust
struct RequestWithdrawRequest {
    viewing_key_account: Address,
    asset_id: u64,
    amount: u64,
    spl_recipient: Address,
}
```


## Squads Zone Program

### Accounts
Layouts of accounts owned by the squads zone program. Which instructions create, read, write and close the accounts.

#### Viewing Key Account

Stores the user's shared viewing key and the ciphertexts that let each recovery key and the auditor recover the shared private key. It also holds the blinding seed, wrapped to the shared viewing key, from which the owner and auditor derive change-output blindings. One account per zone user.

Derivation seed: `[b"viewing_key_account", owner]`.

Created by `create_viewing_key_account`. `update_viewing_key_account` updates recovery keys or rotates the shared key; `migrate_viewing_key_account` re-encrypts to a rotated auditor key; `toggle_viewing_key_account` sets `state`; `close_viewing_key_account` reclaims rent.

```rust
struct ViewingKeyAccount {
    /// Account type tag.
    discriminator: u8,
    /// Solana account or smart account PDA that owns this record and authorizes its updates.
    owner: Address,
    /// Active, or transfers blocked (see toggle_viewing_key_account).
    state: u8,
    /// Encryption scheme for the shared key and UTXO ciphertexts. P256_AES = 1.
    encryption_scheme: u8,
    /// Public shared viewing key. UTXOs to and from `owner`
    /// are encrypted to it.
    shared_viewing_key: P256Pubkey,
    /// Incremented on each rotation; orders key updates.
    key_nonce: u64,
    /// Blinding seed (32 B) wrapped to the shared viewing key. Change-output
    /// blindings derive from it as Poseidon(blinding_seed, blinding_nonce).
    encrypted_blinding_seed: SharedKeyCiphertext,
    /// Read, incremented, and passed to the zone proof on each transact;
    /// gives every change output a fresh blinding.
    blinding_nonce: u64,
    /// One recovery key per smart account key holder.
    recovery_keys: Vec<P256Pubkey>,
    /// Shared private key encrypted to each `recovery_keys[i]`.
    recovery_key_ciphertexts: Vec<SharedKeyCiphertext>,
    /// One key per auditor declared for the zone.
    auditor_keys: Vec<P256Pubkey>,
    /// Shared private key encrypted to each `auditor_keys[i]`.
    auditor_key_ciphertexts: Vec<SharedKeyCiphertext>,
}
```

ViewingKeyAccount size is `181 + 114·(R + A)` bytes, for `R` recovery keys and `A` auditors (the 81-byte `encrypted_blinding_seed` and 8-byte `blinding_nonce` are in the fixed part; four 4-byte `Vec` length prefixes, borsh-packed):

| Recovery keys (R) | Auditors (A) | Size (bytes) |
| --- | --- | --- |
| 1 | 1 | 409 |
| 2 | 1 | 523 |
| 3 | 1 | 637 |
| 5 | 1 | 865 |


#### Proposal

The proposal account holds the parameters of a queued deposit, withdrawal, or transfer. The `commitment_hash` is a public input to the [zone proof](#zone-proof) so that the executor who creates the proof when sending the transaction cannot change the operation between approval and execution.

Derivation seed: `[b"proposal", owner, cipher_text[0..33]]`. The ciphertext prefix is the ephemeral P-256 key, fresh per encryption, so each proposal derives a distinct PDA.

Created by `create_proposal`. `execute_proposal` settles the operation and closes the proposal; `cancel_proposal` closes it before execution. A proposal expires once the cluster Unix time passes `expiry`.

```rust
struct Proposal {
    /// Account type tag.
    discriminator: u8,
    /// Viewing key account whose UTXOs the operation spends.
    owner: Address,
    /// Recipient owner for a transfer, SPL account for a deposit or withdrawal.
    recipient: Address,
    /// Asset mint. SOL is Address::default().
    asset: Address,
    /// Poseidon commitment over the operation parameters; public input to the
    /// zone proof at execution.
    commitment_hash: [u8; 32],
    /// Amount and blinding encrypted to the shared viewing key.
    cipher_text: ProposalCiphertext,
    /// Unix timestamp after which execution fails.
    expiry: i64,
}
```

Size: `225` bytes (`1 + 32 + 32 + 32 + 32 + 88 + 8`, borsh-packed).

#### Key Update Proposal

Queues an async update to a viewing key account's recovery keys. The new ciphertexts and key rotation proof are supplied by the execution instruction.

Derivation seed: `[b"key_update_proposal", target, domain]`

A smart account holder proposes the update through `update_viewing_key_account`; once the smart account approves, the backend settles it with `execute_key_update` and closes the proposal. `cancel_key_update` closes it before execution and reclaims rent. The proposal also expires once the cluster Unix time passes `expiry`.

```rust
struct KeyUpdateProposal {
    /// Account type tag.
    discriminator: u8,
    /// Domain separation for pda derivation.
    domain: u16,
    /// Viewing key account to update.
    target: Address,
    /// Requested change to a recovery key.
    operation: KeyOperation,
    /// Unix timestamp after which execution fails.
    expiry: i64,
}

struct KeyOperation {
    /// Add, remove, or replace a recovery key.
    op: u8,
    /// Recovery key slot the operation applies to.
    index: u8,
    /// New key for add and replace; ignored for remove.
    key: P256Pubkey,
}
```

Size: `78` bytes (`1 + 2 + 32 + 35 + 8`, borsh-packed; the `KeyOperation` is `1 + 1 + 33`).

#### Zone Config

The zone's config account, one per program, contains the auditor key that must be part of every shared viewing key, the optional co-signer, and the bound on proposal lifetime.

Derivation seed: `[b"zone_config"]`.

Created by `create_zone_config`. `update_zone_config` rotates the auditor key or co-signer, or transfers `authority`; setting `authority` to the default freezes the config against further updates.

```rust
struct ZoneConfig {
    /// Account type tag.
    discriminator: u8,
    /// Authority that can update the zone. The default value freezes it.
    authority: Address,
    /// Solana key that must co-sign every spend. The default value disables co-signing.
    co_signer: Address,
    /// Upper bound on a proposal's `expiry`, in seconds from creation.
    max_proposal_lifetime: i64,
    /// Zone auditor key. Every output UTXO is encrypted to it.
    auditor_key: P256Pubkey,
}
```

Size: `106` bytes (`1 + 32 + 33 + 32 + 8`, borsh-packed).


### Zone ZK Proofs

The zone verifies its own ZK proof (Groth16), separate from the SPP proof which proves the UTXO transfer. The SPP proof settles the UTXO state transition; the zone proof enforces the verifiable encryption. Both proofs pass the `private_tx_hash` as public input to constrain them to the same transaction.

#### Zone Proof

Verified by `transact` and `execute_proposal`. One circuit covers all user flows: deposit, withdrawal, and transfer. Proves every output UTXO is encrypted to the named recipient viewing keys, and that the encrypted amounts match the committed operation. Each viewing key is shared with the auditor, so encrypting to it gives the auditor read access. 

**Public inputs**

1. `private_tx_hash` — instruction data; shared with the SPP proof.
2. `recipient_viewing_keys` — recipient ViewingKeyAccount(s).
3. `output_utxo_ciphertexts` — instruction data.
4. `public_amount` — instruction data (deposit/withdrawal; `0` for transfer).
5. `commitment_hash` — Proposal (async) or instruction data (sync).
6. `blinding_nonce` — sender ViewingKeyAccount, after increment; the proof checks the change blinding is `Poseidon(blinding_seed, blinding_nonce)`.

#### Viewing Key Encryption Proof

Verified by `create_viewing_key_account`. Proves the `shared_viewing_key`'s private key is correctly encrypted to every recovery and auditor key.

**Public inputs**

1. `shared_viewing_key` — instruction data.
2. `recovery_keys` — instruction data.
3. `auditor_key` — ZoneConfig.
4. `recovery_key_ciphertexts`, `auditor_key_ciphertexts` — instruction data.

#### Key Rotation Proof

Verified by `execute_key_update` (recovery-key changes, shared-key rotation) and `migrate_viewing_key_account` (auditor-key rotation). Proves the new `shared_viewing_key`'s private key is correctly encrypted to every updated recovery and auditor key, consistent with the account's prior state.

**Public inputs**

1. `old_state_hash` — hash of the account's current keys and ciphertexts.
2. `new_shared_viewing_key` — instruction data.
3. new recovery or auditor keys — KeyUpdateProposal (recovery) or ZoneConfig (auditor).
4. new ciphertexts — instruction data.

### Instructions

| # | Instruction | Tag | Description | Co-Signer | Accounts Read | Accounts Modified | Access Control |
|---|------------|-----|-------------|:---------:|---------------|-------------------|----------------|
| 1 | transact | 0 | Deposit, withdrawal, or transfer; verifies the zone proof and CPIs SPP. | ✓ | ZoneConfig, recipient ViewingKeyAccount | sender ViewingKeyAccount (blinding_nonce), SPP trees (CPI), SPL vault | zk proof that owner signed; co-signer signed |
| 2 | proofless_deposit | 1 | Public deposit without a proof. | ✓ | recipient ViewingKeyAccount | SPP UTXO tree (CPI), SPL vault | Depositor signs; co-signer |
| 3 | merge_transact | 2 | Merge service consolidates a user's fragmented zone UTXOs. | ✓ | ZoneConfig, owner ViewingKeyAccount | SPP trees (CPI) | Whitelisted merge authority (proof); co-signer |
| 4 | create_zone_config | 3 | Create the zone; set the auditor key and co-signer. | — | — | ZoneConfig (create) | Zone creator signs |
| 5 | update_zone_config | 4 | Rotate the auditor key, co-signer, or authority; burning the authority freezes the config. | — | — | ZoneConfig | `authority` signs |
| 6 | create_viewing_key_account | 5 | Register a shared viewing key with recovery and auditor ciphertexts. | — | ZoneConfig | ViewingKeyAccount (create) | Owner signs to register recovery keys; without the owner signature the account is created auditor-only (no recovery keys) |
| 7 | update_viewing_key_account | 6 | Propose recovery-key changes or a shared-key rotation through the smart account. | — | ViewingKeyAccount | KeyUpdateProposal (create) | Smart account approval |
| 8 | migrate_viewing_key_account | 7 | Permissionless re-encryption to a rotated auditor key. | — | ZoneConfig | ViewingKeyAccount | Permissionless (proof) |
| 9 | close_viewing_key_account | 8 | Close the viewing key account and reclaim rent. | — | — | ViewingKeyAccount (close) | Owner signs |
| 10 | toggle_viewing_key_account | 9 | Block or unblock transfers; while blocked, only full_withdrawal remains available. | — | — | ViewingKeyAccount (state) | Owner signs |
| 11 | full_withdrawal | 10 | Escape-hatch exit without the co-signer or backend. | — | ViewingKeyAccount | SPP trees (CPI), SPL vault | Owner signs |
| 12 | create_proposal | 11 | Queue a deposit, withdrawal, or transfer for async execution. | — | ViewingKeyAccount | Proposal (create) | Proposer signs (smart account) |
| 13 | cancel_proposal | 12 | Cancel a queued proposal before execution. | — | — | Proposal (close) | Proposer / owner signs |
| 14 | execute_proposal | 13 | Relayer/co-signer settles an approved proposal with the proof. | ✓ | Proposal, ZoneConfig, sender + recipient ViewingKeyAccount | SPP trees (CPI), Proposal (close) | Co-signer / relayer signs |
| 15 | execute_key_update | 14 | Backend settles an approved key update proposal with the key rotation proof. | — | KeyUpdateProposal, ZoneConfig | ViewingKeyAccount, KeyUpdateProposal (close) | Zone backend signs (proof) |
| 16 | cancel_key_update | 15 | Cancel a queued key update proposal before execution and reclaim rent. | — | — | KeyUpdateProposal (close) | Proposer / owner signs (smart account) |

#### transact

Verifies the zone proof, then CPIs SPP `zone_transact`, which verifies the SPP proof and settles the UTXO state transition. One entrypoint for deposit, withdrawal, and transfer; `public_amount` selects the operation.

**Accounts**

1. `payer` — fee payer (relayer for transfer/withdrawal, user for deposit); signer, writable.
2. `co_signer` — zone co-signer; signer.
3. `zone_config` — read.
4. `sender_viewing_key_account` — read, writable (`blinding_nonce` incremented).
5. `recipient_viewing_key_account` — read (transfer only).
6. `zone_auth` — zone PDA; signs the SPP CPI.
7. `spp_program` — SPP program (CPI target).
8. `tree_account` — SPP nullifier + UTXO trees; writable. TODO: allow multiple trees

**Instruction data**

`M` = output UTXOs, `N` = spent inputs.

```rust
struct TransactIxData {
    /// Compressed Groth16 zone proof with commitment.
    zone_proof: ZoneProof,
    /// Compressed Groth16 SPP proof; forwarded to SPP.
    spp_proof: SppProof,
    /// Some for deposit/withdrawal, None for transfer.
    public_amount: Option<u64>,
    /// Public input shared with the SPP proof.
    private_tx_hash: [u8; 32],
    /// Unix timestamp after which the transaction is rejected.
    expiry: i64,
    /// One hash per output UTXO. Length M.
    output_utxo_hashes: Vec<[u8; 32]>,
    /// Per input: root-cache index in its UTXO tree. Length N.
    utxo_tree_root_index: Vec<u16>,
    /// Per input: root-cache index in its nullifier tree. Length N.
    nullifier_tree_root_index: Vec<u16>,
    /// Output ciphertexts, zone serialization. Checked by the zone proof, not parsed by SPP.
    encrypted_utxos: Vec<u8>,
}
```

**Encrypted UTXO Serialization**

The `sender_viewing_key_account` and `recipient_viewing_key_account` identify the owners and serve as view tags, so the ciphertext contains no pubkeys or tags. A transfer moves one asset with no separate SOL change, so the sender has one change output and each recipient one. The asset stays private; each ciphertext includes its own `asset_id`.

The sender change derives its blinding from the `blinding_seed` in its viewing key account as `Poseidon(blinding_seed, blinding_nonce)`, so only its amount and asset are transmitted, in a separate ciphertext encrypted to the sender's shared viewing key. Each recipient output transmits amount, asset, and the sender-chosen blinding, encrypted to the recipient's shared viewing key. One ephemeral `tx_viewing_pk` is shared across all ciphertexts.

```rust
struct EncryptedUtxos {
    /// Ephemeral P-256 key; ECDH with the sender's and each recipient's shared viewing key.
    tx_viewing_pk: P256Pubkey,
    /// Sender change: amount + asset. Blinding is derived, not transmitted.
    sender_ciphertext: SenderCiphertext,
    /// One per recipient UTXO. Length R.
    recipient_ciphertexts: Vec<RecipientCiphertext>,
}

struct SenderPlaintext {
    amount: u64,
    asset_id: u64,
}

struct RecipientPlaintext {
    amount: u64,
    asset_id: u64,
    /// Random blinding chosen by the sender.
    blinding: [u8; 31],
}
```

The recipient reconstructs its UTXO from the plaintext plus `owner` (the `recipient_viewing_key_account` owner). The sender derives its change blinding from the seed.

The Squads backend is the relayer and the `payer`: it pays the Solana base fee natively, so there is no in-pool reimbursement. The zone passes `relayer_fee = 0` to the SPP CPI and omits the field from its own instruction data.

Blob size: `33 (tx_viewing_pk) + 32 (sender_ciphertext) + 4 (Vec len) + 63·R`.

| R | Blob (B) |
| --- | --- |
| 0 | 69 |
| 1 | 132 |

**Transaction Size**

Fixed-size fields: `zone_proof 192 + spp_proof 192 + private_tx_hash 32 + expiry 8 = 424`, plus `public_amount` (1 `None`, 9 `Some`). Four `Vec` fields each add a 4-byte length prefix: `output_utxo_hashes` (`32·M`), `utxo_tree_root_index` (`2·N`), `nullifier_tree_root_index` (`2·N`), and `encrypted_utxos` (`69 + 63·R`, see [Encrypted UTXO Serialization](#encrypted-utxo-serialization)). Data total for a transfer: `510 + 32·M + 4·N + 63·R`.

Each account address costs 32 bytes when written in full, or ~1 byte when referenced through an address-lookup table (ALT). The static accounts (`zone_config`, `zone_auth`, `spp_program`, `tree_account`) are referenced through the ALT; `payer`, `co_signer`, the viewing key accounts, and `zone_program_id` are written in full. The transaction total assumes one signer (65 B), the message header (3 B), a recent blockhash (32 B), and the instruction framing.

| Shape | Inputs (N) | Outputs (M) | Data (B) | Full keys | ALT keys | Tx total (B) |
| --- | --- | --- | --- | --- | --- | --- |
| transfer | 1 | 2 | 641 | 4 | 4 | 954 |

**Withdraw Transaction Size**

A withdrawal is a 1-in 1-out circuit with the withdrawn amount public (`public_amount` `Some`, 9 B). The single output is the sender's change, so it uses only the sender ciphertext (`R = 0`, `encrypted_utxos` `69` B), and there is no `recipient_viewing_key_account`.

Data, at `M = N = 1`: `424 + 9 (public_amount) + (4 + 32) + (4 + 2) + (4 + 2) + (4 + 69) = 554` B.

A withdrawal also moves SPL out of the pool: `spl_token_program` and `spl_interface` are referenced through the ALT, and `spl_recipient_account` is written in full.

| Shape | Inputs (N) | Outputs (M) | Data (B) | Full keys | ALT keys | Tx total (B) |
| --- | --- | --- | --- | --- | --- | --- |
| withdraw | 1 | 1 | 554 | 4 | 6 | 871 |


# TODO:
1. add detailed instruction data layout (the merge proof uses verifiable encryption, )
2. remove merge authority whitelist, add merge authorities vec to protocol config
3. specify  Async deposit SPL-source authorization. same as in dev/confidential-transfers
4. specify Replay protection for signed async proposals: spec relies on commitment_hash + nullifier + expiry; the impl additionally has signing_nonce. State explicitly that the UTXO nullifier is what prevents async-proposal replay, we should add the nonce

# Notes:
1. Multiple auditors viewking key accounts are compatible with multiple auditors. The protocol config currently only contains one auditor key. If we add multiple auditor keys to the protocol config should every viewing key account be encrypted to all or only 1 auditor? (we could let the co-signer enforce this dynamically.)
2. Relayer fee is hardcoded to 0 since we assume squads backend sponsors fees.
