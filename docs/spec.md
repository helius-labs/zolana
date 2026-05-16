# Spec

## Table of Contents

- [Abstract](#abstract)
- [Architecture](#architecture)
  - [Operations](#operations)
    - [User](#user)
    - [Protocol](#protocol)
  - [Concurrency](#concurrency)
  - [Wallet](#wallet)
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
- [Encryption](#encryption)
- [SPP - Shielded Pool Program](#spp---shielded-pool-program)
  - [Accounts](#accounts)
  - [Instructions](#instructions)
    - [transact](#transact)
- [Policy Program Interface](#policy-program-interface)
- [RPC](#rpc)
  - [Photon Indexer](#photon-indexer)
  - [Pocket RPC](#pocket-rpc)
  - [Decryption Service](#decryption-service)
  - [Merge Service](#merge-service)
- [Notes](#notes)

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

P256 keypair held by the user. Signs transactions (P256 signature verified inside the SPP proof) and decrypts UTXOs encrypted to the user's pubkey.

## Default Pocket

The default pocket is similar to zcash and has no policy.
Users invoke the SPP directly.
Merge and decryption services are optional and can be used for performance and improved UX.

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

Options:

1. H(utxo_hash, blinding)
    1. pro: no additional data necessary to convey information
    2. con:
2. H(utxo_hash, dns)
    1. dns = Poseidon(utxo_hash, nullifier_secret)
    2. nullifier_secret = KDF("nullifier", P256_privkey)

**Checks**

| Check | Description |
| --- | --- |
| UTXO Ownership | Spent input UTXOs MUST be authorized by their owner, either with a P256 signature verified in circuit or a Solana signer checked by SPP. The P256 signature binds `signing_nonce` and `expiry_unix_ts` alongside the input UTXOs to prevent prover replay. Pubkeys are encoded as Poseidon(pubkey_low, pubkey_high). |
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

# Encryption

Encrypted data is unchecked in SPP. Users and policies are free to implement custom encryption schemes. This section describes standardized encryption schemes used by the default pocket. Policy pockets define their own encryption separately.

1. Cleartext Shield
2. Transfer No FMD
3. UTXO Split Encryption
4. Transfer With FMD

For schemes that encrypt, AES-GCM keys are derived per recipient via `ECDH(ephemeral_sk, owner.pubkey)`. A single `ephemeral_pubkey` is shared across all recipients in a transaction.

### Cleartext Shield

No encryption. Output UTXO fields are carried in cleartext; `blinding = 0` and is reconstructed at deserialization.

Instruction data layout:

| Offset | Size | Field | Type | Description |
| --- | --- | --- | --- | --- |
| 0 | 1 | type_prefix | u8 | discriminator (shield) |
| 1 | 34 | owner.pubkey | 1-byte prefix + P256 (SEC1-compressed) | output UTXO owner |
| 35 | 8 | asset_id | u64 |  |
| 43 | 8 | asset_amount | u64 |  |

Total: **51 bytes**.

### Transfer No FMD

One ciphertext per output UTXO (M total). Each is encrypted to its own owner; the sender's change ciphertext additionally carries `nullifier_data` so the sender's wallet can recover the spent inputs.

A standard transfer creates a bundle of outputs per recipient (e.g. 1 SOL + 1 SPL). One ciphertext encodes the whole bundle; per-output blindings are derived from a single 31-byte `blinding_seed`:

```
blinding_i = Sha256BE(blinding_seed || u8(position_i))
```

where `position_i` is the index of the output within the bundle.

Plain text layout (per recipient bundle, AES-GCM plaintext):

| Offset | Size | Field | Type | Description |
| --- | --- | --- | --- | --- |
| 0 | 34 | owner.pubkey | 1-byte prefix + P256 (SEC1-compressed) | shared owner of this bundle |
| 34 | 8 | spl_asset_id | u64 | from per-mint [Asset registry](#accounts); `0` if no SPL output in the bundle |
| 42 | 8 | spl_amount | u64 | `0` if no SPL output in the bundle |
| 50 | 8 | sol_amount | u64 | `0` if no SOL output in the bundle |
| 58 | 31 | blinding_seed | `[u8; 31]` | derives per-output blindings via `Sha256BE(seed \|\| position)` |

Plain text size: **89 bytes** per recipient ciphertext (→ **105 bytes** ciphertext after the 16-byte GCM tag). The sender's change ciphertext appends `nullifier_data: [u8;32] × N` (one full nullifier per spent input), bringing it to `89 + 32·N` bytes plaintext / `105 + 32·N` bytes ciphertext.

Instruction data layout (on-chain in `encrypted_utxos`):

| Offset | Size | Field | Description |
| --- | --- | --- | --- |
| 0 | 1 | type_prefix | discriminator (transfer) |
| 1 | 34 | ephemeral_pubkey | shared P256 pubkey for ECDH key derivation |
| 35 | 1 | num_recipients | u8; number of recipient bundles `R` that follow the sender's ciphertext |
| 36 | 105 + 32·N | ciphertext_sender | sender's change bundle: `89 + 32·N` plaintext + 16-byte GCM tag |
| ... | 105 × R | ciphertext_recipients | one per recipient bundle: 89-byte plaintext + 16-byte GCM tag |

Total: `36 + 105·(1 + R) + 32·N` bytes. Standard single-recipient transfer: `R = 1`, total `246 + 32·N`.

### Transfer With FMD

Same as [Transfer No FMD](#transfer-no-fmd), with a 68-byte `fmd_prefix` prepended to each recipient ciphertext so recipients can scan efficiently. The sender's change ciphertext does not need an FMD clue (the sender already knows it owns the output).

Instruction data layout:

| Offset | Size | Field | Description |
| --- | --- | --- | --- |
| 0 | 1 | type_prefix | discriminator (transfer + FMD) |
| 1 | 34 | ephemeral_pubkey |  |
| 35 | 1 | num_recipients | u8; number of recipient `(fmd_prefix, ciphertext)` pairs that follow |
| 36 | 105 + 32·N | ciphertext_sender | sender's change bundle, no FMD clue |
| ... | (68 + 105) × R | fmd_prefix + ciphertext per recipient bundle | one FMD clue + ciphertext per recipient bundle |

Total: `36 + (105 + 32·N) + 173·R = 141 + 173·R + 32·N` bytes. Standard single-recipient transfer: `R = 1`, total `314 + 32·N`.

### UTXO Split Encryption

All M outputs share the same owner, amount, blinding, and asset, so a single ciphertext encodes them.

Plain text layout (AES-GCM plaintext):

| Offset | Size | Field | Type | Description |
| --- | --- | --- | --- | --- |
| 0 | 34 | owner.pubkey | 1-byte prefix + P256 (SEC1-compressed) | shared owner of all M outputs |
| 34 | 1 | num_outputs | u8 | M |
| 35 | 8 | asset_id | u64 | from per-mint [Asset registry](#accounts) |
| 43 | 8 | asset_amount | u64 | shared across all M outputs |
| 51 | 31 | blinding | `[u8; 31]` | shared across all M outputs |

Plain text size: **82 bytes** (→ **98 bytes** ciphertext after the 16-byte GCM tag).

Instruction data layout:

| Offset | Size | Field | Description |
| --- | --- | --- | --- |
| 0 | 1 | type_prefix | discriminator (split) |
| 1 | 34 | ephemeral_pubkey |  |
| 35 | 98 | ciphertext | 82-byte plaintext + 16-byte GCM tag |

Total: **133 bytes**.

# SPP - Shielded Pool Program

## Accounts

| Account | Description |
| --- | --- |
| Tree account | Contains the nullifier tree (`light-batched-merkle-tree`, H=40), nullifier queue, and UTXO tree (sparse Merkle tree, H=26). |
| SPL interface vault | Per-mint SPL / Token-22 vault holding all shielded SPL tokens. |
| Asset registry | PDA derived from the mint, set at `create_spl_interface` time. Stores the `asset_id: u64` assigned to that mint (used as the compact asset identifier inside UTXOs and ciphertexts). |
| Asset counter | Singleton account holding the monotonic `next_asset_id: u64`. Incremented on each `create_spl_interface`. |
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

| Field | Type | Size | Notes |
| --- | --- | --- | --- |
| expiry_unix_ts | u64 | 8 | Unix timestamp in seconds |
| signing_nonce | [u8;31] | 31 | per-tx random nonce signed alongside the input UTXOs (replay protection against the prover) |
| proof | Compressed Groth16 proof | 192 |  |
| relayer_fee | u16 | 2 | zero on shield (payer = user) |
| output_utxo_hashes | [u8;32] × M | 32·M | one per output; appended to [UTXO tree](#accounts) |
| nullifier_root_index | u16 × N | 2·N | ref into nullifier-tree root cache |
| tx_hash | Option\<[u8;32]\> | 1 or 33 |  |
| public_sol_amount | Option\<u64\> | 1 or 9 | `Some` for shield/unshield SOL, `None` for shielded transfer |
| public_spl_amount | Option\<u64\> | 1 or 9 | `Some` for shield/unshield SPL, `None` for shielded transfer |
| encrypted_utxos | Vec\<u8\> | variable | opaque ciphertext blob; any length, not checked by the program |

Size by circuit shape (total tx size, ciphertext included)\*:

| Circuit | N (nullifiers) | M (output utxo hashes) | ciphertext (B) | tx overhead (B)\*\* | shield / unshield (B) | transfer (B) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 in 1 out | 1 | 1 | 51 | 206 | 543 | — |
| 1 in 2 out | 1 | 2 | 278 | 206 | 802 | 786 |
| 3 in 3 out | 3 | 3 | 342 | 206 | 902 | 886 |
| 5 in 3 out | 5 | 3 | 406 | 206 | 970 | 954 |
| 1 in 8 out | 1 | 8 | 133 | 206 | 849 | 833 |

\* assumes `tx_hash = None`.
\*\* assumes ALT for `tree_account`, `payer` and `program_id` inline; overhead = 64 (signature) + 3 (message header) + 65 (inline account keys: compact-u16 count + 2 × 32-byte pubkeys for `payer` and `program_id`) + 32 (recent blockhash) + 36 (ALT section: compact-u16 count + 32-byte ALT pubkey + writable count + writable index + readonly count) + 6 (instruction body: program_id_index + account_indices + data_len_varint).

**Checks**

1. `current_unix_ts <= expiry_unix_ts` (Solana `Clock.unix_timestamp`)
2. Each `nullifier_root_index` references a non-stale root.
3. `tree_account` is not paused.
4. Proof verifies against public inputs.
5. Append each `output_utxo_hashes[i]` to the UTXO sparse Merkle tree.
6. Insert each nullifier into the nullifier queue.
7. If `public_sol_amount` is `Some`, transfer `public_sol_amount + relayer_fee` lamports of SOL between `payer` and the pool (shield: payer → pool; unshield: pool → recipient). The `relayer_fee` portion compensates the relayer.
8. If `public_spl_amount` is `Some`, CPI the token program to transfer SPL between the user and the vault token account (shield: user → vault; unshield: vault → recipient).

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

## Pocket RPC

**Methods:**

1. get_decrypted_utxos
2. get_balance
3. get_instruction (for shield the user must sign directly)

## Decryption Service

**Idea:** An opt-in service that can be independent from an RPC that can index and decrypt a users UTXOs.

1. User decryption service handshake, similar to TLS, to establish a shared asymmetric secret

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
4.
