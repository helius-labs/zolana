
# Registry

Spec for a solana program and indexer that implement the registry spec from spec.md.

## Program

Maps a Solana pubkey to a [ShieldedPubkey](#wallet) and the current sync delegate.

### Account

| Account | Description |
| --- | --- |
| Owner record | Per-owner PDA, seeds = `["zolana/registry/v0", solana_owner_pubkey]`. Owned by the Registry program. The owner Solana signer can write all paths; the current delegate Solana signer can write `delegate_rotate` and `revoke`. Append-only entry history. |

```rust
struct OwnerRecord {
    /// Is static.
    owner: Address,
    /// Is static.
    /// Used for both signing and encryption if no delegate is set.
    owner_p256: P256Pubkey,
    /// Owner can set a delegate.
    /// Delegate can revoke itself and rotate its key.
    delegate: Option<Address>,
    /// Append-only delegate entries. New entries are pushed; old entries remain so that
    /// pre-rotation ciphertexts stay decryptable by recipients and sync
    /// delegates that retained the corresponding `encryption_sk`.
    entries: Vec<Entry>,
}

impl OwnerRecord {

    /// Invariant maintained by the program:
    /// `self.delegate.is_some() ⇔ self.entries.last().is_some()`.
    pub fn shielded_pubkey(&self) -> ShieldedPubkey {
        match self.entries.last() {
            Some(entry) => ShieldedPubkey {
                signing:    self.owner_p256,
                encryption: entry.encryption_pk,
            },
            None => ShieldedPubkey {
                signing:    self.owner_p256,
                encryption: self.owner_p256,
            },
        }
    }
}

struct Entry {
    /// Delegate's P-256 SEC1-compressed pubkey: the ECDH counterparty.
    /// A recipient with `owner_sk` recomputes the epoch's encryption secret
    /// as `encryption_sk := KDF(ECDH(owner_sk, sync_pk))`
    /// (see [Wallet](#wallet)).
    sync_pk: [u8; 33],
    /// `encryption_sk · G`. Cached so senders can read it without `owner_sk`.
    encryption_pk: [u8; 33],
    /// Unix seconds; set by the program from `Clock` on append.
    created_at: i64,
}
```

### Instructions

| Instruction | Signer | Description |
| --- | --- | --- |
| register | owner | Tag 0; creates the `OwnerRecord` PDA with `owner_p256` set, `delegate = None`, `entries = []`. |
| set_delegate | owner | Tag 1; appoints (or replaces) the current delegate. Sets `delegate` and appends a new `Entry`. |
| delegate_rotate | current delegate | Tag 2; appends a new `Entry`; `delegate` Solana address unchanged. |
| revoke | owner OR current delegate | Tag 3; clears `delegate`. Existing `entries` are not modified. |
| close | owner | Tag 4; closes the `OwnerRecord` PDA and refunds rent. Only permitted while `entries.is_empty()`. |

No P-256 proof-of-possession is required over `owner_p256`, `sync_pk`, or `encryption_pk`. A malformed entry only harms the registrant — senders following it produce ciphertexts no one can decrypt. Wallets MAY warn when their own `owner_p256` does not match the on-chain value, or when the published `encryption_pk` differs from `KDF(ECDH(owner_sk, sync_pk)) · G`.

#### `register`

**Discriminator:** 0

**Accounts**

| # | Name | W | S | Notes |
| --- | --- | --- | --- | --- |
| 1 | owner_record | x |   | PDA, created by this instruction |
| 2 | owner |   | x | Solana owner pubkey; pays rent |
| 3 | system_program |   |   | for PDA creation |

**Instruction data**

```rust
struct RegisterIxData {
    owner_p256: [u8; 33],
}
```

**Checks**

1. `owner_record` PDA does not yet exist.
2. `owner_p256[0] != 0` (valid SEC1-compressed prefix).
3. Initialize `OwnerRecord { owner: accounts.owner.key, owner_p256, delegate: None, entries: [] }`.

#### `set_delegate`

**Discriminator:** 1

**Accounts**

| # | Name | W | S | Notes |
| --- | --- | --- | --- | --- |
| 1 | owner_record | x |   | existing PDA |
| 2 | owner |   | x | Solana owner pubkey |

**Instruction data**

```rust
struct SetDelegateIxData {
    delegate: Address,
    sync_pk: [u8; 33],
    encryption_pk: [u8; 33],
}
```

**Checks**

1. `owner_record.owner == accounts.owner.key`.
2. `sync_pk[0] != 0` and `encryption_pk[0] != 0`.
3. Set `owner_record.delegate = Some(delegate)`.
4. Append `Entry { sync_pk, encryption_pk, created_at: current_unix_ts }`.

Calling `set_delegate` while a delegate is already set replaces the appointment. The previous epoch's `Entry` stays in `entries`; a new `Entry` is appended.

#### `delegate_rotate`

**Discriminator:** 2

**Accounts**

| # | Name | W | S | Notes |
| --- | --- | --- | --- | --- |
| 1 | owner_record | x |   | existing PDA |
| 2 | delegate |   | x | current `owner_record.delegate` |

**Instruction data**

```rust
struct DelegateRotateIxData {
    sync_pk: [u8; 33],
    encryption_pk: [u8; 33],
}
```

**Checks**

1. `owner_record.delegate == Some(accounts.delegate.key)`.
2. `sync_pk[0] != 0` and `encryption_pk[0] != 0`.
3. Append `Entry { sync_pk, encryption_pk, created_at: current_unix_ts }`. `owner_record.delegate` is unchanged.

#### `revoke`

**Discriminator:** 3

**Accounts**

| # | Name | W | S | Notes |
| --- | --- | --- | --- | --- |
| 1 | owner_record | x |   | existing PDA |
| 2 | signer |   | x | either `owner_record.owner` or `owner_record.delegate` |

**Instruction data**

```rust
struct RevokeIxData {}
```

**Checks**

1. `accounts.signer.key == owner_record.owner` OR `owner_record.delegate == Some(accounts.signer.key)`.
2. Set `owner_record.delegate = None`. `entries` are not modified.

After `revoke`, `shielded_pubkey()` returns `(owner_p256, owner_p256)`. The owner re-appoints with `set_delegate`.

#### `close`

**Discriminator:** 4

**Accounts**

| # | Name | W | S | Notes |
| --- | --- | --- | --- | --- |
| 1 | owner_record | x |   | existing PDA; rent refunded to `owner` |
| 2 | owner |   | x | Solana owner pubkey |

**Instruction data**

```rust
struct CloseIxData {}
```

**Checks**

1. `owner_record.owner == accounts.owner.key`.
2. `owner_record.entries.is_empty()`.
3. Close the PDA; transfer lamports to `owner`.

`close` is only legal before the first `set_delegate`. Once any delegate epoch is recorded, the entry history must persist so historic ciphertexts remain decryptable.

### Lookup semantics

Senders translating a Solana address to a `ShieldedPubkey`:

1. Read the `OwnerRecord` PDA at `["zolana/registry/v0", solana_owner_pubkey]`. Absent → registry miss; fall back to no-registry behaviour ([Wallet Transfer User Flows](#wallet-transfer-user-flows) Scenarios 5–6).
2. Use `OwnerRecord::shielded_pubkey()`. The result is always a valid `ShieldedPubkey` — `(owner_p256, owner_p256)` in a standalone epoch, `(owner_p256, entries.last().encryption_pk)` in a delegate epoch.

Recipients restoring from mnemonic decrypt ciphertexts epoch by epoch:

- Ciphertexts received during a standalone epoch (no delegate at the time) are decryptable with `encryption_sk = owner_sk`.
- Ciphertexts received during a delegate epoch `entries[i]` are decryptable with `encryption_sk = KDF(ECDH(owner_sk, entries[i].sync_pk))`. Recipients try entries newest → oldest, matching the ciphertext's intended recipient pubkey against the cached `entries[i].encryption_pk` to short-circuit.

### Notes

1. Wallets SHOULD register even without a sync delegate. Without a record, senders holding only the wallet's Solana address fall back to unshield / SPL transfer (Scenarios 5–6).


## Indexer
