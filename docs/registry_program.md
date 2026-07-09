
# Registry

Solana program and indexer notes for the [Registry](#registry) section of [spec.md](spec.md).

Program id: `9EwHPNdsPHMt7kaUZaXDTaj92HVC8CL4Q16io4Vu87t4`

## Program

Maps a Solana pubkey to a [ShieldedAddress](#shielded-address) and the current sync delegate.

### Account

| Account | Description |
| --- | --- |
| User record | Per-owner PDA, seeds = `["rings/registry/v0", owner]`. Owned by the user-registry program. The owner Solana signer can write `register`, `set_sync_delegate`, and `revoke_sync_delegate`. The active sync delegate Solana signer can write `rotate_sync_delegate_key` and `revoke_sync_delegate`. Append-only entry history. Permanent once created. |

Account data is prefixed with discriminator byte `1`, followed by a borsh-encoded `UserRecord`. The canonical PDA bump is stored in `UserRecord.bump`.

```rust
struct UserRecord {
    /// Static.
    owner: Address,
    /// Canonical PDA bump; stored so reads do not re-derive it.
    bump: u8,
    /// Static P-256 signing pubkey. `None` for Solana-only owners.
    owner_p256: Option<P256Pubkey>,
    /// Static wallet nullifier pubkey. Must be canonical (`< Fr`).
    nullifier_pubkey: [u8; 32],
    /// Static wallet viewing pubkey, published to senders while no sync delegate is set.
    viewing_pubkey: P256Pubkey,
    /// Active sync delegate Solana pubkey, or none after revoke.
    sync_delegate: Option<Address>,
    /// Append-only sync-delegate epochs.
    entries: Vec<SyncDelegateEntry>,
}

struct SyncDelegateEntry {
    /// Sync delegate Solana pubkey at the time this entry was appended.
    delegate: Address,
    /// Delegate's P-256 ECDH pubkey.
    sync_pubkey: P256Pubkey,
    /// Shared viewing pubkey published to senders for this entry.
    viewing_pubkey: P256Pubkey,
    /// Unix seconds from `Clock` at append time.
    created_at: i64,
}
```

Invariants (see [spec.md](spec.md#record)):

- While a sync delegate is active, `sync_delegate` is set if and only if `entries` is non-empty.
- After `revoke_sync_delegate`, `sync_delegate` is cleared; historical `entries` remain append-only.
- `entries` is append-only: never modified or removed.
- `nullifier_pubkey`, `owner_p256`, and `viewing_pubkey` do not rotate in place.
- No close or delete operation.

Sender-facing viewing pubkey:

```rust
impl UserRecord {
    pub fn sender_viewing_pubkey(&self) -> P256Pubkey {
        if self.sync_delegate.is_some() {
            self.entries.last()
                .map(|entry| entry.viewing_pubkey)
                .unwrap_or(self.viewing_pubkey)
        } else {
            self.viewing_pubkey
        }
    }
}
```

### Instructions

Wire format: one-byte instruction discriminator, then borsh instruction data (empty for `revoke_sync_delegate`).

| Instruction | Discriminator | Signer | Description |
| --- | --- | --- | --- |
| `register` | 0 | owner | Creates the user-record PDA with static keys, `sync_delegate = None`, `entries = []`. |
| `set_sync_delegate` | 1 | owner | Appoints or replaces the active sync delegate. Sets `sync_delegate` and appends a new entry. |
| `rotate_sync_delegate_key` | 2 | active sync delegate | Appends a new entry; `sync_delegate` address unchanged. |
| `revoke_sync_delegate` | 3 | owner OR active sync delegate | Clears `sync_delegate`. Existing `entries` are not modified. |

No on-chain proof that `viewing_pubkey` equals `KDF(ECDH(...)) · G`. The program only checks P-256 compressed prefixes (`0x02` / `0x03`) and canonical `nullifier_pubkey`. A malformed entry only harms the registrant.

#### `register`

**Accounts**

| # | Name | W | S | Notes |
| --- | --- | --- | --- | --- |
| 1 | user_record | x |   | PDA, created by this instruction |
| 2 | owner | x | x | Solana owner pubkey; pays rent |
| 3 | system_program |   |   | for PDA creation |

**Instruction data**

```rust
struct RegisterData {
    owner_p256: Option<P256Pubkey>,
    nullifier_pubkey: [u8; 32],
    viewing_pubkey: P256Pubkey,
}
```

**Checks**

1. `user_record` PDA does not yet exist.
2. `owner_p256` and `viewing_pubkey` use valid SEC1-compressed prefixes when present.
3. `nullifier_pubkey < Fr`.
4. Initialize `UserRecord` with `sync_delegate = None`, `entries = []`, stored bump.

#### `set_sync_delegate`

**Accounts**

| # | Name | W | S | Notes |
| --- | --- | --- | --- | --- |
| 1 | user_record | x |   | existing PDA |
| 2 | owner | x | x | record owner |
| 3 | system_program |   |   | for realloc / rent top-up |

**Instruction data**

```rust
struct SetSyncDelegateData {
    sync_delegate: Address,
    sync_pubkey: P256Pubkey,
    viewing_pubkey: P256Pubkey,
}
```

**Checks**

1. `user_record.owner == accounts.owner.key`.
2. `sync_pubkey` and `viewing_pubkey` use valid SEC1-compressed prefixes.
3. Set `sync_delegate = Some(sync_delegate)`.
4. Append `SyncDelegateEntry { delegate: sync_delegate, sync_pubkey, viewing_pubkey, created_at }`.
5. Grow account to `UserRecord::space_for(entries.len())`.

Calling `set_sync_delegate` while a sync delegate is already set replaces the appointment. The previous epoch's entry stays in `entries`; a new entry is appended.

#### `rotate_sync_delegate_key`

**Accounts**

| # | Name | W | S | Notes |
| --- | --- | --- | --- | --- |
| 1 | user_record | x |   | existing PDA |
| 2 | sync_delegate | x | x | must match `user_record.sync_delegate` |
| 3 | system_program |   |   | for realloc / rent top-up |

**Instruction data**

```rust
struct RotateSyncDelegateKeyData {
    sync_pubkey: P256Pubkey,
    viewing_pubkey: P256Pubkey,
}
```

**Checks**

1. `user_record.sync_delegate == Some(accounts.sync_delegate.key)`.
2. `sync_pubkey` and `viewing_pubkey` use valid SEC1-compressed prefixes.
3. Append entry with `delegate = accounts.sync_delegate.key`. `sync_delegate` field unchanged.
4. Grow account to `UserRecord::space_for(entries.len())`.

#### `revoke_sync_delegate`

**Accounts**

| # | Name | W | S | Notes |
| --- | --- | --- | --- | --- |
| 1 | user_record | x |   | existing PDA |
| 2 | signer |   | x | `user_record.owner` or active `sync_delegate` |

**Instruction data**

None (discriminator only).

**Checks**

1. `accounts.signer.key == user_record.owner` OR `user_record.sync_delegate == Some(accounts.signer.key)`.
2. `user_record.sync_delegate` is currently set.
3. Set `sync_delegate = None`. `entries` are not modified.

After `revoke_sync_delegate`, `sender_viewing_pubkey()` returns the static `viewing_pubkey`. The owner re-appoints with `set_sync_delegate`.

### Lookup semantics

Senders translating a Solana address to a shielded viewing pubkey:

1. Read the user-record PDA at `["rings/registry/v0", owner]`. Absent → registry miss; fall back to no-registry behaviour.
2. Use `UserRecord::sender_viewing_pubkey()` together with the owner's shielded identity hash from `owner_p256` / `owner`.

Recipients restoring from mnemonic decrypt ciphertexts epoch by epoch using historical `entries` and the static `viewing_pubkey` after revoke.

### Notes

1. Wallets SHOULD register even without a sync delegate. Without a record, senders holding only the wallet's Solana address fall back to unshield / SPL transfer.
2. `get_record` is an RPC account fetch, not an on-chain instruction.

## Indexer
