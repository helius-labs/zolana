use solana_address::Address;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_keypair::{P256Pubkey, PublicKey, ShieldedAddress, ShieldedKeypair, SignatureType};
use zolana_user_registry_interface::{
    instruction::{register, update_keys, RegisterData, UpdateKeysData},
    user_record_pda, user_registry_program_id, UserRecord,
};

use crate::{error::ClientError, rpc::Rpc};

/// Derive the on-chain registry record fields from a shielded keypair: the
/// P256 owner key (only for P256-owned wallets), nullifier pubkey, and viewing
/// pubkey. Returns the exact `RegisterData` the register/update instructions take.
fn register_fields(owner: Pubkey, keypair: &ShieldedKeypair) -> Result<RegisterData, ClientError> {
    let owner_p256 = match keypair.signing_pubkey().signature_type()? {
        SignatureType::P256 => Some(*keypair.signing_pubkey().as_p256()?.as_bytes()),
        SignatureType::Ed25519 => {
            if keypair.signing_pubkey().as_ed25519()? != owner.to_bytes() {
                return Err(ClientError::AddressResolution(format!(
                    "ed25519 shielded signing key does not match funding owner {owner}"
                )));
            }
            None
        }
    };
    Ok(RegisterData {
        owner_p256,
        nullifier_pubkey: keypair.nullifier_key.pubkey()?,
        viewing_pubkey: *keypair.viewing_pubkey().as_bytes(),
    })
}

/// Publish `keypair`'s shielded keys to the on-chain user-registry directory
/// under `funding`'s pubkey, so senders who know only that Solana address can
/// resolve its shielded address. Registration is optional for receiving a
/// confidential transfer to a known shielded address; it is the
/// pubkey-addressability directory.
///
/// Idempotent: registers if no record exists and returns `Ok(None)` if the
/// record already matches. A different existing record is rejected; use
/// [`update_registered_keys`] for an intentional key rotation.
///
/// `funding` must sign — the registry keys the record under its pubkey and the
/// program requires the owner's signature, so only the record's owner can
/// publish or update it.
pub fn ensure_registered<R: Rpc + ?Sized>(
    rpc: &R,
    funding: &Keypair,
    keypair: &ShieldedKeypair,
) -> Result<Option<Signature>, ClientError> {
    let owner = funding.pubkey();
    let data = register_fields(owner, keypair)?;
    let (user_record, _bump) = user_record_pda(&owner);
    let owner_address = Address::new_from_array(owner.to_bytes());

    if let Some(record) = fetch_user_record_optional_checked(rpc, owner)? {
        if record_matches_registration(&record, &data) {
            return Ok(None);
        }
        return Err(ClientError::RegistryKeysMismatch { owner });
    }

    let ix = register(user_record, owner, data);
    Ok(Some(rpc.create_and_send_transaction(
        &[ix],
        owner_address,
        &[funding],
    )?))
}

/// Explicitly replace the shielded keys in an existing registry record.
pub fn update_registered_keys<R: Rpc + ?Sized>(
    rpc: &R,
    funding: &Keypair,
    keypair: &ShieldedKeypair,
) -> Result<Option<Signature>, ClientError> {
    let owner = funding.pubkey();
    let data = register_fields(owner, keypair)?;
    let record = fetch_user_record_checked(rpc, owner)?;
    if record_matches_registration(&record, &data) {
        return Ok(None);
    }

    let (user_record, _bump) = user_record_pda(&owner);
    let ix = update_keys(
        user_record,
        owner,
        UpdateKeysData {
            owner_p256: data.owner_p256,
            nullifier_pubkey: data.nullifier_pubkey,
            viewing_pubkey: data.viewing_pubkey,
        },
    );
    Ok(Some(rpc.create_and_send_transaction(
        &[ix],
        Address::new_from_array(owner.to_bytes()),
        &[funding],
    )?))
}

fn record_matches_registration(record: &UserRecord, data: &RegisterData) -> bool {
    record.owner_p256 == data.owner_p256
        && record.nullifier_pubkey == data.nullifier_pubkey
        && record.viewing_pubkey == data.viewing_pubkey
}

pub fn fetch_user_record_checked<R: Rpc + ?Sized>(
    rpc: &R,
    owner: Pubkey,
) -> Result<UserRecord, ClientError> {
    let (record_pda, bump) = user_record_pda(&owner);
    let account = rpc
        .get_account(Address::new_from_array(record_pda.to_bytes()))?
        .ok_or(ClientError::UserRegistryRecordNotFound {
            owner,
            record: record_pda,
        })?;
    parse_user_record_account(owner, record_pda, bump, &account)
}

pub fn fetch_user_record_optional_checked<R: Rpc + ?Sized>(
    rpc: &R,
    owner: Pubkey,
) -> Result<Option<UserRecord>, ClientError> {
    let (record_pda, bump) = user_record_pda(&owner);
    let Some(account) = rpc.get_account(Address::new_from_array(record_pda.to_bytes()))? else {
        return Ok(None);
    };
    Ok(Some(parse_user_record_account(
        owner, record_pda, bump, &account,
    )?))
}

pub fn decode_user_record_account(
    account: &solana_account::Account,
) -> Result<UserRecord, ClientError> {
    if account.owner != user_registry_program_id() {
        return Err(ClientError::Rpc(
            "user record account is not owned by the user registry program".to_string(),
        ));
    }
    UserRecord::try_from_account_data(&account.data).map_err(|err| {
        ClientError::Rpc(format!("invalid user registry record account data: {err}"))
    })
}

fn parse_user_record_account(
    owner: Pubkey,
    record_pda: Pubkey,
    bump: u8,
    account: &solana_account::Account,
) -> Result<UserRecord, ClientError> {
    let record = decode_user_record_account(account)?;
    if record.owner.to_bytes() != owner.to_bytes() {
        return Err(ClientError::Rpc(format!(
            "user registry record {record_pda} stores a different owner than {owner}"
        )));
    }
    if record.bump != bump {
        return Err(ClientError::Rpc(format!(
            "user registry record {record_pda} stores non-canonical bump {} instead of {bump}",
            record.bump
        )));
    }
    Ok(record)
}

pub fn validate_registered_keypair<R: Rpc + ?Sized>(
    rpc: &R,
    owner: Pubkey,
    keypair: &ShieldedKeypair,
) -> Result<(), ClientError> {
    let record = fetch_user_record_checked(rpc, owner)?;
    let expected = register_fields(owner, keypair)?;
    if record.owner_p256 != expected.owner_p256
        || record.nullifier_pubkey != expected.nullifier_pubkey
        || record.viewing_pubkey != expected.viewing_pubkey
    {
        return Err(ClientError::RegistryKeysMismatch { owner });
    }
    Ok(())
}

pub fn resolve_registered_address<R: Rpc + ?Sized>(
    rpc: &R,
    owner: Pubkey,
) -> Result<ShieldedAddress, ClientError> {
    let record = fetch_user_record_checked(rpc, owner)?;
    resolved_address_from_record(owner, &record)
}

pub fn try_resolve_registered_address<R: Rpc + ?Sized>(
    rpc: &R,
    owner: Pubkey,
) -> Result<Option<ShieldedAddress>, ClientError> {
    let Some(record) = fetch_user_record_optional_checked(rpc, owner)? else {
        return Ok(None);
    };
    Ok(Some(resolved_address_from_record(owner, &record)?))
}

pub(crate) fn resolved_address_from_record(
    owner: Pubkey,
    record: &UserRecord,
) -> Result<ShieldedAddress, ClientError> {
    let viewing_pubkey = P256Pubkey::from_bytes(record.sender_viewing_pubkey())?;
    Ok(ShieldedAddress {
        signing_pubkey: signing_pubkey_from_record(owner, record)?,
        nullifier_pubkey: record.nullifier_pubkey,
        viewing_pubkey,
    })
}

/// Project a registry record into the owner's base shielded address. This uses
/// `record.viewing_pubkey`, not an active sync delegate's sender-facing key.
pub(crate) fn base_address_from_record(
    owner: Pubkey,
    record: &UserRecord,
) -> Result<ShieldedAddress, ClientError> {
    Ok(ShieldedAddress {
        signing_pubkey: signing_pubkey_from_record(owner, record)?,
        nullifier_pubkey: record.nullifier_pubkey,
        viewing_pubkey: P256Pubkey::from_bytes(record.viewing_pubkey)?,
    })
}

fn signing_pubkey_from_record(
    owner: Pubkey,
    record: &UserRecord,
) -> Result<PublicKey, ClientError> {
    Ok(match record.owner_p256 {
        Some(owner_p256) => PublicKey::from_p256(&P256Pubkey::from_bytes(owner_p256)?),
        None => PublicKey::from_ed25519(&owner.to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use borsh::to_vec;
    use solana_account::Account;
    use solana_signer::Signer;
    use zolana_keypair::{ShieldedKeypair, ViewingKey};
    use zolana_user_registry_interface::{user_registry_program_id, SyncDelegateEntry};

    use super::*;

    #[derive(Default)]
    struct MockRpc {
        account: Option<(Address, Account)>,
    }

    impl Rpc for MockRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Ok(self
                .account
                .as_ref()
                .and_then(|(expected, account)| (*expected == address).then(|| account.clone())))
        }
    }

    fn account_data(record: &UserRecord) -> Vec<u8> {
        let mut data = vec![UserRecord::DISCRIMINATOR];
        data.extend_from_slice(&to_vec(record).expect("serialize user record"));
        data
    }

    fn user_record(owner: Pubkey, bump: u8) -> UserRecord {
        UserRecord {
            owner: owner.to_bytes().into(),
            bump,
            owner_p256: Some([2u8; 33]),
            nullifier_pubkey: [3u8; 32],
            viewing_pubkey: [4u8; 33],
            sync_delegate: None,
            entries: Vec::new(),
            merging_enabled: false,
        }
    }

    fn account_for(record: &UserRecord) -> Account {
        Account {
            lamports: 1,
            data: account_data(record),
            owner: user_registry_program_id(),
            executable: false,
            rent_epoch: 0,
        }
    }

    fn registered_record(owner: Pubkey, bump: u8, keypair: &ShieldedKeypair) -> UserRecord {
        UserRecord {
            owner: owner.to_bytes().into(),
            bump,
            owner_p256: Some(*keypair.signing_pubkey().as_p256().unwrap().as_bytes()),
            nullifier_pubkey: keypair.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *keypair.viewing_pubkey().as_bytes(),
            sync_delegate: None,
            entries: Vec::new(),
            merging_enabled: false,
        }
    }

    #[test]
    fn fetch_user_record_checked_reads_canonical_pda() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let record = user_record(owner, bump);
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&record),
            )),
        };

        let fetched = fetch_user_record_checked(&rpc, owner).expect("fetch user record");

        assert_eq!(fetched, record);
    }

    #[test]
    fn fetch_user_record_checked_reports_missing_record() {
        let owner = Pubkey::new_unique();
        let (pda, _) = user_record_pda(&owner);
        let rpc = MockRpc { account: None };

        let err = fetch_user_record_checked(&rpc, owner).expect_err("missing record");

        assert!(matches!(
            err,
            ClientError::UserRegistryRecordNotFound { owner: got_owner, record }
                if got_owner == owner && record == pda
        ));
    }

    #[test]
    fn fetch_user_record_optional_checked_returns_none_for_missing_record() {
        let owner = Pubkey::new_unique();
        let rpc = MockRpc { account: None };

        let record = fetch_user_record_optional_checked(&rpc, owner).expect("optional fetch");

        assert_eq!(record, None);
    }

    #[test]
    fn resolved_address_from_record_maps_registered_keys() {
        let owner = Pubkey::new_unique();
        let (_, bump) = user_record_pda(&owner);
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
        let record = registered_record(owner, bump, &keypair);

        let address = resolved_address_from_record(owner, &record).expect("resolved address");

        assert_eq!(address.signing_pubkey, keypair.signing_pubkey());
        assert_eq!(
            address.nullifier_pubkey,
            keypair.nullifier_key.pubkey().unwrap()
        );
        assert_eq!(
            address.viewing_pubkey.as_bytes(),
            keypair.viewing_pubkey().as_bytes()
        );
    }

    #[test]
    fn resolve_registered_address_fetches_and_maps_record() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
        let record = registered_record(owner, bump, &keypair);
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&record),
            )),
        };

        let address = resolve_registered_address(&rpc, owner).expect("resolved address");

        assert_eq!(address.signing_pubkey, keypair.signing_pubkey());
        assert_eq!(address.viewing_pubkey, keypair.viewing_pubkey());
    }

    #[test]
    fn validate_registered_keypair_accepts_ed25519_owner_records() {
        let owner_keypair = solana_keypair::Keypair::new();
        let seed: [u8; 32] = *owner_keypair.secret_bytes();
        let keypair =
            ShieldedKeypair::from_ed25519(&seed, ViewingKey::new()).expect("ed25519 keypair");
        let owner = owner_keypair.pubkey();
        let (pda, bump) = user_record_pda(&owner);
        let record = UserRecord {
            owner: owner.to_bytes().into(),
            bump,
            owner_p256: None,
            nullifier_pubkey: keypair.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *keypair.viewing_pubkey().as_bytes(),
            sync_delegate: None,
            entries: Vec::new(),
            merging_enabled: false,
        };
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&record),
            )),
        };

        validate_registered_keypair(&rpc, owner, &keypair).expect("valid ed25519 record");
    }

    #[test]
    fn validate_registered_keypair_rejects_ed25519_owner_mismatch() {
        let funding = Keypair::new();
        let signer = Keypair::new();
        let keypair = ShieldedKeypair::from_ed25519(signer.secret_bytes(), ViewingKey::new())
            .expect("ed25519 keypair");

        let err = register_fields(funding.pubkey(), &keypair)
            .expect_err("unrelated ed25519 signer must not be registered");
        assert!(err
            .to_string()
            .contains("ed25519 shielded signing key does not match funding owner"));
    }

    #[test]
    fn fetch_user_record_checked_rejects_owner_mismatch() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let record = user_record(Pubkey::new_unique(), bump);
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&record),
            )),
        };

        let err = fetch_user_record_checked(&rpc, owner).expect_err("owner mismatch");

        assert!(err.to_string().contains("different owner"));
    }

    #[test]
    fn fetch_user_record_checked_rejects_wrong_account_owner() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let record = user_record(owner, bump);
        let mut account = account_for(&record);
        account.owner = Pubkey::new_unique();
        let rpc = MockRpc {
            account: Some((Address::new_from_array(pda.to_bytes()), account)),
        };

        let err = fetch_user_record_checked(&rpc, owner).expect_err("program owner mismatch");

        assert!(err.to_string().contains("not owned by the user registry"));
    }

    #[test]
    fn fetch_user_record_checked_rejects_noncanonical_bump() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let record = user_record(owner, bump.wrapping_add(1));
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&record),
            )),
        };

        let err = fetch_user_record_checked(&rpc, owner).expect_err("bump mismatch");

        assert!(err.to_string().contains("non-canonical bump"));
    }

    #[test]
    fn decode_user_record_account_rejects_wrong_discriminator() {
        let mut account = Account {
            lamports: 1,
            data: vec![0],
            owner: user_registry_program_id(),
            executable: false,
            rent_epoch: 0,
        };
        account.data.extend_from_slice(
            &to_vec(&UserRecord {
                owner: [1u8; 32].into(),
                bump: 255,
                owner_p256: None,
                nullifier_pubkey: [2u8; 32],
                viewing_pubkey: [3u8; 33],
                sync_delegate: Some([4u8; 32]),
                entries: vec![SyncDelegateEntry {
                    delegate: [4u8; 32],
                    sync_pubkey: [5u8; 33],
                    viewing_pubkey: [6u8; 33],
                    created_at: 1,
                }],
                merging_enabled: false,
            })
            .expect("serialize user record"),
        );

        let err = decode_user_record_account(&account).expect_err("bad discriminator");

        assert!(err
            .to_string()
            .contains("missing user record discriminator"));
    }

    /// Mock that serves an optional record account and captures the sent
    /// transaction so registry write behavior can be asserted without a validator.
    #[derive(Default)]
    struct SendMockRpc {
        account: Option<(Address, Account)>,
        sent: std::cell::RefCell<Option<solana_transaction::Transaction>>,
    }

    impl Rpc for SendMockRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Ok(self
                .account
                .as_ref()
                .and_then(|(expected, account)| (*expected == address).then(|| account.clone())))
        }

        fn get_latest_blockhash(&self) -> Result<(solana_hash::Hash, u64), ClientError> {
            Ok((solana_hash::Hash::default(), 0))
        }

        fn send_transaction(
            &self,
            transaction: &solana_transaction::Transaction,
        ) -> Result<Signature, ClientError> {
            *self.sent.borrow_mut() = Some(transaction.clone());
            Ok(Signature::default())
        }
    }

    fn account_at(owner: Pubkey, record: &UserRecord) -> (Address, Account) {
        let (pda, _bump) = user_record_pda(&owner);
        (Address::new_from_array(pda.to_bytes()), account_for(record))
    }

    fn ensure_registered_ix_tag(rpc: &SendMockRpc) -> u8 {
        // First byte of the single instruction's data = the user-registry tag.
        rpc.sent
            .borrow()
            .as_ref()
            .expect("a tx was sent")
            .message
            .instructions[0]
            .data[0]
    }

    #[test]
    fn ensure_registered_registers_when_absent() {
        let funding = Keypair::new();
        let keypair = ShieldedKeypair::new().unwrap();
        let rpc = SendMockRpc::default(); // no record -> register path
        let sig = ensure_registered(&rpc, &funding, &keypair).expect("ensure_registered");
        assert!(sig.is_some(), "register should send a transaction");
        // Tag 0 = register (first user-registry instruction tag).
        assert_eq!(
            ensure_registered_ix_tag(&rpc),
            zolana_user_registry_interface::instruction::discriminator::REGISTER
        );
    }

    #[test]
    fn ensure_registered_noops_when_current() {
        let funding = Keypair::new();
        let keypair = ShieldedKeypair::new().unwrap();
        let owner = funding.pubkey();
        let (_pda, bump) = user_record_pda(&owner);
        let record = registered_record(owner, bump, &keypair);
        let rpc = SendMockRpc {
            account: Some(account_at(owner, &record)),
            ..Default::default()
        };
        let sig = ensure_registered(&rpc, &funding, &keypair).expect("ensure_registered");
        assert!(sig.is_none(), "matching record must not send a transaction");
        assert!(rpc.sent.borrow().is_none());
    }

    #[test]
    fn ensure_registered_refuses_changed_keys() {
        let funding = Keypair::new();
        let keypair = ShieldedKeypair::new().unwrap();
        let owner = funding.pubkey();
        let (_pda, bump) = user_record_pda(&owner);
        let stale = registered_record(owner, bump, &ShieldedKeypair::new().unwrap());
        let rpc = SendMockRpc {
            account: Some(account_at(owner, &stale)),
            ..Default::default()
        };

        assert!(matches!(
            ensure_registered(&rpc, &funding, &keypair),
            Err(ClientError::RegistryKeysMismatch { owner: got }) if got == owner
        ));
        assert!(rpc.sent.borrow().is_none());
    }

    #[test]
    fn update_registered_keys_rotates_changed_keys() {
        let funding = Keypair::new();
        let keypair = ShieldedKeypair::new().unwrap();
        let owner = funding.pubkey();
        let (_pda, bump) = user_record_pda(&owner);
        let stale = registered_record(owner, bump, &ShieldedKeypair::new().unwrap());
        let rpc = SendMockRpc {
            account: Some(account_at(owner, &stale)),
            ..Default::default()
        };

        let signature = update_registered_keys(&rpc, &funding, &keypair)
            .expect("explicit key rotation")
            .expect("rotation transaction");
        assert_eq!(signature, Signature::default());
        assert_eq!(
            ensure_registered_ix_tag(&rpc),
            zolana_user_registry_interface::instruction::discriminator::UPDATE_KEYS
        );
    }
}
