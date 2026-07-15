use solana_address::Address;
use solana_instruction::Instruction;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use solana_transaction::Transaction as SolanaTransaction;
use zolana_keypair::{
    viewing_key::ViewTag, P256Pubkey, PublicKey, ShieldedAddress, ShieldedKeypair, SignatureType,
};
use zolana_user_registry_interface::{
    instruction::{register, update_keys, RegisterData, UpdateKeysData},
    user_record_pda, user_registry_program_id, UserRecord,
};

use crate::{
    actions::ResolvedAddress,
    error::ClientError,
    rpc::{AsyncRpc, Rpc, SignableTransaction},
};

/// Derive the on-chain registry record fields from a shielded keypair: the
/// P256 owner key (only for P256-owned wallets), nullifier pubkey, and viewing
/// pubkey. Returns the exact `RegisterData` the register/update instructions take.
fn register_fields(address: &ShieldedAddress) -> Result<RegisterData, ClientError> {
    let owner_p256 = match address.signing_pubkey.signature_type()? {
        SignatureType::P256 => Some(*address.signing_pubkey.as_p256()?.as_bytes()),
        SignatureType::Ed25519 => None,
    };
    Ok(RegisterData {
        owner_p256,
        nullifier_pubkey: address.nullifier_pubkey,
        viewing_pubkey: *address.viewing_pubkey.as_bytes(),
    })
}

/// Publish `keypair`'s shielded keys to the on-chain user-registry directory
/// under `funding`'s pubkey, so senders who know only that Solana address route
/// transfers to the shielded path (rather than falling back to a public
/// withdrawal). Registration is optional for receiving a confidential transfer
/// to a known shielded address; it is the pubkey-addressability directory.
///
/// Idempotent: registers if no record exists, updates the record on a key
/// change, and returns `Ok(None)` if the record already matches (no transaction
/// sent). The record lives at `user_record_pda(&funding.pubkey()).0`.
///
/// `funding` must sign — the registry keys the record under its pubkey and the
/// program requires the owner's signature, so only the record's owner can
/// publish or update it.
pub fn ensure_registered<R: Rpc>(
    rpc: &R,
    funding: &Keypair,
    keypair: &ShieldedKeypair,
) -> Result<Option<Signature>, ClientError> {
    let owner = funding.pubkey();
    let data = register_fields(&keypair.shielded_address()?)?;
    let (user_record, _bump) = user_record_pda(&owner);
    let owner_address = Address::new_from_array(owner.to_bytes());

    if let Some(record) = fetch_user_record_optional_checked(rpc, owner)? {
        if record.owner_p256 == data.owner_p256
            && record.nullifier_pubkey == data.nullifier_pubkey
            && record.viewing_pubkey == data.viewing_pubkey
        {
            return Ok(None);
        }
        let ix = update_keys(
            user_record,
            owner,
            UpdateKeysData {
                owner_p256: data.owner_p256,
                nullifier_pubkey: data.nullifier_pubkey,
                viewing_pubkey: data.viewing_pubkey,
            },
        );
        return Ok(Some(rpc.create_and_send_transaction(
            &[ix],
            owner_address,
            &[funding],
        )?));
    }

    let ix = register(user_record, owner, data);
    Ok(Some(rpc.create_and_send_transaction(
        &[ix],
        owner_address,
        &[funding],
    )?))
}

/// Build an unsigned register/update transaction for an external Solana signer.
///
/// Returns `Ok(None)` when the on-chain record already matches `address`.
pub async fn build_registration_transaction<R: AsyncRpc>(
    rpc: &R,
    owner: Pubkey,
    address: &ShieldedAddress,
) -> Result<Option<SignableTransaction>, ClientError> {
    let data = register_fields(address)?;
    let existing = fetch_user_record_optional_checked_async(rpc, owner).await?;
    let Some(instruction) = registration_instruction(owner, data, existing) else {
        return Ok(None);
    };
    let (blockhash, last_valid_block_height) = rpc.get_latest_blockhash().await?;
    Ok(Some(SignableTransaction {
        transaction: unsigned_registration_transaction(owner, instruction, blockhash),
        last_valid_block_height,
    }))
}

/// Blocking adapter for building an unsigned register/update transaction.
pub fn build_registration_transaction_sync<R: Rpc>(
    rpc: &R,
    owner: Pubkey,
    address: &ShieldedAddress,
) -> Result<Option<SignableTransaction>, ClientError> {
    let data = register_fields(address)?;
    let existing = fetch_user_record_optional_checked(rpc, owner)?;
    let Some(instruction) = registration_instruction(owner, data, existing) else {
        return Ok(None);
    };
    let (blockhash, last_valid_block_height) = rpc.get_latest_blockhash()?;
    Ok(Some(SignableTransaction {
        transaction: unsigned_registration_transaction(owner, instruction, blockhash),
        last_valid_block_height,
    }))
}

fn registration_instruction(
    owner: Pubkey,
    data: RegisterData,
    existing: Option<UserRecord>,
) -> Option<Instruction> {
    let (user_record, _bump) = user_record_pda(&owner);
    match existing {
        Some(record)
            if record.owner_p256 == data.owner_p256
                && record.nullifier_pubkey == data.nullifier_pubkey
                && record.viewing_pubkey == data.viewing_pubkey =>
        {
            None
        }
        Some(_) => Some(update_keys(
            user_record,
            owner,
            UpdateKeysData {
                owner_p256: data.owner_p256,
                nullifier_pubkey: data.nullifier_pubkey,
                viewing_pubkey: data.viewing_pubkey,
            },
        )),
        None => Some(register(user_record, owner, data)),
    }
}

fn unsigned_registration_transaction(
    owner: Pubkey,
    instruction: Instruction,
    blockhash: solana_hash::Hash,
) -> SolanaTransaction {
    let mut message = Message::new(&[instruction], Some(&owner));
    message.recent_blockhash = blockhash;
    SolanaTransaction::new_unsigned(message)
}

pub fn fetch_user_record_checked<R: Rpc>(
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

pub fn fetch_user_record_optional_checked<R: Rpc>(
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

pub async fn fetch_user_record_optional_checked_async<R: AsyncRpc>(
    rpc: &R,
    owner: Pubkey,
) -> Result<Option<UserRecord>, ClientError> {
    let (record_pda, bump) = user_record_pda(&owner);
    let Some(account) = rpc
        .get_account(Address::new_from_array(record_pda.to_bytes()))
        .await?
    else {
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

pub fn validate_registered_keypair<R: Rpc>(
    rpc: &R,
    owner: Pubkey,
    keypair: &ShieldedKeypair,
) -> Result<(), ClientError> {
    let record = fetch_user_record_checked(rpc, owner)?;
    let expected_owner_p256 = match keypair.signing_pubkey().signature_type()? {
        SignatureType::P256 => Some(*keypair.signing_pubkey().as_p256()?.as_bytes()),
        SignatureType::Ed25519 => None,
    };
    let expected_nullifier = keypair.nullifier_key.pubkey()?;
    let expected_viewing = *keypair.viewing_pubkey().as_bytes();
    if record.owner_p256 != expected_owner_p256
        || record.nullifier_pubkey != expected_nullifier
        || record.viewing_pubkey != expected_viewing
    {
        return Err(ClientError::AddressResolution(format!(
            "user registry record for {owner} does not match the local wallet"
        )));
    }
    Ok(())
}

pub fn resolve_registered_address<R: Rpc>(
    rpc: &R,
    owner: Pubkey,
) -> Result<ResolvedAddress, ClientError> {
    let record = fetch_user_record_checked(rpc, owner)
        .map_err(|err| ClientError::AddressResolution(err.to_string()))?;
    resolved_address_from_record(owner, &record)
        .map_err(|err| ClientError::AddressResolution(err.to_string()))
}

pub fn try_resolve_registered_address<R: Rpc>(
    rpc: &R,
    owner: Pubkey,
) -> Result<Option<ResolvedAddress>, ClientError> {
    let Some(record) = fetch_user_record_optional_checked(rpc, owner)? else {
        return Ok(None);
    };
    Ok(Some(resolved_address_from_record(owner, &record).map_err(
        |err| ClientError::AddressResolution(err.to_string()),
    )?))
}

pub async fn try_resolve_registered_address_async<R: AsyncRpc>(
    rpc: &R,
    owner: Pubkey,
) -> Result<Option<ResolvedAddress>, ClientError> {
    let Some(record) = fetch_user_record_optional_checked_async(rpc, owner).await? else {
        return Ok(None);
    };
    Ok(Some(resolved_address_from_record(owner, &record).map_err(
        |err| ClientError::AddressResolution(err.to_string()),
    )?))
}

/// Returns whether `owner` has an on-chain user-registry record.
pub async fn is_wallet_registered<R: AsyncRpc>(
    rpc: &R,
    owner: Pubkey,
) -> Result<bool, ClientError> {
    Ok(fetch_user_record_optional_checked_async(rpc, owner)
        .await?
        .is_some())
}

/// Blocking adapter for CLI and unit-test flows.
pub fn is_wallet_registered_sync<R: Rpc>(rpc: &R, owner: Pubkey) -> Result<bool, ClientError> {
    Ok(fetch_user_record_optional_checked(rpc, owner)?.is_some())
}

/// Confidential output view tag for a transfer recipient.
///
/// Registered owners use their shielded signing pubkey tag. Unregistered owners
/// (public withdrawals) use the zero tag.
pub async fn recipient_confidential_view_tag<R: AsyncRpc>(
    rpc: &R,
    recipient: Pubkey,
) -> Result<ViewTag, ClientError> {
    let Some(record) = fetch_user_record_optional_checked_async(rpc, recipient).await? else {
        return Ok([0u8; 32]);
    };
    signing_pubkey_from_record(recipient, &record)?
        .confidential_view_tag()
        .map_err(|err| ClientError::AddressResolution(err.to_string()))
}

/// Blocking adapter for [`recipient_confidential_view_tag`].
pub fn recipient_confidential_view_tag_sync<R: Rpc>(
    rpc: &R,
    recipient: Pubkey,
) -> Result<ViewTag, ClientError> {
    let Some(record) = fetch_user_record_optional_checked(rpc, recipient)? else {
        return Ok([0u8; 32]);
    };
    signing_pubkey_from_record(recipient, &record)?
        .confidential_view_tag()
        .map_err(|err| ClientError::AddressResolution(err.to_string()))
}

fn signing_pubkey_from_record(
    owner: Pubkey,
    record: &UserRecord,
) -> Result<PublicKey, ClientError> {
    Ok(match record.owner_p256 {
        Some(owner_p256) => PublicKey::from_p256(
            &P256Pubkey::from_bytes(owner_p256)
                .map_err(|err| ClientError::AddressResolution(err.to_string()))?,
        ),
        None => PublicKey::from_ed25519(&owner.to_bytes()),
    })
}

pub fn resolved_address_from_record(
    owner: Pubkey,
    record: &UserRecord,
) -> Result<ResolvedAddress, ClientError> {
    let signing_pubkey = signing_pubkey_from_record(owner, record)?;
    let viewing_pubkey = P256Pubkey::from_bytes(record.sender_viewing_pubkey())?;
    Ok(ResolvedAddress {
        owner,
        address: ShieldedAddress {
            signing_pubkey,
            nullifier_pubkey: record.nullifier_pubkey,
            viewing_pubkey,
        },
        view_tag: viewing_pubkey.x(),
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

        fn get_latest_blockhash(&self) -> Result<(solana_hash::Hash, u64), ClientError> {
            Ok((solana_hash::Hash::new_from_array([9u8; 32]), 1))
        }
    }

    #[async_trait::async_trait]
    impl AsyncRpc for MockRpc {
        async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            Rpc::get_account(self, address)
        }

        async fn get_latest_blockhash(&self) -> Result<(solana_hash::Hash, u64), ClientError> {
            Rpc::get_latest_blockhash(self)
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
    fn registration_builder_returns_unsigned_transaction_for_external_signer() {
        let owner = Pubkey::new_unique();
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
        let transaction = build_registration_transaction_sync(
            &MockRpc::default(),
            owner,
            &keypair.shielded_address().expect("shielded address"),
        )
        .expect("build registration")
        .expect("registration required");

        assert_eq!(transaction.transaction.message.account_keys[0], owner);
        assert_eq!(
            transaction.transaction.message.recent_blockhash,
            solana_hash::Hash::new_from_array([9u8; 32])
        );
        assert_eq!(
            transaction.transaction.signatures,
            vec![Signature::default()]
        );
        assert_eq!(transaction.last_valid_block_height, 1);
    }

    #[tokio::test]
    async fn async_registration_builder_returns_sendable_unsigned_transaction() {
        let owner = Pubkey::new_unique();
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
        let rpc = MockRpc::default();
        let address = keypair.shielded_address().expect("shielded address");
        let future = build_registration_transaction(&rpc, owner, &address);
        fn assert_send<T: Send>(value: T) -> T {
            value
        }
        let transaction = assert_send(future)
            .await
            .expect("build registration")
            .expect("registration required");

        assert_eq!(transaction.transaction.message.account_keys[0], owner);
        assert_eq!(
            transaction.transaction.signatures,
            vec![Signature::default()]
        );
        assert_eq!(transaction.last_valid_block_height, 1);
    }

    #[test]
    fn is_wallet_registered_sync_reports_registered_owner() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&user_record(owner, bump)),
            )),
        };

        assert!(is_wallet_registered_sync(&rpc, owner).expect("registered"));
    }

    #[test]
    fn is_wallet_registered_sync_reports_unregistered_owner() {
        let owner = Pubkey::new_unique();
        let rpc = MockRpc { account: None };

        assert!(!is_wallet_registered_sync(&rpc, owner).expect("unregistered"));
    }

    #[test]
    fn recipient_confidential_view_tag_sync_uses_registered_signing_pubkey() {
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

        let tag = recipient_confidential_view_tag_sync(&rpc, owner).expect("tag");
        assert_eq!(
            tag,
            keypair
                .signing_pubkey()
                .confidential_view_tag()
                .expect("confidential tag")
        );
    }

    #[test]
    fn recipient_confidential_view_tag_sync_uses_zero_tag_for_unregistered_owner() {
        let owner = Pubkey::new_unique();
        let rpc = MockRpc { account: None };

        let tag = recipient_confidential_view_tag_sync(&rpc, owner).expect("tag");
        assert_eq!(tag, [0u8; 32]);
    }

    #[tokio::test]
    async fn is_wallet_registered_reports_registered_owner() {
        let owner = Pubkey::new_unique();
        let (pda, bump) = user_record_pda(&owner);
        let rpc = MockRpc {
            account: Some((
                Address::new_from_array(pda.to_bytes()),
                account_for(&user_record(owner, bump)),
            )),
        };

        assert!(is_wallet_registered(&rpc, owner).await.expect("registered"));
    }

    #[tokio::test]
    async fn is_wallet_registered_reports_unregistered_owner() {
        let owner = Pubkey::new_unique();
        let rpc = MockRpc { account: None };

        assert!(!is_wallet_registered(&rpc, owner)
            .await
            .expect("unregistered"));
    }

    #[test]
    fn resolved_address_from_record_maps_registered_keys() {
        let owner = Pubkey::new_unique();
        let (_, bump) = user_record_pda(&owner);
        let keypair = ShieldedKeypair::new().expect("shielded keypair");
        let record = registered_record(owner, bump, &keypair);

        let resolved = resolved_address_from_record(owner, &record).expect("resolved address");

        assert_eq!(resolved.owner, owner);
        assert_eq!(resolved.address.signing_pubkey, keypair.signing_pubkey());
        assert_eq!(
            resolved.address.nullifier_pubkey,
            keypair.nullifier_key.pubkey().unwrap()
        );
        assert_eq!(
            resolved.address.viewing_pubkey.as_bytes(),
            keypair.viewing_pubkey().as_bytes()
        );
        assert_eq!(resolved.view_tag, keypair.recipient_bootstrap_view_tag());
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

        let resolved = resolve_registered_address(&rpc, owner).expect("resolved address");

        assert_eq!(resolved.owner, owner);
        assert_eq!(resolved.address.signing_pubkey, keypair.signing_pubkey());
        assert_eq!(resolved.view_tag, keypair.recipient_bootstrap_view_tag());
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
    /// transaction, so `ensure_registered`'s three branches can be asserted
    /// without a validator.
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
    fn ensure_registered_updates_when_keys_changed() {
        let funding = Keypair::new();
        let keypair = ShieldedKeypair::new().unwrap();
        let owner = funding.pubkey();
        let (_pda, bump) = user_record_pda(&owner);
        // Record exists but with stale keys (a different keypair).
        let stale = registered_record(owner, bump, &ShieldedKeypair::new().unwrap());
        let rpc = SendMockRpc {
            account: Some(account_at(owner, &stale)),
            ..Default::default()
        };
        let sig = ensure_registered(&rpc, &funding, &keypair).expect("ensure_registered");
        assert!(
            sig.is_some(),
            "key change should send an update transaction"
        );
        assert_eq!(
            ensure_registered_ix_tag(&rpc),
            zolana_user_registry_interface::instruction::discriminator::UPDATE_KEYS
        );
    }
}
