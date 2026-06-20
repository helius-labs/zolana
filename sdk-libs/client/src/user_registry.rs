use solana_address::Address;
use solana_pubkey::Pubkey;
use zolana_interface::user_registry::{user_record_pda, UserRecord};
use zolana_keypair::{P256Pubkey, PublicKey, ShieldedAddress, ShieldedKeypair};

use crate::{actions::ResolvedAddress, error::ClientError, rpc::Rpc};

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

fn parse_user_record_account(
    owner: Pubkey,
    record_pda: Pubkey,
    bump: u8,
    account: &solana_account::Account,
) -> Result<UserRecord, ClientError> {
    let record = UserRecord::try_from_account_checked(account).map_err(|err| {
        ClientError::Rpc(format!("invalid user registry record {record_pda}: {err}"))
    })?;
    if record.owner != owner.to_bytes() {
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
    let expected_owner_p256 = Some(*keypair.signing_pubkey().as_p256()?.as_bytes());
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

pub fn resolved_address_from_record(
    owner: Pubkey,
    record: &UserRecord,
) -> Result<ResolvedAddress, ClientError> {
    let signing_pubkey = match record.owner_p256 {
        Some(owner_p256) => PublicKey::from_p256(&P256Pubkey::from_bytes(owner_p256)?),
        None => PublicKey::from_ed25519(&owner.to_bytes()),
    };
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
    use zolana_interface::user_registry::{user_registry_program_id, SyncDelegateEntry};
    use zolana_keypair::ShieldedKeypair;

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
            owner: owner.to_bytes(),
            bump,
            owner_p256: Some([2u8; 33]),
            nullifier_pubkey: [3u8; 32],
            viewing_pubkey: [4u8; 33],
            sync_delegate: None,
            entries: Vec::new(),
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
            owner: owner.to_bytes(),
            bump,
            owner_p256: Some(*keypair.signing_pubkey().as_p256().unwrap().as_bytes()),
            nullifier_pubkey: keypair.nullifier_key.pubkey().unwrap(),
            viewing_pubkey: *keypair.viewing_pubkey().as_bytes(),
            sync_delegate: None,
            entries: Vec::new(),
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
    fn try_from_account_checked_rejects_wrong_discriminator() {
        let mut account = Account {
            lamports: 1,
            data: vec![0],
            owner: user_registry_program_id(),
            executable: false,
            rent_epoch: 0,
        };
        account.data.extend_from_slice(
            &to_vec(&UserRecord {
                owner: [1u8; 32],
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
            })
            .expect("serialize user record"),
        );

        let err = UserRecord::try_from_account_checked(&account).expect_err("bad discriminator");

        assert!(err
            .to_string()
            .contains("missing user record discriminator"));
    }
}
