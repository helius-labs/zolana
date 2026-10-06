use solana_account::Account;
use solana_pubkey::Pubkey;
use solana_transaction_status_client_types::TransactionDetails;
use zolana_indexer_api::{
    Base64String, Context, GetUserRecordsRequest, GetUserRecordsResponse, Hash, SerializablePubkey,
    UserRecord, MAX_USER_RECORD_OWNERS,
};
use zolana_user_registry_interface::{
    user_record_pda, user_registry_program_id, UserRecord as UserRecordAccount,
};

use crate::api::error::PhotonApiError;
use crate::rpc::RpcClient;

/// Reads the records straight from the chain: Photon does not index the user
/// registry, and one `getMultipleAccounts` call answers every owner at a single
/// slot. `context` is that slot, not the indexer's.
pub async fn get_user_records(
    rpc_client: &RpcClient,
    request: GetUserRecordsRequest,
) -> Result<GetUserRecordsResponse, PhotonApiError> {
    validate_owners(&request.owners)?;

    let derived = request
        .owners
        .iter()
        .map(|owner| user_record_pda(&owner.0))
        .collect::<Vec<_>>();
    let addresses = derived
        .iter()
        .map(|(address, _)| *address)
        .collect::<Vec<_>>();
    let fetched = rpc_client
        .get_multiple_accounts_at_slot(&addresses)
        .await
        .map_err(|error| {
            PhotonApiError::UnexpectedError(format!("Failed to fetch user records: {error}"))
        })?;
    let block = rpc_client
        .get_block(fetched.slot, TransactionDetails::None)
        .await
        .map_err(|error| {
            PhotonApiError::UnexpectedError(format!(
                "Failed to fetch block {}: {error}",
                fetched.slot
            ))
        })?;
    let block_time = block.block_time.ok_or_else(|| {
        PhotonApiError::UnexpectedError(format!("Block {} has no block time", fetched.slot))
    })?;

    let records = user_records(&request.owners, &derived, fetched.accounts)?;
    Ok(GetUserRecordsResponse {
        context: Context {
            block_time,
            slot: fetched.slot,
        },
        records,
    })
}

fn validate_owners(owners: &[SerializablePubkey]) -> Result<(), PhotonApiError> {
    if owners.is_empty() {
        return Err(PhotonApiError::ValidationError(
            "At least one owner must be provided".to_string(),
        ));
    }
    if owners.len() > MAX_USER_RECORD_OWNERS {
        return Err(PhotonApiError::ValidationError(format!(
            "Too many owners requested {}. Maximum allowed: {}",
            owners.len(),
            MAX_USER_RECORD_OWNERS
        )));
    }
    Ok(())
}

fn user_records(
    owners: &[SerializablePubkey],
    derived: &[(Pubkey, u8)],
    accounts: Vec<Option<Account>>,
) -> Result<Vec<Option<UserRecord>>, PhotonApiError> {
    if accounts.len() != owners.len() {
        return Err(PhotonApiError::UnexpectedError(format!(
            "RPC returned {} accounts for {} user records",
            accounts.len(),
            owners.len()
        )));
    }
    owners
        .iter()
        .zip(derived)
        .zip(accounts)
        .map(|((owner, (address, bump)), account)| {
            account
                .map(|account| user_record(owner, *address, *bump, &account))
                .transpose()
                .map(Option::flatten)
        })
        .collect()
}

/// An account at the PDA the registry does not own is a rent donation it has
/// not claimed, so the owner is unregistered. A registry-owned account that
/// does not hold this owner's canonical record is reported rather than hidden
/// as "unregistered": a wallet acting on a false `null` would re-register or
/// send a payment into the open.
fn user_record(
    owner: &SerializablePubkey,
    address: Pubkey,
    bump: u8,
    account: &Account,
) -> Result<Option<UserRecord>, PhotonApiError> {
    if account.owner != user_registry_program_id() {
        return Ok(None);
    }
    let record = UserRecordAccount::try_from_account_data(&account.data).map_err(|error| {
        PhotonApiError::UnexpectedError(format!("User record {address} is malformed: {error}"))
    })?;
    if record.owner != owner.0 {
        return Err(PhotonApiError::UnexpectedError(format!(
            "User record {address} stores owner {} instead of {owner}",
            record.owner
        )));
    }
    if record.bump != bump {
        return Err(PhotonApiError::UnexpectedError(format!(
            "User record {address} stores bump {} instead of the canonical {bump}",
            record.bump
        )));
    }
    Ok(Some(UserRecord {
        owner: *owner,
        owner_p256: record.owner_p256.map(|key| Base64String(key.to_vec())),
        nullifier_pubkey: Hash(record.nullifier_pubkey),
        viewing_pubkey: Base64String(record.viewing_pubkey.to_vec()),
        merging_enabled: record.merging_enabled,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::fake_node::serve_in_order;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use serde_json::{json, Value};

    fn owner(value: u8) -> SerializablePubkey {
        SerializablePubkey::from([value; 32])
    }

    fn registered(owner: &SerializablePubkey, owner_p256: Option<[u8; 33]>) -> UserRecordAccount {
        UserRecordAccount {
            owner: owner.0,
            bump: user_record_pda(&owner.0).1,
            owner_p256,
            nullifier_pubkey: [3; 32],
            viewing_pubkey: [4; 33],
            merging_enabled: true,
        }
    }

    /// The program allocates every record at the fixed size, so a record
    /// without a P256 owner carries zero padding after its borsh encoding.
    fn record_data(record: &UserRecordAccount) -> Vec<u8> {
        let mut data = vec![UserRecordAccount::DISCRIMINATOR];
        data.extend(borsh::to_vec(record).unwrap());
        data.resize(UserRecordAccount::SIZE, 0);
        data
    }

    fn record_account(record: &UserRecordAccount) -> Account {
        Account {
            lamports: 1,
            data: record_data(record),
            owner: user_registry_program_id(),
            executable: false,
            rent_epoch: 0,
        }
    }

    fn encoded_account(account: &Account) -> Value {
        json!({
            "lamports": account.lamports,
            "data": [BASE64.encode(&account.data), "base64"],
            "owner": account.owner.to_string(),
            "executable": account.executable,
            "rentEpoch": account.rent_epoch,
        })
    }

    #[test]
    fn rejects_an_empty_and_an_oversized_owner_list() {
        assert!(matches!(
            validate_owners(&[]),
            Err(PhotonApiError::ValidationError(message)) if message.contains("At least one owner")
        ));
        let too_many = vec![owner(1); MAX_USER_RECORD_OWNERS + 1];
        assert!(matches!(
            validate_owners(&too_many),
            Err(PhotonApiError::ValidationError(message)) if message.contains("Maximum allowed: 100")
        ));
        assert!(validate_owners(&too_many[..MAX_USER_RECORD_OWNERS]).is_ok());
    }

    #[test]
    fn a_donation_at_the_pda_is_not_a_record() {
        let owner = owner(1);
        let (address, bump) = user_record_pda(&owner.0);
        let donated = Account {
            lamports: 1_000,
            data: Vec::new(),
            owner: Pubkey::default(),
            executable: false,
            rent_epoch: 0,
        };
        assert_eq!(user_record(&owner, address, bump, &donated).unwrap(), None);
    }

    #[test]
    fn a_registry_account_that_is_not_this_owners_record_is_an_error() {
        let owner = owner(1);
        let (address, bump) = user_record_pda(&owner.0);

        let mut foreign = registered(&owner, None);
        foreign.owner = Pubkey::from([2; 32]);
        assert!(matches!(
            user_record(&owner, address, bump, &record_account(&foreign)),
            Err(PhotonApiError::UnexpectedError(message)) if message.contains("stores owner")
        ));

        let mut wrong_bump = registered(&owner, None);
        wrong_bump.bump = bump.wrapping_add(1);
        assert!(matches!(
            user_record(&owner, address, bump, &record_account(&wrong_bump)),
            Err(PhotonApiError::UnexpectedError(message)) if message.contains("stores bump")
        ));

        let mut truncated = record_account(&registered(&owner, None));
        truncated.data.pop();
        assert!(matches!(
            user_record(&owner, address, bump, &truncated),
            Err(PhotonApiError::UnexpectedError(message)) if message.contains("malformed")
        ));
    }

    #[test]
    fn a_short_rpc_answer_is_an_error_rather_than_a_misaligned_list() {
        let owners = [owner(1), owner(2)];
        let derived = owners
            .iter()
            .map(|owner| user_record_pda(&owner.0))
            .collect::<Vec<_>>();
        assert!(matches!(
            user_records(&owners, &derived, vec![None]),
            Err(PhotonApiError::UnexpectedError(message)) if message.contains("1 accounts for 2")
        ));
    }

    #[tokio::test]
    async fn reads_every_owner_at_one_slot_in_request_order() {
        let owners = vec![owner(1), owner(2), owner(3)];
        let p256_owner = registered(&owners[0], Some([7; 33]));
        let solana_owner = registered(&owners[2], None);
        let accounts = json!({
            "context": { "slot": 77 },
            "value": [
                encoded_account(&record_account(&p256_owner)),
                null,
                encoded_account(&record_account(&solana_owner)),
            ],
        });
        let block = json!({
            "blockhash": "11111111111111111111111111111111",
            "previousBlockhash": "11111111111111111111111111111111",
            "parentSlot": 76,
            "blockTime": 1_700_000_000,
            "blockHeight": 70,
        });
        let (url, node) = serve_in_order(&[
            (
                "200 OK",
                &json!({ "jsonrpc": "2.0", "id": 1, "result": accounts }).to_string(),
            ),
            (
                "200 OK",
                &json!({ "jsonrpc": "2.0", "id": 2, "result": block }).to_string(),
            ),
        ]);

        let response = get_user_records(
            &RpcClient::new(url),
            GetUserRecordsRequest {
                owners: owners.clone(),
            },
        )
        .await
        .unwrap();
        let requests = node.join().unwrap();

        assert_eq!(
            response.context,
            Context {
                block_time: 1_700_000_000,
                slot: 77
            }
        );
        assert_eq!(
            response.records,
            vec![
                Some(UserRecord {
                    owner: owners[0],
                    owner_p256: Some(Base64String(vec![7; 33])),
                    nullifier_pubkey: Hash([3; 32]),
                    viewing_pubkey: Base64String(vec![4; 33]),
                    merging_enabled: true,
                }),
                None,
                Some(UserRecord {
                    owner: owners[2],
                    owner_p256: None,
                    nullifier_pubkey: Hash([3; 32]),
                    viewing_pubkey: Base64String(vec![4; 33]),
                    merging_enabled: true,
                }),
            ]
        );

        // One account read for the canonical PDAs, then the block of the slot
        // that read reported.
        let accounts_request: Value = serde_json::from_str(&requests[0]).unwrap();
        assert_eq!(accounts_request["method"], "getMultipleAccounts");
        let expected_addresses = owners
            .iter()
            .map(|owner| Value::from(user_record_pda(&owner.0).0.to_string()))
            .collect::<Vec<_>>();
        assert_eq!(
            accounts_request["params"][0],
            Value::Array(expected_addresses)
        );
        let block_request: Value = serde_json::from_str(&requests[1]).unwrap();
        assert_eq!(block_request["method"], "getBlock");
        assert_eq!(block_request["params"][0], 77);
        assert_eq!(block_request["params"][1]["transactionDetails"], "none");
    }

    #[tokio::test]
    async fn validation_happens_before_any_rpc_call() {
        let error = get_user_records(
            &RpcClient::new("http://127.0.0.1:1".to_string()),
            GetUserRecordsRequest { owners: Vec::new() },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, PhotonApiError::ValidationError(_)));
    }
}
