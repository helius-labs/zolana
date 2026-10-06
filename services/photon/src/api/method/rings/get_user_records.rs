use sea_orm::DatabaseConnection;
use solana_account::Account;
use solana_pubkey::Pubkey;
use zolana_indexer_api::{
    Base64String, GetUserRecordsRequest, GetUserRecordsResponse, Hash, SerializablePubkey,
    UserRecord, MAX_USER_RECORD_OWNERS,
};
use zolana_user_registry_interface::{
    user_record_pda, user_registry_program_id, UserRecord as UserRecordAccount,
};

use crate::api::error::PhotonApiError;
use crate::common::indexer_context::extract as extract_context;
use crate::rpc::RpcClient;

/// Photon does not index the user registry: the records come from the chain,
/// read no earlier than the indexer's context slot so a `null` is never staler
/// than the context it is reported with.
pub async fn get_user_records(
    conn: &DatabaseConnection,
    rpc_client: &RpcClient,
    request: GetUserRecordsRequest,
) -> Result<GetUserRecordsResponse, PhotonApiError> {
    validate_owners(&request.owners)?;

    let context = extract_context(conn).await?;
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
        .get_multiple_accounts_from_slot(&addresses, context.slot)
        .await
        .map_err(|error| {
            PhotonApiError::UnexpectedError(format!("Failed to fetch user records: {error}"))
        })?;
    // The node enforces the floor; one that ignores it must not get to report
    // a stale absence as current.
    if fetched.slot < context.slot {
        return Err(PhotonApiError::UnexpectedError(format!(
            "User records read at slot {} behind the indexer at slot {}",
            fetched.slot, context.slot
        )));
    }

    let records = user_records(&request.owners, &derived, fetched.accounts)?;
    Ok(GetUserRecordsResponse { context, records })
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
    use crate::dao::generated::blocks;
    use crate::migration::RingsMigrator;
    use crate::rpc::fake_node::serve_in_order;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use sea_orm::{Database, EntityTrait, Set};
    use sea_orm_migration::MigratorTrait;
    use serde_json::{json, Value};
    use zolana_indexer_api::Context;

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

    /// A `getMultipleAccounts` answer from a bank at `slot`.
    fn accounts_answer(slot: u64, accounts: &[Option<Account>]) -> String {
        let value = accounts
            .iter()
            .map(|account| account.as_ref().map_or(Value::Null, encoded_account))
            .collect::<Vec<_>>();
        json!({ "jsonrpc": "2.0", "id": 1, "result": { "context": { "slot": slot }, "value": value } })
            .to_string()
    }

    async fn indexer_at(slot: i64, block_time: i64) -> sea_orm::DatabaseConnection {
        let db = empty_indexer().await;
        blocks::Entity::insert(blocks::ActiveModel {
            slot: Set(slot),
            parent_slot: Set(0),
            parent_blockhash: Set(vec![0; 32]),
            blockhash: Set(vec![1; 32]),
            block_height: Set(1),
            block_time: Set(block_time),
        })
        .exec(&db)
        .await
        .unwrap();
        db
    }

    async fn empty_indexer() -> sea_orm::DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();
        db
    }

    fn unreachable_node() -> RpcClient {
        RpcClient::new("http://127.0.0.1:1".to_string())
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
    async fn reads_every_owner_in_request_order_no_earlier_than_the_indexer() {
        let owners = vec![owner(1), owner(2), owner(3)];
        let p256_owner = registered(&owners[0], Some([7; 33]));
        let solana_owner = registered(&owners[2], None);
        let (url, node) = serve_in_order(&[(
            "200 OK",
            &accounts_answer(
                77,
                &[
                    Some(record_account(&p256_owner)),
                    None,
                    Some(record_account(&solana_owner)),
                ],
            ),
        )]);

        let response = get_user_records(
            &indexer_at(70, 1_700_000_000).await,
            &RpcClient::new(url),
            GetUserRecordsRequest {
                owners: owners.clone(),
            },
        )
        .await
        .unwrap();
        let requests = node.join().unwrap();

        // The indexer's context, not the slot the node answered at.
        assert_eq!(
            response.context,
            Context {
                block_time: 1_700_000_000,
                slot: 70
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
        // One read of the canonical PDAs in request order, floored at the
        // context slot.
        assert_eq!(requests.len(), 1);
        let request: Value = serde_json::from_str(&requests[0]).unwrap();
        assert_eq!(request["method"], "getMultipleAccounts");
        let expected_addresses = owners
            .iter()
            .map(|owner| Value::from(user_record_pda(&owner.0).0.to_string()))
            .collect::<Vec<_>>();
        assert_eq!(request["params"][0], Value::Array(expected_addresses));
        assert_eq!(request["params"][1]["minContextSlot"], 70);
    }

    #[tokio::test]
    async fn a_node_answering_behind_the_indexer_is_refused() {
        let (url, node) = serve_in_order(&[("200 OK", &accounts_answer(69, &[None]))]);

        let error = get_user_records(
            &indexer_at(70, 1).await,
            &RpcClient::new(url),
            GetUserRecordsRequest {
                owners: vec![owner(1)],
            },
        )
        .await
        .unwrap_err();
        node.join().unwrap();

        assert!(matches!(
            error,
            PhotonApiError::UnexpectedError(message) if message.contains("slot 69 behind the indexer at slot 70")
        ));
    }

    #[tokio::test]
    async fn an_indexer_without_a_block_answers_before_any_rpc_call() {
        let error = get_user_records(
            &empty_indexer().await,
            &unreachable_node(),
            GetUserRecordsRequest {
                owners: vec![owner(1)],
            },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, PhotonApiError::RecordNotFound(_)));
    }

    #[tokio::test]
    async fn validation_happens_before_any_database_or_rpc_call() {
        let error = get_user_records(
            &empty_indexer().await,
            &unreachable_node(),
            GetUserRecordsRequest { owners: Vec::new() },
        )
        .await
        .unwrap_err();
        assert!(matches!(error, PhotonApiError::ValidationError(_)));
    }
}
