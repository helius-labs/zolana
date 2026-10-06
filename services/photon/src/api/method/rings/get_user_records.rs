use std::iter;

use solana_account::Account;
use solana_clock::Clock;
use solana_pubkey::Pubkey;
use zolana_indexer_api::{
    Base64String, Context, GetUserRecordsRequest, GetUserRecordsResponse, Hash, SerializablePubkey,
    UserRecord, MAX_USER_RECORD_OWNERS,
};
use zolana_user_registry_interface::{
    user_record_pda, user_registry_program_id, UserRecord as UserRecordAccount,
};

use crate::api::error::PhotonApiError;
use crate::rpc::RpcClient;

/// `getMultipleAccounts` answers at most 100 keys, and the Clock sysvar takes
/// one of them.
const OWNERS_PER_READ: usize = 99;
/// A request too wide for one call is read again until every call answers at
/// the same slot.
const SAME_SLOT_ATTEMPTS: usize = 3;

/// Reads the records straight from the chain: Photon does not index the user
/// registry. The Clock sysvar rides along in the same `getMultipleAccounts`
/// call, so `context` is the slot the accounts were read at and that bank's
/// timestamp, with no second call that could miss a block still being built.
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
    let read = read_at_one_slot(rpc_client, &addresses).await?;
    let records = user_records(&request.owners, &derived, read.accounts)?;
    Ok(GetUserRecordsResponse {
        context: Context {
            block_time: read.unix_timestamp,
            slot: read.slot,
        },
        records,
    })
}

struct RegistryRead {
    slot: u64,
    unix_timestamp: i64,
    accounts: Vec<Option<Account>>,
}

async fn read_at_one_slot(
    rpc_client: &RpcClient,
    addresses: &[Pubkey],
) -> Result<RegistryRead, PhotonApiError> {
    for _ in 0..SAME_SLOT_ATTEMPTS {
        if let Some(read) = read_once(rpc_client, addresses).await? {
            return Ok(read);
        }
    }
    Err(PhotonApiError::UnexpectedError(format!(
        "Reading {} user records crossed a slot boundary {SAME_SLOT_ATTEMPTS} times",
        addresses.len()
    )))
}

/// `None` when the calls did not all answer at one slot.
async fn read_once(
    rpc_client: &RpcClient,
    addresses: &[Pubkey],
) -> Result<Option<RegistryRead>, PhotonApiError> {
    let mut read: Option<RegistryRead> = None;
    for chunk in addresses.chunks(OWNERS_PER_READ) {
        let keys = iter::once(solana_clock::sysvar::ID)
            .chain(chunk.iter().copied())
            .collect::<Vec<_>>();
        let fetched = rpc_client
            .get_multiple_accounts_at_slot(&keys)
            .await
            .map_err(|error| {
                PhotonApiError::UnexpectedError(format!("Failed to fetch user records: {error}"))
            })?;
        if fetched.accounts.len() != keys.len() {
            return Err(PhotonApiError::UnexpectedError(format!(
                "RPC returned {} accounts for {} keys",
                fetched.accounts.len(),
                keys.len()
            )));
        }
        let mut accounts = fetched.accounts.into_iter();
        let clock = clock_at(fetched.slot, accounts.next().flatten())?;
        match &mut read {
            None => {
                read = Some(RegistryRead {
                    slot: fetched.slot,
                    unix_timestamp: clock.unix_timestamp,
                    accounts: accounts.collect(),
                })
            }
            Some(read) if read.slot == fetched.slot => read.accounts.extend(accounts),
            Some(_) => return Ok(None),
        }
    }
    Ok(read)
}

/// The clock is read in the same call as the records, so its slot is that
/// call's slot; anything else is a node answering from two banks.
fn clock_at(slot: u64, account: Option<Account>) -> Result<Clock, PhotonApiError> {
    let account = account
        .ok_or_else(|| PhotonApiError::UnexpectedError("Clock sysvar is missing".to_string()))?;
    let (clock, _): (Clock, usize) =
        bincode::serde::decode_from_slice(&account.data, bincode::config::legacy()).map_err(
            |error| PhotonApiError::UnexpectedError(format!("Clock sysvar is malformed: {error}")),
        )?;
    if clock.slot != slot {
        return Err(PhotonApiError::UnexpectedError(format!(
            "Clock sysvar at slot {} in a read at slot {slot}",
            clock.slot
        )));
    }
    Ok(clock)
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

    fn clock_account(slot: u64, unix_timestamp: i64) -> Account {
        let clock = Clock {
            slot,
            unix_timestamp,
            ..Clock::default()
        };
        Account {
            lamports: 1,
            data: bincode::serde::encode_to_vec(clock, bincode::config::legacy()).unwrap(),
            owner: Pubkey::default(),
            executable: false,
            rent_epoch: 0,
        }
    }

    /// A `getMultipleAccounts` answer: the clock first, then one entry per owner.
    fn read_answer(slot: u64, unix_timestamp: i64, accounts: &[Option<Account>]) -> String {
        let mut value = vec![encoded_account(&clock_account(slot, unix_timestamp))];
        value.extend(accounts.iter().map(|account| match account {
            Some(account) => encoded_account(account),
            None => Value::Null,
        }));
        json!({ "jsonrpc": "2.0", "id": 1, "result": { "context": { "slot": slot }, "value": value } })
            .to_string()
    }

    fn requested_keys(request: &str) -> Vec<String> {
        let request: Value = serde_json::from_str(request).unwrap();
        assert_eq!(request["method"], "getMultipleAccounts");
        request["params"][0]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key.as_str().unwrap().to_string())
            .collect()
    }

    fn pda_strings(owners: &[SerializablePubkey]) -> Vec<String> {
        iter::once(solana_clock::sysvar::ID.to_string())
            .chain(
                owners
                    .iter()
                    .map(|owner| user_record_pda(&owner.0).0.to_string()),
            )
            .collect()
    }

    #[tokio::test]
    async fn reads_every_owner_at_one_slot_in_request_order() {
        let owners = vec![owner(1), owner(2), owner(3)];
        let p256_owner = registered(&owners[0], Some([7; 33]));
        let solana_owner = registered(&owners[2], None);
        let (url, node) = serve_in_order(&[(
            "200 OK",
            &read_answer(
                77,
                1_700_000_000,
                &[
                    Some(record_account(&p256_owner)),
                    None,
                    Some(record_account(&solana_owner)),
                ],
            ),
        )]);

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
        // One call: the clock, then the canonical PDAs in request order.
        assert_eq!(requests.len(), 1);
        assert_eq!(requested_keys(&requests[0]), pda_strings(&owners));
    }

    #[tokio::test]
    async fn a_full_batch_takes_two_reads_that_agree_on_the_slot() {
        let owners = (1..=MAX_USER_RECORD_OWNERS as u8)
            .map(owner)
            .collect::<Vec<_>>();
        let (url, node) = serve_in_order(&[
            ("200 OK", &read_answer(77, 5, &vec![None; OWNERS_PER_READ])),
            ("200 OK", &read_answer(77, 5, &[None])),
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

        assert_eq!(response.context.slot, 77);
        assert_eq!(response.records, vec![None; MAX_USER_RECORD_OWNERS]);
        assert_eq!(
            requested_keys(&requests[0]),
            pda_strings(&owners[..OWNERS_PER_READ])
        );
        assert_eq!(
            requested_keys(&requests[1]),
            pda_strings(&owners[OWNERS_PER_READ..])
        );
    }

    #[tokio::test]
    async fn a_read_that_crosses_a_slot_is_taken_again() {
        let owners = (1..=MAX_USER_RECORD_OWNERS as u8)
            .map(owner)
            .collect::<Vec<_>>();
        let (url, node) = serve_in_order(&[
            ("200 OK", &read_answer(77, 5, &vec![None; OWNERS_PER_READ])),
            ("200 OK", &read_answer(78, 6, &[None])),
            ("200 OK", &read_answer(78, 6, &vec![None; OWNERS_PER_READ])),
            ("200 OK", &read_answer(78, 6, &[None])),
        ]);

        let response = get_user_records(&RpcClient::new(url), GetUserRecordsRequest { owners })
            .await
            .unwrap();
        let requests = node.join().unwrap();

        assert_eq!(
            response.context,
            Context {
                block_time: 6,
                slot: 78
            }
        );
        assert_eq!(requests.len(), 4);
    }

    #[tokio::test]
    async fn a_read_that_keeps_crossing_slots_is_an_error() {
        let owners = (1..=MAX_USER_RECORD_OWNERS as u8)
            .map(owner)
            .collect::<Vec<_>>();
        let answers = (0..SAME_SLOT_ATTEMPTS as u64)
            .flat_map(|attempt| {
                [
                    read_answer(77 + attempt, 5, &vec![None; OWNERS_PER_READ]),
                    read_answer(78 + attempt, 6, &[None]),
                ]
            })
            .collect::<Vec<_>>();
        let (url, node) = serve_in_order(
            &answers
                .iter()
                .map(|answer| ("200 OK", answer.as_str()))
                .collect::<Vec<_>>(),
        );

        let error = get_user_records(&RpcClient::new(url), GetUserRecordsRequest { owners })
            .await
            .unwrap_err();
        node.join().unwrap();

        assert!(matches!(
            error,
            PhotonApiError::UnexpectedError(message) if message.contains("crossed a slot boundary")
        ));
    }

    #[tokio::test]
    async fn a_clock_from_another_bank_is_an_error() {
        let (url, node) = serve_in_order(&[(
            "200 OK",
            &json!({ "jsonrpc": "2.0", "id": 1, "result": { "context": { "slot": 77 }, "value": [
                encoded_account(&clock_account(76, 5)),
                null,
            ] } })
            .to_string(),
        )]);

        let error = get_user_records(
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
            PhotonApiError::UnexpectedError(message) if message.contains("Clock sysvar at slot 76")
        ));
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
