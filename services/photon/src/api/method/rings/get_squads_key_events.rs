//! Read side of the Squads key-material log.
//!
//! A rotation overwrites the viewing key account and a close zeroes it, while
//! the UTXO ciphertexts those keys decrypt stay on chain. A recovery or auditor
//! key holder that was offline across the write reads the destroyed material
//! here or nowhere.

use super::common::{
    decode_cursor, encode_cursor, hash_from_vec, next_cursor_from_rows, pubkey_from_vec,
    signature_from_bytes, u16_from_i16, u64_from_i64,
};
use crate::api::error::PhotonApiError;
use crate::common::indexer_context::extract as extract_context;
use crate::dao::generated::squads_key_events;
use bincode::{Decode, Encode};
use sea_orm::{
    ColumnTrait, Condition, DatabaseConnection, EntityTrait, QueryFilter, QueryOrder, QuerySelect,
    TransactionTrait,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use zolana_indexer_api::{
    Base64String, Context, Hash, Limit, RpcMethod, SerializablePubkey, SerializableSignature,
};

pub const GET_SQUADS_KEY_EVENTS: &str = "get_squads_key_events";

pub struct GetSquadsKeyEvents;

impl RpcMethod for GetSquadsKeyEvents {
    const NAME: &'static str = GET_SQUADS_KEY_EVENTS;
    type Request = GetSquadsKeyEventsRequest;
    type Response = GetSquadsKeyEventsResponse;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetSquadsKeyEventsRequest {
    /// The rotated or closed viewing key account. Required unless `owner` is
    /// given, and combined with it when both are.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<SerializablePubkey>,
    /// The owner the account carried before the write. It is a hash for a smart
    /// account owner, so it is not an address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<Hash>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Base64String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<Limit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct GetSquadsKeyEventsResponse {
    pub context: Context,
    /// Oldest key material first, so a holder replays rotations in the order
    /// the chain applied them.
    pub events: Vec<SquadsKeyEvent>,
    pub next_cursor: Option<Base64String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub struct SquadsKeyEvent {
    pub slot: u64,
    pub tx_signature: SerializableSignature,
    pub event_index: u16,
    pub source_instruction_tag: u16,
    /// Kind byte as the program wrote it. Negative when the record carried
    /// none.
    pub event_kind: i16,
    pub account: SerializablePubkey,
    pub owner: Hash,
    /// Nonce of the account state before the emitting instruction wrote it.
    pub key_nonce: u64,
    /// Nonce the rotation wrote. A close writes none.
    pub new_key_nonce: Option<u64>,
    /// Rotation commitment the proof was bound to. A close has none.
    pub old_state_hash: Option<Hash>,
    /// `[kind, payload]` as emitted, holding the destroyed key material.
    pub raw_event: Base64String,
    /// Zero when the indexer could not decode the record, and then every field
    /// above except `event_kind` and `raw_event` is unset.
    pub parse_version: i16,
}

#[derive(Clone, Debug, Decode, Encode, PartialEq, Eq)]
pub(super) struct SquadsKeyEventCursor {
    pub(super) slot: u64,
    pub(super) squads_key_event_id: u64,
}

pub async fn get_squads_key_events(
    conn: &DatabaseConnection,
    request: GetSquadsKeyEventsRequest,
) -> Result<GetSquadsKeyEventsResponse, PhotonApiError> {
    let limit = request.limit.unwrap_or_default().value();
    if request.account.is_none() && request.owner.is_none() {
        return Err(PhotonApiError::ValidationError(
            "An account or an owner must be provided".to_string(),
        ));
    }
    let cursor = request
        .cursor
        .as_ref()
        .map(decode_cursor::<SquadsKeyEventCursor>)
        .transpose()?;

    let context = extract_context(conn).await?;
    let tx = conn.begin().await?;
    crate::api::set_transaction_isolation_if_needed(&tx).await?;

    let mut query = squads_key_events::Entity::find();
    if let Some(account) = request.account {
        query = query.filter(squads_key_events::Column::Account.eq(account.to_bytes_vec()));
    }
    if let Some(owner) = request.owner {
        query = query.filter(squads_key_events::Column::Owner.eq(owner.to_vec()));
    }
    if let Some(cursor) = cursor {
        query = query.filter(cursor_condition(&cursor)?);
    }

    let rows = query
        .order_by_asc(squads_key_events::Column::Slot)
        .order_by_asc(squads_key_events::Column::SquadsKeyEventId)
        .limit(limit)
        .all(&tx)
        .await?;

    let next_cursor = next_cursor_from_rows(&rows, limit, cursor_from_row)?;
    let events = rows
        .into_iter()
        .map(key_event_from_row)
        .collect::<Result<Vec<_>, PhotonApiError>>()?;

    tx.commit().await?;

    Ok(GetSquadsKeyEventsResponse {
        context,
        events,
        next_cursor,
    })
}

/// Rows after the cursor in the response order. The row id breaks the tie
/// between events of one slot, so no event is served twice or skipped.
fn cursor_condition(cursor: &SquadsKeyEventCursor) -> Result<Condition, PhotonApiError> {
    let slot = i64_from_u64(cursor.slot, "slot")?;
    let event_id = i64_from_u64(cursor.squads_key_event_id, "key event id")?;

    Ok(Condition::any()
        .add(squads_key_events::Column::Slot.gt(slot))
        .add(
            Condition::all()
                .add(squads_key_events::Column::Slot.eq(slot))
                .add(squads_key_events::Column::SquadsKeyEventId.gt(event_id)),
        ))
}

fn cursor_from_row(row: &squads_key_events::Model) -> Result<Vec<u8>, PhotonApiError> {
    encode_cursor(&SquadsKeyEventCursor {
        slot: u64_from_i64(row.slot, "slot")?,
        squads_key_event_id: u64_from_i64(row.squads_key_event_id, "key event id")?,
    })
}

fn key_event_from_row(row: squads_key_events::Model) -> Result<SquadsKeyEvent, PhotonApiError> {
    Ok(SquadsKeyEvent {
        slot: u64_from_i64(row.slot, "slot")?,
        tx_signature: signature_from_bytes(&row.signature)?,
        event_index: u16_from_i16(row.event_index, "event index")?,
        source_instruction_tag: u16_from_i16(row.source_instruction_tag, "source instruction tag")?,
        event_kind: row.event_kind,
        account: pubkey_from_vec(row.account)?,
        owner: hash_from_vec(row.owner)?,
        key_nonce: u64_from_i64(row.key_nonce, "key nonce")?,
        new_key_nonce: row
            .new_key_nonce
            .map(|nonce| u64_from_i64(nonce, "new key nonce"))
            .transpose()?,
        old_state_hash: row.old_state_hash.map(hash_from_vec).transpose()?,
        raw_event: Base64String(row.raw_event),
        parse_version: row.parse_version,
    })
}

fn i64_from_u64(value: u64, field: &str) -> Result<i64, PhotonApiError> {
    i64::try_from(value).map_err(|_| {
        PhotonApiError::ValidationError(format!("{} {} does not fit in i64", field, value))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::generated::{blocks, transactions};
    use crate::migration::RingsMigrator;
    use sea_orm::{Database, Set};
    use sea_orm_migration::MigratorTrait;

    const ACCOUNT: [u8; 32] = [4; 32];
    const OWNER: [u8; 32] = [6; 32];

    async fn setup_test_db() -> DatabaseConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        RingsMigrator::up(&db, None).await.unwrap();
        db
    }

    /// One rotation of `account`, indexed in `slot`, with `key_nonce` ordering
    /// it against the others of that account.
    async fn insert_key_event(
        db: &DatabaseConnection,
        slot: i64,
        key_nonce: i64,
        account: [u8; 32],
    ) {
        let signature = vec![u8::try_from(key_nonce).unwrap(); 64];
        blocks::Entity::insert(blocks::ActiveModel {
            slot: Set(slot),
            parent_slot: Set(slot - 1),
            parent_blockhash: Set(vec![0; 32]),
            blockhash: Set(vec![u8::try_from(slot).unwrap(); 32]),
            block_height: Set(slot),
            block_time: Set(slot),
        })
        .exec(db)
        .await
        .ok();
        transactions::Entity::insert(transactions::ActiveModel {
            signature: Set(signature.clone()),
            slot: Set(slot),
            error: Set(None),
        })
        .exec(db)
        .await
        .unwrap();
        squads_key_events::Entity::insert(squads_key_events::ActiveModel {
            squads_key_event_id: Default::default(),
            signature: Set(signature),
            event_index: Set(0),
            slot: Set(slot),
            squads_program_id: Set(vec![5; 32]),
            source_instruction_tag: Set(14),
            event_kind: Set(1),
            account: Set(account.to_vec()),
            owner: Set(OWNER.to_vec()),
            key_nonce: Set(key_nonce),
            new_key_nonce: Set(Some(key_nonce + 1)),
            old_state_hash: Set(Some(vec![7; 32])),
            raw_event: Set(vec![1, key_nonce as u8]),
            parse_version: Set(1),
        })
        .exec(db)
        .await
        .unwrap();
    }

    fn request(account: Option<[u8; 32]>, owner: Option<[u8; 32]>) -> GetSquadsKeyEventsRequest {
        GetSquadsKeyEventsRequest {
            account: account.map(SerializablePubkey::from),
            owner: owner.map(Hash::from),
            cursor: None,
            limit: None,
        }
    }

    /// A returning key holder has the account address and nothing else, and
    /// must replay the rotations in the order the chain applied them.
    #[tokio::test]
    async fn returns_key_material_for_an_account_oldest_first() {
        let db = setup_test_db().await;
        insert_key_event(&db, 2, 2, ACCOUNT).await;
        insert_key_event(&db, 1, 1, ACCOUNT).await;
        insert_key_event(&db, 3, 3, [9; 32]).await;

        let response = get_squads_key_events(&db, request(Some(ACCOUNT), None))
            .await
            .unwrap();

        let nonces = response
            .events
            .iter()
            .map(|event| event.key_nonce)
            .collect::<Vec<_>>();
        assert_eq!(nonces, vec![1, 2]);
        assert_eq!(
            response.events[0].account,
            SerializablePubkey::from(ACCOUNT)
        );
        assert_eq!(response.events[0].raw_event, Base64String(vec![1, 1]));
        assert_eq!(response.next_cursor, None);
    }

    #[tokio::test]
    async fn returns_key_material_for_an_owner_across_accounts() {
        let db = setup_test_db().await;
        insert_key_event(&db, 1, 1, ACCOUNT).await;
        insert_key_event(&db, 2, 2, [9; 32]).await;

        let response = get_squads_key_events(&db, request(None, Some(OWNER)))
            .await
            .unwrap();

        assert_eq!(response.events.len(), 2);
        assert_eq!(
            response.events[1].account,
            SerializablePubkey::from([9; 32])
        );
    }

    /// The cursor must resume exactly where the page ended.
    #[tokio::test]
    async fn pages_with_the_cursor() {
        let db = setup_test_db().await;
        for nonce in 1..=3 {
            insert_key_event(&db, nonce, nonce, ACCOUNT).await;
        }

        let first = get_squads_key_events(
            &db,
            GetSquadsKeyEventsRequest {
                limit: Some(Limit::new(2).unwrap()),
                ..request(Some(ACCOUNT), None)
            },
        )
        .await
        .unwrap();
        assert_eq!(first.events.len(), 2);

        let second = get_squads_key_events(
            &db,
            GetSquadsKeyEventsRequest {
                cursor: first.next_cursor.clone(),
                limit: Some(Limit::new(2).unwrap()),
                ..request(Some(ACCOUNT), None)
            },
        )
        .await
        .unwrap();

        assert_eq!(
            second
                .events
                .iter()
                .map(|event| event.key_nonce)
                .collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(second.next_cursor, None);
    }

    /// A request with no filter would return every key holder's material.
    #[tokio::test]
    async fn rejects_a_request_with_no_account_and_no_owner() {
        let db = setup_test_db().await;

        let error = get_squads_key_events(&db, request(None, None))
            .await
            .expect_err("an unfiltered request must be rejected");

        assert!(matches!(error, PhotonApiError::ValidationError(_)));
    }
}
