//! Shared fixture for the two places that compare resolving a shielded
//! transaction by signature against reaching it through the view tag index:
//! the `signature_lookup_cost_is_independent_of_view_tag_history` integration
//! test, which pins the cost in requests and hydrated rows, and
//! `benches/rings_signature_lookup.rs`, which measures what that costs in
//! wall-clock time.
//!
//! Both go through the same seeding and the same `resolve` pager so the bench
//! cannot drift into measuring something the test does not pin.

use std::future::Future;

use photon_indexer::{
    api::method::rings::{
        get_shielded_transactions_by_signature, get_shielded_transactions_by_tags,
    },
    dao::generated::{
        blocks, rings_output_payloads, rings_outputs, rings_transactions, transactions,
    },
    migration::RingsMigrator,
};
use sea_orm::{Database, DatabaseConnection, EntityTrait, Set};
use sea_orm_migration::MigratorTrait;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use zolana_indexer_api::{
    ChainPosition, GetRingsByTagsRequest, GetShieldedTransactionsBySignatureRequest,
    GetShieldedTransactionsByTagsResponse, Hash, Limit, SerializableSignature,
};
use zolana_interface::pda;

pub const VIEW_TAG: [u8; 32] = [77u8; 32];
/// The page size the confirmation path used before the signature lookup.
pub const PAGE_LIMIT: u64 = 50;

const BASE_SLOT: u64 = 100_000;
/// Keep each insert under the SQLite bound on statement parameters.
const SEED_INSERT_CHUNK: usize = 50;

/// Requests issued and transaction rows hydrated to reach one transaction.
/// These are the terms the database cost actually grows in, so they stay stable
/// under a loaded machine in a way wall-clock timings would not.
#[derive(Debug, PartialEq, Eq)]
pub struct LookupCost {
    pub requests: usize,
    pub hydrated_transactions: usize,
}

/// One page of a lookup: the signatures it surfaced, how many transactions the
/// server hydrated to produce it, and where the next page would start.
pub struct Page {
    pub signatures: Vec<Signature>,
    pub hydrated: usize,
    pub next: Option<ChainPosition>,
}

pub fn signature_at(index: u64) -> Signature {
    let mut bytes = [0u8; 64];
    bytes
        .get_mut(..8)
        .expect("signature is longer than the index prefix")
        .copy_from_slice(&index.to_be_bytes());
    Signature::from(bytes)
}

pub async fn fresh_rings_database() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:")
        .await
        .expect("in-memory database");
    RingsMigrator::up(&db, None)
        .await
        .expect("rings migrations");
    db
}

/// Drive `fetch` until `target` shows up, counting what it took to get there.
/// Both lookups run through this, so the signature lookup's request count is
/// derived from that endpoint reporting no next position rather than assumed.
pub async fn resolve<F, Fut>(target: Signature, mut fetch: F) -> LookupCost
where
    F: FnMut(Option<ChainPosition>) -> Fut,
    Fut: Future<Output = Page>,
{
    let mut cost = LookupCost {
        requests: 0,
        hydrated_transactions: 0,
    };
    let mut since = None;
    loop {
        let page = fetch(since).await;
        cost.requests += 1;
        cost.hydrated_transactions += page.hydrated;
        if page.signatures.contains(&target) {
            return cost;
        }
        since = page.next;
        assert!(since.is_some(), "lookup ran out of pages before {target}");
    }
}

pub async fn resolve_by_signature(db: &DatabaseConnection, target: Signature) -> LookupCost {
    resolve(target, move |_cursor| async move {
        let response = get_shielded_transactions_by_signature(
            db,
            GetShieldedTransactionsBySignatureRequest {
                tx_signature: SerializableSignature(target),
            },
        )
        .await
        .expect("signature lookup");

        Page {
            signatures: response
                .transactions
                .iter()
                .map(|item| item.transaction.tx_signature.0)
                .collect(),
            hydrated: response.transactions.len(),
            next: None,
        }
    })
    .await
}

pub async fn resolve_by_tags(
    db: &DatabaseConnection,
    view_tag: [u8; 32],
    target: Signature,
    page_limit: u64,
) -> LookupCost {
    resolve(target, move |since| async move {
        let page = tag_page(db, view_tag, since, page_limit).await;
        Page {
            signatures: page
                .transactions
                .iter()
                .map(|item| item.tx_signature.0)
                .collect(),
            hydrated: page.transactions.len(),
            next: page.next,
        }
    })
    .await
}

pub async fn tag_page(
    db: &DatabaseConnection,
    view_tag: [u8; 32],
    since: Option<ChainPosition>,
    page_limit: u64,
) -> GetShieldedTransactionsByTagsResponse {
    get_shielded_transactions_by_tags(
        db,
        GetRingsByTagsRequest {
            tags: vec![Hash::from(view_tag)],
            since,
            limit: Some(Limit::new(page_limit).expect("page limit is within the shared bounds")),
            ring_program_id: None,
        },
    )
    .await
    .expect("tag lookup")
}

/// Insert one transaction per index, each carrying `view_tag` on its single
/// output and sitting in its own slot so the tag query's `slot ASC` order is
/// deterministic and the highest index is always the newest.
/// The ring every seeded transaction is attributed to. A real derived PDA, so
/// filtering by `fixture_ring_program()` resolves to these rows.
pub fn fixture_ring_program() -> Pubkey {
    Pubkey::new_from_array([4; 32])
}

pub fn fixture_ring_config() -> Pubkey {
    pda::ring_auth(&fixture_ring_program()).0
}

pub async fn seed_tagged_transaction_history(
    db: &DatabaseConnection,
    view_tag: [u8; 32],
    indexes: std::ops::Range<u64>,
) {
    let mut block_rows = Vec::new();
    let mut transaction_rows = Vec::new();
    let mut rings_rows = Vec::new();
    let mut output_rows = Vec::new();
    let mut payload_rows = Vec::new();

    for index in indexes {
        let slot = i64::try_from(BASE_SLOT + index).expect("slot fits in i64");
        let signature = signature_at(index).as_ref().to_vec();
        let rings_tx_id = i64::try_from(index).expect("index fits in i64") + 1;

        block_rows.push(blocks::ActiveModel {
            slot: Set(slot),
            parent_slot: Set(slot - 1),
            parent_blockhash: Set(vec![0; 32]),
            blockhash: Set(rings_tx_id.to_be_bytes().repeat(4)),
            block_height: Set(slot),
            block_time: Set(slot),
        });
        transaction_rows.push(transactions::ActiveModel {
            signature: Set(signature.clone()),
            slot: Set(slot),
            error: Set(None),
        });
        rings_rows.push(rings_transactions::ActiveModel {
            rings_tx_id: Set(rings_tx_id),
            signature: Set(signature),
            event_index: Set(0),
            slot: Set(slot),
            ring_config: Set(Some(fixture_ring_config().to_bytes().to_vec())),
            source_instruction_tag: Set(0),
            output_tree: Set(vec![8u8; 32]),
            first_output_leaf_index: Set(rings_tx_id),
            tx_viewing_pk: Set(Some(vec![2u8; 33])),
            salt: Set(Some(vec![3u8; 16])),
            proofless: Set(false),
        });
        output_rows.push(rings_outputs::ActiveModel {
            output_id: Set(rings_tx_id),
            rings_tx_id: Set(rings_tx_id),
            slot: Set(slot),
            output_index: Set(0),
            output_tree: Set(vec![8u8; 32]),
            leaf_index: Set(rings_tx_id),
            view_tag: Set(view_tag.to_vec()),
            utxo_hash: Set(rings_tx_id.to_be_bytes().repeat(4)),
            // Copied from the transaction, as the ingester does; a fixture
            // leaving them NULL would order differently from production.
            signature: Set(Some(signature_at(index).as_ref().to_vec())),
            event_index: Set(Some(0)),
        });
        payload_rows.push(rings_output_payloads::ActiveModel {
            output_id: Set(rings_tx_id),
            payload: Set(vec![9u8; 32]),
        });
    }

    for chunk in block_rows.chunks(SEED_INSERT_CHUNK) {
        blocks::Entity::insert_many(chunk.to_vec())
            .exec(db)
            .await
            .expect("seed blocks");
    }
    for chunk in transaction_rows.chunks(SEED_INSERT_CHUNK) {
        transactions::Entity::insert_many(chunk.to_vec())
            .exec(db)
            .await
            .expect("seed transactions");
    }
    for chunk in rings_rows.chunks(SEED_INSERT_CHUNK) {
        rings_transactions::Entity::insert_many(chunk.to_vec())
            .exec(db)
            .await
            .expect("seed rings transactions");
    }
    for chunk in output_rows.chunks(SEED_INSERT_CHUNK) {
        rings_outputs::Entity::insert_many(chunk.to_vec())
            .exec(db)
            .await
            .expect("seed rings outputs");
    }
    for chunk in payload_rows.chunks(SEED_INSERT_CHUNK) {
        rings_output_payloads::Entity::insert_many(chunk.to_vec())
            .exec(db)
            .await
            .expect("seed output payloads");
    }
}
