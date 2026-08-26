//! A published payload is trusted only after it reproduces the on-chain commitment.

use solana_address::Address;
use zolana_client::{ClientError, Rpc};
use zolana_interface::event::OutputDataEncoding;
use zolana_ring_policy::{record_nullifier, Member, Record, RecordKind, RecordsOwner};

use crate::instructions::record::proof::RecordProofError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveRecord {
    pub record: Record,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
}

/// `None` when the address was never claimed, a cleared record still reads back.
pub fn read_record<I: Rpc>(
    indexer: &I,
    records: Address,
    kind: RecordKind,
    member: &Member,
) -> Result<Option<LiveRecord>, RecordProofError> {
    let owner = RecordsOwner::new(records.as_array()).map_err(|_| RecordProofError::Hashing)?;
    let address = owner
        .address(kind, member)
        .map_err(|_| RecordProofError::Hashing)?;
    let mut cursor = None;
    let mut live = None;
    loop {
        let page = indexer.get_encrypted_utxos_by_tags(
            vec![records.to_bytes()],
            cursor.clone(),
            Some(100),
            None,
        )?;
        for indexed in page.matches {
            let Some(candidate) = decode(&owner, &address, kind, member, &indexed) else {
                continue;
            };
            if is_spent(indexer, &candidate.nullifier)? {
                continue;
            }
            // The address slot admits one lineage per pair, so a second live
            // version means the published stream disagrees with the tree.
            if live.is_some() {
                return Err(RecordProofError::AmbiguousRecord {
                    kind,
                    member: *member.as_bytes(),
                });
            }
            live = Some(candidate);
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    Ok(live)
}

fn decode(
    owner: &RecordsOwner,
    address: &[u8; 32],
    kind: RecordKind,
    member: &Member,
    indexed: &zolana_client::EncryptedUtxoMatch,
) -> Option<LiveRecord> {
    let OutputDataEncoding::Plaintext(payload) = indexed.output_slot.output_data()? else {
        return None;
    };
    let record = Record::from_payload(&payload)?;
    if record.kind != kind || record.member != *member {
        return None;
    }
    let utxo_hash = record.utxo_hash(owner, address).ok()?;
    if utxo_hash != indexed.output_slot.output_context.hash {
        return None;
    }
    let nullifier = record_nullifier(&utxo_hash, &record.blinding()).ok()?;
    Some(LiveRecord {
        record,
        utxo_hash,
        nullifier,
    })
}

fn is_spent<I: Rpc>(indexer: &I, nullifier: &[u8; 32]) -> Result<bool, ClientError> {
    Ok(!indexer
        .get_shielded_transactions_by_nullifiers(vec![*nullifier], None, Some(1), None)?
        .transactions
        .is_empty())
}
