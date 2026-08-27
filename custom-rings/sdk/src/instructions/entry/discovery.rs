//! Published content is trusted only after it reproduces the on-chain commitment.

use solana_address::Address;
use zolana_client::{ClientError, Rpc};
use zolana_interface::event::OutputDataEncoding;
use zolana_ring_policy::{entry_nullifier, ListEntry, ListId, ListNamespace, Member};

use crate::instructions::entry::proof::EntryProofError;

/// The current version of a lineage with its tree position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LiveEntry {
    pub entry: ListEntry,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
}

/// `None` when the address was never claimed, a cleared entry still reads back.
pub fn read_entry<I: Rpc>(
    indexer: &I,
    namespace: Address,
    list_id: ListId,
    member: &Member,
) -> Result<Option<LiveEntry>, EntryProofError> {
    let owner = ListNamespace::new(namespace.as_array()).map_err(|_| EntryProofError::Hashing)?;
    let address = owner
        .address(list_id, member)
        .map_err(|_| EntryProofError::Hashing)?;
    let mut cursor = None;
    let mut live = None;
    loop {
        let page = indexer.get_encrypted_utxos_by_tags(
            vec![namespace.to_bytes()],
            cursor.clone(),
            Some(100),
            None,
        )?;
        for indexed in page.matches {
            let Some(candidate) = decode(&owner, &address, list_id, member, &indexed) else {
                continue;
            };
            if is_spent(indexer, &candidate.nullifier)? {
                continue;
            }
            // The address slot admits one lineage per pair, so a second live
            // version means the published stream disagrees with the tree.
            if live.is_some() {
                return Err(EntryProofError::AmbiguousEntry {
                    list_id,
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
    owner: &ListNamespace,
    address: &[u8; 32],
    list_id: ListId,
    member: &Member,
    indexed: &zolana_client::EncryptedUtxoMatch,
) -> Option<LiveEntry> {
    let OutputDataEncoding::Plaintext(content) = indexed.output_slot.output_data()? else {
        return None;
    };
    let entry = ListEntry::from_entry_bytes(&content)?;
    if entry.list_id != list_id || entry.member != *member {
        return None;
    }
    let utxo_hash = entry.utxo_hash(owner, address).ok()?;
    if utxo_hash != indexed.output_slot.output_context.hash {
        return None;
    }
    let nullifier = entry_nullifier(&utxo_hash, &entry.blinding()).ok()?;
    Some(LiveEntry {
        entry,
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
