//! Every velocity transfer spends the version before it, the counters ride its messages.

use solana_address::Address;
use zolana_client::{AsyncRpc, OutputSlot, Rpc, ShieldedTransaction};
use zolana_interface::{event::OutputDataEncoding, instruction::MessageData};
use zolana_keypair::{constants::SALT_LEN, P256Pubkey};
use zolana_ring_policy::{entry_nullifier, ListNamespace, Member, SpendRecord};

use crate::instructions::entry::{EntryProofError, LineageLookup, Lineages};

/// The publishing transaction, its messages carry the counters under its key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordOrigin {
    pub first_nullifier: [u8; 32],
    pub tx_viewing_pk: Option<P256Pubkey>,
    pub salt: Option<[u8; SALT_LEN]>,
    pub messages: Vec<MessageData>,
}

/// The current version of a member's record and its origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveSpendRecord {
    pub record: SpendRecord,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
    pub origin: RecordOrigin,
}

#[must_use]
pub struct ReadSpendRecord {
    pub entries_tree: Address,
    pub entries_tree_id: u16,
    pub namespace: Address,
    pub member: Member,
}

impl ReadSpendRecord {
    /// `None` until the member registers.
    pub fn read<I: Rpc>(self, indexer: &I) -> Result<Option<LiveSpendRecord>, EntryProofError> {
        let lookup = self.lookup()?;
        let lineages = Lineages {
            entries_tree: self.entries_tree,
            lookups: &[lookup],
        }
        .fetch(indexer)?;
        Ok(lineages.into_iter().next().flatten())
    }

    pub async fn read_async<I: AsyncRpc>(
        self,
        indexer: &I,
    ) -> Result<Option<LiveSpendRecord>, EntryProofError> {
        let lookup = self.lookup()?;
        let lineages = Lineages {
            entries_tree: self.entries_tree,
            lookups: &[lookup],
        }
        .fetch_async(indexer)
        .await?;
        Ok(lineages.into_iter().next().flatten())
    }

    fn lookup(&self) -> Result<SpendLookup, EntryProofError> {
        let owner =
            ListNamespace::new(self.namespace.as_array()).map_err(|_| EntryProofError::Hashing)?;
        Ok(SpendLookup {
            owner,
            member: self.member,
            tree_id: self.entries_tree_id,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SpendLookup {
    pub owner: ListNamespace,
    pub member: Member,
    pub tree_id: u16,
}

impl LineageLookup for SpendLookup {
    type Live = LiveSpendRecord;

    fn address(&self) -> Result<[u8; 32], EntryProofError> {
        self.owner
            .spend_address(&self.member, self.tree_id)
            .map_err(|_| EntryProofError::Hashing)
    }

    fn decode(
        &self,
        address: &[u8; 32],
        spender: &ShieldedTransaction,
        slot: &OutputSlot,
    ) -> Option<LiveSpendRecord> {
        let OutputDataEncoding::Plaintext(content) = slot.output_data()? else {
            return None;
        };
        let record = SpendRecord::from_record_bytes(&content)?;
        if record.member != self.member {
            return None;
        }
        let utxo_hash = record.utxo_hash(&self.owner, address, self.tree_id).ok()?;
        if utxo_hash != slot.output_context.hash {
            return None;
        }
        let nullifier = entry_nullifier(&utxo_hash, &record.blinding).ok()?;
        Some(LiveSpendRecord {
            record,
            utxo_hash,
            nullifier,
            origin: RecordOrigin {
                first_nullifier: spender.nullifiers.first().copied()?,
                tx_viewing_pk: spender.tx_viewing_pk,
                salt: spender.salt,
                messages: spender.messages.clone(),
            },
        })
    }

    fn nullifier(live: &LiveSpendRecord) -> [u8; 32] {
        live.nullifier
    }

    fn version(live: &LiveSpendRecord) -> u64 {
        live.record.version
    }

    fn broken(&self, version: u64) -> EntryProofError {
        EntryProofError::BrokenSpendLineage {
            member: *self.member.as_bytes(),
            version,
        }
    }
}

#[cfg(test)]
mod tests {
    use zolana_client::{Context, OutputContext};
    use zolana_ring_policy::SpendCounters;

    use super::*;
    use crate::instructions::entry::discovery::tests::{namespace, owner, tree, NullifierRpc};

    fn member() -> Member {
        Member::owner_tag(&[5u8; 32]).expect("member")
    }

    fn version(version: u64) -> (SpendRecord, [u8; 32], [u8; 32]) {
        let record = SpendRecord {
            member: member(),
            version,
            window: 3,
            counters_commitment: SpendCounters::zero(&[]).commitment().expect("commitment"),
            blinding: [version as u8 + 1; 32],
        };
        let address = owner().spend_address(&member(), 0).expect("address");
        let utxo_hash = record.utxo_hash(&owner(), &address, 0).expect("leaf");
        (
            record,
            utxo_hash,
            entry_nullifier(&utxo_hash, &record.blinding).expect("nullifier"),
        )
    }

    fn spender(spent: [u8; 32], record: &SpendRecord, utxo_hash: [u8; 32]) -> ShieldedTransaction {
        ShieldedTransaction {
            slot: 0,
            tx_signature: solana_signature::Signature::default(),
            tx_viewing_pk: None,
            salt: Some([9u8; SALT_LEN]),
            output_slots: vec![OutputSlot {
                view_tag: namespace().to_bytes(),
                output_context: OutputContext {
                    hash: utxo_hash,
                    tree: tree(),
                    leaf_index: record.version,
                },
                payload: record.to_output_data().to_vec(),
            }],
            messages: vec![MessageData {
                view_tag: namespace().to_bytes(),
                data: vec![1, 2, 3],
            }],
            nullifiers: vec![spent],
            proofless: false,
        }
    }

    #[test]
    fn the_walk_returns_the_live_version_with_its_origin() {
        let address = owner().spend_address(&member(), 0).expect("address");
        let (first, first_hash, first_nullifier) = version(0);
        let (second, second_hash, second_nullifier) = version(1);
        let rpc = NullifierRpc::new(vec![
            spender(address, &first, first_hash),
            spender(first_nullifier, &second, second_hash),
        ]);
        let live = ReadSpendRecord {
            entries_tree: tree(),
            entries_tree_id: 0,
            namespace: namespace(),
            member: member(),
        }
        .read(&rpc)
        .expect("walk")
        .expect("registered");
        assert_eq!(live.record, second);
        assert_eq!(live.nullifier, second_nullifier);
        assert_eq!(live.origin.first_nullifier, first_nullifier);
        assert_eq!(live.origin.salt, Some([9u8; SALT_LEN]));
        assert_eq!(live.origin.messages.len(), 1);
        let _ = Context {
            block_time: 0,
            slot: 0,
        };
    }

    #[test]
    fn an_unregistered_member_reads_none() {
        let rpc = NullifierRpc::new(Vec::new());
        let live = ReadSpendRecord {
            entries_tree: tree(),
            entries_tree_id: 0,
            namespace: namespace(),
            member: member(),
        }
        .read(&rpc)
        .expect("walk");
        assert_eq!(live, None);
    }
}
