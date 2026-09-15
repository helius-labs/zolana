//! Record discovery separates current-head authentication from counter recovery.

use solana_address::Address;
use zolana_client::{AsyncRpc, Rpc};
use zolana_interface::instruction::MessageData;
use zolana_keypair::{constants::SALT_LEN, P256Pubkey};
use zolana_ring_client::RecordCarrier;
use zolana_ring_policy::{entry_nullifier, ListNamespace, Member, SpendRecord};

use crate::{
    instructions::entry::{EntryProofError, LineageLookup, Lineages, SpentSlot},
    CustomRing,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordOrigin {
    pub first_nullifier: [u8; 32],
    pub tx_viewing_pk: Option<P256Pubkey>,
    pub salt: Option<[u8; SALT_LEN]>,
    pub messages: Vec<MessageData>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveSpendRecord {
    pub record: SpendRecord,
    pub utxo_hash: [u8; 32],
    pub nullifier: [u8; 32],
    pub origin: RecordOrigin,
}

pub struct ReadEnvironment<'a, I, R> {
    pub indexer: &'a I,
    pub rpc: &'a R,
}

impl<I, R> Clone for ReadEnvironment<'_, I, R> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<I, R> Copy for ReadEnvironment<'_, I, R> {}

#[must_use]
pub struct ReadSpendRecord {
    pub ring: CustomRing,
    pub entries_tree: Address,
    pub entries_tree_id: u16,
    pub member: Member,
}

impl ReadSpendRecord {
    /// Authenticated against the exact current head root.
    pub fn read_current<I: Rpc, R: Rpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<Option<LiveSpendRecord>, EntryProofError> {
        match self.current(env) {
            Ok(head) => Ok(Some(head.record)),
            Err(error) if error.is_unregistered() => Ok(None),
            Err(error) => Err(error),
        }
    }

    pub async fn read_current_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<Option<LiveSpendRecord>, EntryProofError> {
        match self.current_async(env).await {
            Ok(head) => Ok(Some(head.record)),
            Err(error) if error.is_unregistered() => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Unauthenticated history, unsuitable for transfer preparation.
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

    pub(crate) fn lookup(&self) -> Result<SpendLookup, EntryProofError> {
        let owner = ListNamespace::new(self.ring.namespace_pda().as_array())
            .map_err(|_| EntryProofError::Hashing)?;
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

    fn decode(&self, address: &[u8; 32], slot: SpentSlot<'_>) -> Option<LiveSpendRecord> {
        let SpentSlot { transaction, slot } = slot;
        if ListNamespace::new(&slot.view_tag).ok()? != self.owner {
            return None;
        }
        let record = RecordCarrier::decode(slot, &transaction.messages)
            .ok()??
            .record();
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
                first_nullifier: transaction.nullifiers.first().copied()?,
                tx_viewing_pk: transaction.tx_viewing_pk,
                salt: transaction.salt,
                messages: transaction.messages.clone(),
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
    use zolana_client::{OutputContext, OutputSlot, ShieldedTransaction};
    use zolana_ring_policy::SpendCounters;

    use super::*;
    use crate::instructions::entry::discovery::tests::{tree, NullifierRpc};

    fn ring() -> CustomRing {
        CustomRing::new(Address::new_from_array([8u8; 32]))
    }

    fn namespace() -> Address {
        ring().namespace_pda()
    }

    fn owner() -> ListNamespace {
        ListNamespace::new(namespace().as_array()).expect("owner")
    }

    fn member() -> Member {
        Member::owner_tag(&[5u8; 32]).expect("member")
    }

    fn version(version: u64) -> (SpendRecord, [u8; 32], [u8; 32]) {
        let record = SpendRecord {
            member: member(),
            version,
            window: 3,
            counters_commitment: SpendCounters::EMPTY.commitment().expect("commitment"),
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
        let mut payload = record.to_output_data().to_vec();
        let mut messages = Vec::new();
        let tx_key = zolana_keypair::ViewingKey::new();
        if record.version != 0 {
            let output = zolana_transaction::instructions::transact::SppProofOutputUtxo {
                asset: zolana_transaction::SOL_MINT,
                blinding: record.blinding,
                owner_address: Some(zolana_keypair::ShieldedAddress::for_pda(
                    &namespace(),
                    zolana_keypair::NullifierKey::from_secret([0; 31])
                        .pubkey()
                        .unwrap(),
                    tx_key.pubkey(),
                )),
                owner_tag: Some(namespace().to_bytes()),
                ..Default::default()
            };
            payload = zolana_transaction::instructions::transact::encode_confidential_slots(
                &[output],
                &Default::default(),
                &tx_key,
                [9; SALT_LEN],
            )
            .unwrap()
            .remove(0)
            .unwrap()
            .data;
            messages.push(MessageData {
                view_tag: zolana_ring_policy::spend_record_message_tag(namespace().as_array())
                    .unwrap(),
                data: record.to_output_data().to_vec(),
            });
        }
        messages.push(MessageData {
            view_tag: namespace().to_bytes(),
            data: vec![1, 2, 3],
        });
        ShieldedTransaction {
            slot: 0,
            tx_signature: solana_signature::Signature::default(),
            tx_viewing_pk: Some(tx_key.pubkey()),
            salt: Some([9u8; SALT_LEN]),
            output_slots: vec![OutputSlot {
                view_tag: namespace().to_bytes(),
                output_context: OutputContext {
                    hash: utxo_hash,
                    tree: tree(),
                    leaf_index: record.version,
                },
                payload,
            }],
            messages,
            nullifiers: vec![spent],
            proofless: false,
        }
    }

    fn read(rpc: &NullifierRpc) -> Result<Option<LiveSpendRecord>, EntryProofError> {
        ReadSpendRecord {
            ring: ring(),
            entries_tree: tree(),
            entries_tree_id: 0,
            member: member(),
        }
        .read(rpc)
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
        let live = read(&rpc).expect("walk").expect("registered");
        assert_eq!(live.record, second);
        assert_eq!(live.nullifier, second_nullifier);
        assert_eq!(live.origin.first_nullifier, first_nullifier);
        assert_eq!(live.origin.salt, Some([9u8; SALT_LEN]));
        assert_eq!(live.origin.messages.len(), 2);
    }

    #[test]
    fn a_successor_requires_one_bound_public_record_message() {
        let (record, hash, _) = version(1);
        let address = owner().spend_address(&member(), 0).unwrap();
        let transaction = spender(address, &record, hash);
        let lookup = SpendLookup {
            owner: owner(),
            member: member(),
            tree_id: 0,
        };
        let decode = |transaction: &ShieldedTransaction| {
            lookup.decode(
                &address,
                SpentSlot {
                    transaction,
                    slot: &transaction.output_slots[0],
                },
            )
        };
        assert_eq!(decode(&transaction).unwrap().record, record);
        let mutations: [fn(&mut ShieldedTransaction); 6] = [
            |tx| {
                tx.messages.remove(0);
            },
            |tx| tx.messages.push(tx.messages[0].clone()),
            |tx| tx.messages[0].view_tag[0] ^= 1,
            |tx| tx.messages[0].data[5] ^= 1,
            |tx| {
                tx.messages[0].data.pop();
            },
            |tx| tx.output_slots[0].payload = tx.messages[0].data.clone(),
        ];
        for mutate in mutations {
            let mut changed = transaction.clone();
            mutate(&mut changed);
            assert!(decode(&changed).is_none());
        }
    }

    #[test]
    fn an_unregistered_member_reads_none() {
        let rpc = NullifierRpc::new(Vec::new());
        assert_eq!(read(&rpc).expect("walk"), None);
    }
}
