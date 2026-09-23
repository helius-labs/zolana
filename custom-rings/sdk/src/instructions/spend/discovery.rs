use solana_address::Address;
use zolana_client::{indexer::decode_shielded_transaction, AsyncRpc, ClientError, Rpc};
use zolana_indexer_api::{Hash, RingSpendRecord, RingSpendRecordRequest, SerializablePubkey};
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
    /// Its leaf hashes under the id of the tree it landed in.
    pub tree_id: u16,
    pub leaf_index: u64,
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
    pub address_tree_id: u16,
    pub member: Member,
}

impl ReadSpendRecord {
    /// `None` until the member registers.
    pub fn read_current<I: Rpc, R: Rpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<Option<LiveSpendRecord>, EntryProofError> {
        let Some(record) = env.indexer.get_ring_spend_record(self.request())?.record else {
            return Ok(None);
        };
        let live = self.decode_current(record)?;
        let spent = env.rpc.get_account(Self::nullifier_pda(&live))?;
        live_unless_spent(live, spent)
    }

    pub async fn read_current_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        env: ReadEnvironment<'_, I, R>,
    ) -> Result<Option<LiveSpendRecord>, EntryProofError> {
        let Some(record) = env
            .indexer
            .get_ring_spend_record(self.request())
            .await?
            .record
        else {
            return Ok(None);
        };
        let live = self.decode_current(record)?;
        let spent = env.rpc.get_account(Self::nullifier_pda(&live)).await?;
        live_unless_spent(live, spent)
    }

    fn nullifier_pda(live: &LiveSpendRecord) -> Address {
        zolana_interface::pda::nullifier_pda(
            &zolana_interface::pda::tree(live.tree_id),
            &live.nullifier,
        )
        .0
    }

    /// Unauthenticated history, unsuitable for transfer preparation.
    pub fn read<I: Rpc>(self, indexer: &I) -> Result<Option<LiveSpendRecord>, EntryProofError> {
        let lookup = self.lookup()?;
        let lineages = Lineages { lookups: &[lookup] }.fetch(indexer)?;
        Ok(lineages.into_iter().next().flatten())
    }

    pub async fn read_async<I: AsyncRpc>(
        self,
        indexer: &I,
    ) -> Result<Option<LiveSpendRecord>, EntryProofError> {
        let lookup = self.lookup()?;
        let lineages = Lineages { lookups: &[lookup] }.fetch_async(indexer).await?;
        Ok(lineages.into_iter().next().flatten())
    }

    fn request(&self) -> RingSpendRecordRequest {
        RingSpendRecordRequest {
            ring_program_id: SerializablePubkey::from(self.ring.program_id().to_bytes()),
            member: Hash(*self.member.as_bytes()),
        }
    }

    /// The record must decode for the requested member under its spend address.
    fn decode_current(&self, record: RingSpendRecord) -> Result<LiveSpendRecord, EntryProofError> {
        let transaction = decode_shielded_transaction(record.transaction)?;
        let slot = transaction
            .output_slots
            .get(usize::from(record.output_index))
            .ok_or(EntryProofError::InvalidSpendRecord)?;
        let lookup = self.lookup()?;
        lookup
            .decode(
                &lookup.address()?,
                SpentSlot {
                    transaction: &transaction,
                    slot,
                },
            )
            .ok_or(EntryProofError::InvalidSpendRecord)
    }

    pub(crate) fn lookup(&self) -> Result<SpendLookup, EntryProofError> {
        let owner = ListNamespace::new(self.ring.namespace_pda().as_array())
            .map_err(|_| EntryProofError::Hashing)?;
        Ok(SpendLookup {
            owner,
            member: self.member,
            address_tree_id: self.address_tree_id,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SpendLookup {
    pub owner: ListNamespace,
    pub member: Member,
    pub address_tree_id: u16,
}

impl LineageLookup for SpendLookup {
    type Live = LiveSpendRecord;

    fn address(&self) -> Result<[u8; 32], EntryProofError> {
        self.owner
            .spend_address(&self.member, self.address_tree_id)
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
        let tree_id = slot.output_context.tree_id;
        let utxo_hash = record.utxo_hash(&self.owner, address, tree_id).ok()?;
        if utxo_hash != slot.output_context.hash {
            return None;
        }
        let nullifier = entry_nullifier(&utxo_hash, &record.blinding).ok()?;
        Some(LiveSpendRecord {
            record,
            utxo_hash,
            nullifier,
            tree_id,
            leaf_index: slot.output_context.leaf_index,
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

/// A spent record means the projection has not reached its successor.
fn live_unless_spent<A>(
    live: LiveSpendRecord,
    nullifier_pda: Option<A>,
) -> Result<Option<LiveSpendRecord>, EntryProofError> {
    if nullifier_pda.is_some() {
        return Err(ClientError::RingSpendRecordOutOfSync.into());
    }
    Ok(Some(live))
}

#[cfg(test)]
mod tests {
    use zolana_client::{OutputContext, OutputSlot, ShieldedTransaction};
    use zolana_ring_policy::SpendCounters;
    use zolana_transaction::{
        serialization::confidential::{
            Confidential, ConfidentialEncode, ConfidentialOutputPlaintext,
        },
        Data, UtxoSerialization,
    };

    use super::*;
    use crate::instructions::entry::discovery::tests::NullifierRpc;

    const ADDRESS_TREE_ID: u16 = 7;
    const SECOND_TREE_ID: u16 = 9;

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
        version_in(version, ADDRESS_TREE_ID)
    }

    /// The record's address stays in the address tree, its leaf hashes under `tree_id`.
    fn version_in(version: u64, tree_id: u16) -> (SpendRecord, [u8; 32], [u8; 32]) {
        let record = SpendRecord {
            member: member(),
            version,
            window: 3,
            counters_commitment: SpendCounters::EMPTY.commitment().expect("commitment"),
            blinding: [version as u8 + 1; 32],
        };
        let address = owner()
            .spend_address(&member(), ADDRESS_TREE_ID)
            .expect("address");
        let utxo_hash = record.utxo_hash(&owner(), &address, tree_id).expect("leaf");
        (
            record,
            utxo_hash,
            entry_nullifier(&utxo_hash, &record.blinding).expect("nullifier"),
        )
    }

    fn spender(spent: [u8; 32], record: &SpendRecord, utxo_hash: [u8; 32]) -> ShieldedTransaction {
        spender_in(spent, record, utxo_hash, ADDRESS_TREE_ID)
    }

    fn spender_in(
        spent: [u8; 32],
        record: &SpendRecord,
        utxo_hash: [u8; 32],
        tree_id: u16,
    ) -> ShieldedTransaction {
        let mut payload = record.to_output_data().to_vec();
        let mut messages = Vec::new();
        let tx_key = zolana_keypair::ViewingKey::new();
        if record.version != 0 {
            payload = Confidential::encode_plaintext(
                &ConfidentialOutputPlaintext {
                    asset_id: zolana_transaction::SOL_ASSET_ID,
                    amount: 0,
                    blinding: record.blinding,
                    ring_program_id: None,
                    data: Data::default(),
                },
                namespace().to_bytes(),
                &ConfidentialEncode {
                    tx: tx_key.clone(),
                    recipient_pubkey: tx_key.pubkey(),
                    salt: [9; SALT_LEN],
                    slot_index: 0,
                },
            )
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
            event_index: Some(0),
            tx_viewing_pk: Some(tx_key.pubkey()),
            salt: Some([9u8; SALT_LEN]),
            output_slots: vec![OutputSlot {
                view_tag: namespace().to_bytes(),
                output_context: OutputContext {
                    hash: utxo_hash,
                    tree_id,
                    leaf_index: record.version,
                },
                payload,
            }],
            messages,
            nullifiers: vec![spent],
            proofless: false,
            ring_config: None,
            ring_program_id: None,
        }
    }

    fn read(rpc: &NullifierRpc) -> Result<Option<LiveSpendRecord>, EntryProofError> {
        ReadSpendRecord {
            ring: ring(),
            address_tree_id: ADDRESS_TREE_ID,
            member: member(),
        }
        .read(rpc)
    }

    #[test]
    fn the_walk_returns_the_live_version_with_its_origin() {
        let address = owner()
            .spend_address(&member(), ADDRESS_TREE_ID)
            .expect("address");
        let (first, first_hash, first_nullifier) = version(0);
        let (second, second_hash, second_nullifier) = version(1);
        let rpc = NullifierRpc::new(vec![
            spender(address, &first, first_hash),
            spender(first_nullifier, &second, second_hash),
        ]);
        let live = read(&rpc).expect("walk").expect("registered");
        assert_eq!(live.record, second);
        assert_eq!(live.nullifier, second_nullifier);
        assert_eq!(live.leaf_index, 1);
        assert_eq!(live.origin.first_nullifier, first_nullifier);
        assert_eq!(live.origin.salt, Some([9u8; SALT_LEN]));
        assert_eq!(live.origin.messages.len(), 2);
    }

    #[test]
    fn a_record_moved_to_another_tree_hashes_under_its_own_tree() {
        let address = owner()
            .spend_address(&member(), ADDRESS_TREE_ID)
            .expect("address");
        let (first, first_hash, first_nullifier) = version(0);
        let (second, second_hash, second_nullifier) = version_in(1, SECOND_TREE_ID);
        let rpc = NullifierRpc::new(vec![
            spender(address, &first, first_hash),
            spender_in(first_nullifier, &second, second_hash, SECOND_TREE_ID),
        ]);
        let live = read(&rpc).expect("walk").expect("registered");
        assert_eq!(live.record, second);
        assert_eq!(live.tree_id, SECOND_TREE_ID);
        assert_eq!(live.nullifier, second_nullifier);

        let misplaced = NullifierRpc::new(vec![
            spender(address, &first, first_hash),
            spender_in(first_nullifier, &second, second_hash, ADDRESS_TREE_ID),
        ]);
        assert!(matches!(
            read(&misplaced),
            Err(EntryProofError::BrokenSpendLineage { version: 1, .. })
        ));
    }

    #[test]
    fn the_lag_check_reads_the_nullifier_pda_of_the_records_own_tree() {
        let address = owner().spend_address(&member(), ADDRESS_TREE_ID).unwrap();
        let (record, hash, nullifier) = version_in(1, SECOND_TREE_ID);
        let transaction = spender_in(address, &record, hash, SECOND_TREE_ID);
        let live = ReadSpendRecord {
            ring: ring(),
            address_tree_id: ADDRESS_TREE_ID,
            member: member(),
        }
        .lookup()
        .unwrap()
        .decode(
            &address,
            SpentSlot {
                transaction: &transaction,
                slot: &transaction.output_slots[0],
            },
        )
        .expect("decoded");
        let pda = |tree_id| {
            zolana_interface::pda::nullifier_pda(&zolana_interface::pda::tree(tree_id), &nullifier)
                .0
        };
        assert_eq!(ReadSpendRecord::nullifier_pda(&live), pda(SECOND_TREE_ID));
        assert_ne!(ReadSpendRecord::nullifier_pda(&live), pda(ADDRESS_TREE_ID));
    }

    #[test]
    fn a_successor_requires_one_bound_public_record_message() {
        let (record, hash, _) = version(1);
        let address = owner().spend_address(&member(), ADDRESS_TREE_ID).unwrap();
        let transaction = spender(address, &record, hash);
        let lookup = SpendLookup {
            owner: owner(),
            member: member(),
            address_tree_id: ADDRESS_TREE_ID,
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

    fn indexed_genesis() -> RingSpendRecord {
        let (record, hash, _) = version(0);
        let address = owner()
            .spend_address(&member(), ADDRESS_TREE_ID)
            .expect("address");
        RingSpendRecord {
            output_index: 0,
            transaction: zolana_indexer_api::ShieldedTransaction {
                slot: 2,
                tx_signature: Default::default(),
                event_index: Some(0),
                tx_viewing_pk: None,
                salt: None,
                output_slots: vec![zolana_indexer_api::RingsOutputSlot {
                    view_tag: Hash(namespace().to_bytes()),
                    payload: zolana_indexer_api::Base64String(record.to_output_data().to_vec()),
                    output_context: zolana_indexer_api::RingsOutputContext {
                        hash: Hash(hash),
                        tree: SerializablePubkey::from(
                            zolana_interface::pda::tree(ADDRESS_TREE_ID).to_bytes(),
                        ),
                        tree_id: ADDRESS_TREE_ID,
                        leaf_index: 7,
                    },
                }],
                messages: Vec::new(),
                nullifiers: vec![Hash(address)],
                proofless: false,
                ring_config: None,
                ring_program_id: None,
            },
        }
    }

    fn current(member: Member) -> ReadSpendRecord {
        ReadSpendRecord {
            ring: ring(),
            address_tree_id: ADDRESS_TREE_ID,
            member,
        }
    }

    #[test]
    fn the_indexed_record_decodes_for_the_requested_member() {
        let (record, _, nullifier) = version(0);
        let live = current(member())
            .decode_current(indexed_genesis())
            .expect("current");
        assert_eq!(live.record, record);
        assert_eq!(live.nullifier, nullifier);
        assert_eq!(live.leaf_index, 7);
    }

    #[test]
    fn a_substituted_record_is_refused() {
        let other = Member::owner_tag(&[6u8; 32]).expect("member");
        assert!(matches!(
            current(other).decode_current(indexed_genesis()),
            Err(EntryProofError::InvalidSpendRecord)
        ));
        let mutations: [fn(&mut RingSpendRecord); 3] = [
            |record| record.output_index = 1,
            |record| record.transaction.output_slots[0].output_context.hash.0[31] ^= 1,
            |record| record.transaction.output_slots[0].output_context.tree_id ^= 1,
        ];
        for mutate in mutations {
            let mut record = indexed_genesis();
            mutate(&mut record);
            assert!(matches!(
                current(member()).decode_current(record),
                Err(EntryProofError::InvalidSpendRecord)
            ));
        }
    }

    #[test]
    fn an_unregistered_member_reads_none() {
        let rpc = NullifierRpc::new(Vec::new());
        assert_eq!(read(&rpc).expect("walk"), None);
    }
}
