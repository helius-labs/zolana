//! A claim spends the pair's address and every update spends the version
//! before it, content is trusted only after it reproduces the on-chain
//! commitment.

use solana_address::Address;
use zolana_client::{
    rpc::GetShieldedTransactionsByNullifiersResponse, AsyncRpc, OutputSlot, Rpc,
    ShieldedTransaction,
};
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

#[must_use]
pub struct ReadEntry {
    pub entries_tree: Address,
    pub namespace: Address,
    pub list_id: ListId,
    pub member: Member,
}

impl ReadEntry {
    /// `None` when the address was never claimed, a cleared entry still reads back.
    pub fn read<I: Rpc>(self, indexer: &I) -> Result<Option<LiveEntry>, EntryProofError> {
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
    ) -> Result<Option<LiveEntry>, EntryProofError> {
        let lookup = self.lookup()?;
        let lineages = Lineages {
            entries_tree: self.entries_tree,
            lookups: &[lookup],
        }
        .fetch_async(indexer)
        .await?;
        Ok(lineages.into_iter().next().flatten())
    }

    fn lookup(&self) -> Result<EntryLookup, EntryProofError> {
        let owner =
            ListNamespace::new(self.namespace.as_array()).map_err(|_| EntryProofError::Hashing)?;
        Ok(EntryLookup {
            owner,
            list_id: self.list_id,
            member: self.member,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EntryLookup {
    pub owner: ListNamespace,
    pub list_id: ListId,
    pub member: Member,
}

impl EntryLookup {
    pub(crate) fn address(&self) -> Result<[u8; 32], EntryProofError> {
        self.owner
            .address(self.list_id, &self.member)
            .map_err(|_| EntryProofError::Hashing)
    }

    fn decode(&self, address: &[u8; 32], slot: &OutputSlot) -> Option<LiveEntry> {
        let OutputDataEncoding::Plaintext(content) = slot.output_data()? else {
            return None;
        };
        let entry = ListEntry::from_entry_bytes(&content)?;
        if entry.list_id != self.list_id || entry.member != self.member {
            return None;
        }
        let utxo_hash = entry.utxo_hash(&self.owner, address).ok()?;
        if utxo_hash != slot.output_context.hash {
            return None;
        }
        let nullifier = entry_nullifier(&utxo_hash, &entry.blinding()).ok()?;
        Some(LiveEntry {
            entry,
            utxo_hash,
            nullifier,
        })
    }
}

pub(crate) struct Lineages<'a> {
    pub entries_tree: Address,
    pub lookups: &'a [EntryLookup],
}

impl Lineages<'_> {
    /// One entry per lookup, in order.
    pub(crate) fn fetch<I: Rpc>(
        self,
        indexer: &I,
    ) -> Result<Vec<Option<LiveEntry>>, EntryProofError> {
        let mut walk = LineageWalk::start(self)?;
        while let Some(query) = walk.query() {
            let page = indexer.get_shielded_transactions_by_nullifiers(
                query.nullifiers,
                query.cursor,
                None,
                None,
            )?;
            walk.absorb(page)?;
        }
        Ok(walk.finish())
    }

    pub(crate) async fn fetch_async<I: AsyncRpc>(
        self,
        indexer: &I,
    ) -> Result<Vec<Option<LiveEntry>>, EntryProofError> {
        let mut walk = LineageWalk::start(self)?;
        while let Some(query) = walk.query() {
            let page = indexer
                .get_shielded_transactions_by_nullifiers(query.nullifiers, query.cursor, None, None)
                .await?;
            walk.absorb(page)?;
        }
        Ok(walk.finish())
    }
}

struct LineageQuery {
    nullifiers: Vec<[u8; 32]>,
    cursor: Option<Vec<u8>>,
}

/// Every pending lineage advances one version per round, a round ends when the
/// indexer returns its last page.
struct LineageWalk<'a> {
    entries_tree: Address,
    heads: Vec<Head<'a>>,
    cursor: Option<Vec<u8>>,
    spenders: Vec<ShieldedTransaction>,
}

struct Head<'a> {
    lookup: &'a EntryLookup,
    address: [u8; 32],
    live: Option<LiveEntry>,
    nullifier: [u8; 32],
    ended: bool,
}

impl<'a> LineageWalk<'a> {
    fn start(lineages: Lineages<'a>) -> Result<Self, EntryProofError> {
        let heads = lineages
            .lookups
            .iter()
            .map(|lookup| {
                let address = lookup.address()?;
                Ok(Head {
                    lookup,
                    address,
                    live: None,
                    nullifier: address,
                    ended: false,
                })
            })
            .collect::<Result<Vec<_>, EntryProofError>>()?;
        Ok(Self {
            entries_tree: lineages.entries_tree,
            heads,
            cursor: None,
            spenders: Vec::new(),
        })
    }

    fn query(&self) -> Option<LineageQuery> {
        let nullifiers: Vec<[u8; 32]> = self
            .heads
            .iter()
            .filter(|head| !head.ended)
            .map(|head| head.nullifier)
            .collect();
        (!nullifiers.is_empty()).then(|| LineageQuery {
            nullifiers,
            cursor: self.cursor.clone(),
        })
    }

    fn absorb(
        &mut self,
        page: GetShieldedTransactionsByNullifiersResponse,
    ) -> Result<(), EntryProofError> {
        self.spenders.extend(page.transactions);
        // A terminal page still names a cursor, only `scanned_through` ends the round.
        self.cursor = if page.scanned_through.is_some() {
            None
        } else {
            page.next_cursor
        };
        if self.cursor.is_some() {
            return Ok(());
        }
        let spenders = core::mem::take(&mut self.spenders);
        self.advance(&spenders)
    }

    fn advance(&mut self, spenders: &[ShieldedTransaction]) -> Result<(), EntryProofError> {
        for head in self.heads.iter_mut().filter(|head| !head.ended) {
            let Some(spender) = spenders
                .iter()
                .find(|spender| spender.nullifiers.contains(&head.nullifier))
            else {
                head.ended = true;
                continue;
            };
            let successor = spender
                .output_slots
                .iter()
                .filter(|slot| slot.output_context.tree == self.entries_tree)
                .find_map(|slot| head.lookup.decode(&head.address, slot));
            let Some(successor) = successor else {
                return Err(EntryProofError::BrokenLineage {
                    list_id: head.lookup.list_id,
                    member: *head.lookup.member.as_bytes(),
                    version: head
                        .live
                        .map_or(0, |live| live.entry.version.saturating_add(1)),
                });
            };
            head.nullifier = successor.nullifier;
            head.live = Some(successor);
        }
        Ok(())
    }

    fn finish(self) -> Vec<Option<LiveEntry>> {
        self.heads.into_iter().map(|head| head.live).collect()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Mutex;

    use async_trait::async_trait;
    use solana_signature::Signature;
    use zolana_client::{ClientError, Context, OutputContext};
    use zolana_ring_policy::EntryState;

    use super::*;

    pub(crate) fn tree() -> Address {
        Address::new_from_array([7u8; 32])
    }

    pub(crate) fn namespace() -> Address {
        Address::new_from_array([8u8; 32])
    }

    pub(crate) fn owner() -> ListNamespace {
        ListNamespace::new(namespace().as_array()).expect("owner")
    }

    pub(crate) fn member(byte: u8) -> Member {
        Member::owner_tag(&[byte; 32]).expect("member")
    }

    pub(crate) fn lookup(list_id: ListId, member: Member) -> EntryLookup {
        EntryLookup {
            owner: owner(),
            list_id,
            member,
        }
    }

    pub(crate) struct Lineage {
        pub lookup: EntryLookup,
        pub versions: Vec<LiveEntry>,
    }

    impl Lineage {
        pub(crate) fn new(lookup: EntryLookup, states: &[EntryState]) -> Self {
            let address = lookup.address().expect("address");
            let versions = states
                .iter()
                .enumerate()
                .map(|(version, state)| {
                    let entry = ListEntry {
                        list_id: lookup.list_id,
                        member: lookup.member,
                        state: *state,
                        version: version as u64,
                        content_hash: [0u8; 32],
                    };
                    let utxo_hash = entry.utxo_hash(&lookup.owner, &address).expect("hash");
                    LiveEntry {
                        entry,
                        utxo_hash,
                        nullifier: entry_nullifier(&utxo_hash, &entry.blinding())
                            .expect("nullifier"),
                    }
                })
                .collect();
            Self { lookup, versions }
        }

        pub(crate) fn address(&self) -> [u8; 32] {
            self.lookup.address().expect("address")
        }

        pub(crate) fn live(&self) -> Option<LiveEntry> {
            self.versions.last().copied()
        }

        pub(crate) fn spender(&self, index: usize, tree: Address) -> ShieldedTransaction {
            let spent = match index {
                0 => self.address(),
                _ => self.versions[index - 1].nullifier,
            };
            transaction(spent, vec![slot(&self.versions[index], tree)])
        }

        pub(crate) fn spenders(&self, tree: Address) -> Vec<ShieldedTransaction> {
            (0..self.versions.len())
                .map(|index| self.spender(index, tree))
                .collect()
        }
    }

    pub(crate) fn slot(live: &LiveEntry, tree: Address) -> OutputSlot {
        OutputSlot {
            view_tag: namespace().to_bytes(),
            output_context: OutputContext {
                hash: live.utxo_hash,
                tree,
                leaf_index: live.entry.version,
            },
            payload: live.entry.to_output_data().to_vec(),
        }
    }

    pub(crate) fn transaction(
        spent: [u8; 32],
        output_slots: Vec<OutputSlot>,
    ) -> ShieldedTransaction {
        ShieldedTransaction {
            slot: 0,
            tx_signature: Signature::default(),
            tx_viewing_pk: None,
            salt: None,
            output_slots,
            messages: Vec::new(),
            nullifiers: vec![spent],
            proofless: false,
        }
    }

    /// Serves the spenders by nullifier, every other query is refused.
    pub(crate) struct NullifierRpc {
        pub spenders: Vec<ShieldedTransaction>,
        pub page_size: Option<usize>,
        pub requests: Mutex<Vec<Vec<[u8; 32]>>>,
    }

    impl NullifierRpc {
        pub(crate) fn new(spenders: Vec<ShieldedTransaction>) -> Self {
            Self {
                spenders,
                page_size: None,
                requests: Mutex::new(Vec::new()),
            }
        }

        fn page(
            &self,
            nullifiers: Vec<[u8; 32]>,
            cursor: Option<Vec<u8>>,
        ) -> GetShieldedTransactionsByNullifiersResponse {
            self.requests
                .lock()
                .expect("requests")
                .push(nullifiers.clone());
            let matching: Vec<ShieldedTransaction> = self
                .spenders
                .iter()
                .filter(|spender| {
                    spender
                        .nullifiers
                        .iter()
                        .any(|nullifier| nullifiers.contains(nullifier))
                })
                .cloned()
                .collect();
            let start = cursor.map_or(0, |cursor| usize::from(cursor[0]));
            let end = self
                .page_size
                .map_or(matching.len(), |size| (start + size).min(matching.len()));
            let rows = matching[start..end].to_vec();
            // Photon treats a full page as truncated and names a cursor on any row.
            let truncated = self.page_size.is_some_and(|size| rows.len() >= size);
            GetShieldedTransactionsByNullifiersResponse {
                context: Context {
                    block_time: 0,
                    slot: 0,
                },
                next_cursor: (!rows.is_empty()).then(|| vec![end as u8]),
                scanned_through: (!truncated).then(|| vec![end as u8]),
                transactions: rows,
            }
        }
    }

    impl Rpc for NullifierRpc {
        fn get_shielded_transactions_by_nullifiers(
            &self,
            nullifiers: Vec<[u8; 32]>,
            cursor: Option<Vec<u8>>,
            _limit: Option<u32>,
            _config: Option<zolana_client::IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            Ok(self.page(nullifiers, cursor))
        }
    }

    #[async_trait]
    impl AsyncRpc for NullifierRpc {
        async fn get_shielded_transactions_by_nullifiers(
            &self,
            nullifiers: Vec<[u8; 32]>,
            cursor: Option<Vec<u8>>,
            _limit: Option<u32>,
            _config: Option<zolana_client::IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            Ok(self.page(nullifiers, cursor))
        }
    }

    fn read(lookup: EntryLookup, rpc: &NullifierRpc) -> Result<Option<LiveEntry>, EntryProofError> {
        ReadEntry {
            entries_tree: tree(),
            namespace: namespace(),
            list_id: lookup.list_id,
            member: lookup.member,
        }
        .read(rpc)
    }

    #[test]
    fn an_unclaimed_address_reads_none_after_one_nullifier_request() {
        let lookup = lookup(ListId::Allow, member(1));
        let rpc = NullifierRpc::new(Vec::new());
        assert_eq!(read(lookup, &rpc).expect("unclaimed"), None);
        assert_eq!(
            *rpc.requests.lock().expect("requests"),
            vec![vec![lookup.address().expect("address")]]
        );
    }

    #[test]
    fn a_lineage_is_walked_one_version_per_request_and_skips_foreign_trees() {
        let lineage = Lineage::new(
            lookup(ListId::Allow, member(1)),
            &[EntryState::Active, EntryState::Cleared, EntryState::Active],
        );
        let mut spenders = lineage.spenders(tree());
        // A foreign tree republishes version 1 under version 0's nullifier.
        let foreign = Address::new_from_array([9u8; 32]);
        spenders[1]
            .output_slots
            .insert(0, slot(&lineage.versions[1], foreign));
        let rpc = NullifierRpc::new(spenders);
        let live = read(lineage.lookup, &rpc)
            .expect("walk")
            .expect("live version");
        assert_eq!(live, lineage.versions[2]);
        assert_eq!(live.entry.version, 2);
        assert_eq!(
            *rpc.requests.lock().expect("requests"),
            vec![
                vec![lineage.address()],
                vec![lineage.versions[0].nullifier],
                vec![lineage.versions[1].nullifier],
                vec![lineage.versions[2].nullifier],
            ]
        );
    }

    #[test]
    fn the_async_walk_reads_the_same_version() {
        let lineage = Lineage::new(
            lookup(ListId::Block, member(2)),
            &[EntryState::Active, EntryState::Cleared],
        );
        let rpc = NullifierRpc::new(lineage.spenders(tree()));
        let live = futures::executor::block_on(
            ReadEntry {
                entries_tree: tree(),
                namespace: namespace(),
                list_id: ListId::Block,
                member: member(2),
            }
            .read_async(&rpc),
        )
        .expect("walk");
        assert_eq!(live, lineage.live());
    }

    #[test]
    fn a_round_follows_the_cursor_across_pages() {
        let first = Lineage::new(lookup(ListId::Allow, member(1)), &[EntryState::Active]);
        let second = Lineage::new(lookup(ListId::Allow, member(2)), &[EntryState::Active]);
        let mut spenders = first.spenders(tree());
        spenders.extend(second.spenders(tree()));
        let mut rpc = NullifierRpc::new(spenders);
        rpc.page_size = Some(1);
        let lookups = [first.lookup, second.lookup];
        let lineages = Lineages {
            entries_tree: tree(),
            lookups: &lookups,
        }
        .fetch(&rpc)
        .expect("walk");
        assert_eq!(lineages, vec![first.live(), second.live()]);
        // Two full claim pages end on an empty third, the next round is one empty page.
        assert_eq!(rpc.requests.lock().expect("requests").len(), 4);
    }

    #[test]
    fn a_spender_without_a_successor_breaks_the_lineage() {
        let lineage = Lineage::new(
            lookup(ListId::Frozen, member(3)),
            &[EntryState::Active, EntryState::Cleared],
        );
        let mut spenders = lineage.spenders(tree());
        spenders[1].output_slots.clear();
        let rpc = NullifierRpc::new(spenders);
        assert!(matches!(
            read(lineage.lookup, &rpc),
            Err(EntryProofError::BrokenLineage {
                list_id: ListId::Frozen,
                version: 1,
                ..
            })
        ));
    }

    #[test]
    fn a_tampered_payload_is_not_decoded() {
        let lineage = Lineage::new(lookup(ListId::Allow, member(4)), &[EntryState::Active]);
        let live = lineage.versions[0];
        let address = lineage.address();
        let genuine = slot(&live, tree());
        assert_eq!(lineage.lookup.decode(&address, &genuine), Some(live));
        let mut tampered = genuine.clone();
        // Flipping the state byte breaks the commitment.
        tampered.payload[38] = EntryState::Cleared as u8;
        assert_eq!(lineage.lookup.decode(&address, &tampered), None);
        let mut wrong_pair = genuine;
        wrong_pair.payload[5] = ListId::Block as u8;
        assert_eq!(lineage.lookup.decode(&address, &wrong_pair), None);
    }
}
