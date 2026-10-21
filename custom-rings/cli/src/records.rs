//! Member records read while the projection catches up, and the record queue applied once due.

use std::fmt::Display;

use anyhow::{bail, ensure, Result};
use custom_ring_interface::{queue_chain, CustomRingError, QueueEntry, RecordQueue};
use custom_ring_sdk::{CustomRingConfig, MemberRecords, RecordApplication, RingError};
use solana_address::Address;
use solana_signer::Signer;
use zolana_client::{BlockingIndexer, BlockingRpc, Rpc, ZolanaClient};
use zolana_indexer_api::{GetRingRecordQueueRequest, GetRingRecordQueueResponse};
use zolana_ring_client::records::MemberOpeningRead;
use zolana_ring_member_registry::MemberRecord;
use zolana_ring_policy::Member;

use crate::{transact::SENDER_FEE_BUDGET, wait_for, Context, Probe};

pub const NO_MEMBER_REGISTRY: &str =
    "the ring has no member registry, its authority must run `zolana-ring init` first";

#[must_use]
pub(crate) struct Queued {
    tail: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stage {
    Applied,
    Queued,
    Unsent,
}

/// Bound by the on-chain hash chain, read before the applied record they lay over.
pub(crate) struct PendingWrites(Vec<QueueEntry>);

pub(crate) fn read<R: BlockingRpc, I: BlockingIndexer>(
    zolana: &ZolanaClient<R, I>,
    records: MemberRecords<'_>,
) -> Result<Vec<MemberOpeningRead>> {
    let label = format!("the member records of {}", records.ring.program_id());
    patiently(label, || zolana.block_on(records.read(zolana.as_async())))
}

pub(crate) fn read_one<R: BlockingRpc, I: BlockingIndexer>(
    zolana: &ZolanaClient<R, I>,
    records: MemberRecords<'_>,
) -> Result<MemberOpeningRead> {
    let [read] =
        <[_; 1]>::try_from(read(zolana, records)?).map_err(|_| RingError::InvalidRecordOpening)?;
    Ok(read)
}

/// Read again under the newest root while the projection lags the chain.
pub(crate) fn patiently<T>(
    label: impl Display,
    mut read: impl FnMut() -> Result<T, RingError>,
) -> Result<T> {
    wait_for(label, || match read() {
        Ok(value) => Ok(Probe::Ready(value)),
        Err(error) if error.is_projection_lag() => Ok(Probe::Retry(error.into())),
        Err(RingError::MissingMemberRegistry) => bail!(NO_MEMBER_REGISTRY),
        Err(error) => Err(error.into()),
    })
}

impl Queued {
    pub(crate) fn now(ctx: &Context) -> Result<Self> {
        Ok(Self {
            tail: queue(ctx)?.tail(),
        })
    }

    pub(crate) fn apply(self, ctx: &Context, payer: &(dyn Signer + Sync)) -> Result<()> {
        let due = wait_for("the record queue to come due", || {
            let queue = queue(ctx)?;
            if queue.head() >= self.tail {
                return Ok(Probe::Ready(false));
            }
            match queue.apply_due(ctx.rpc().get_slot()?) {
                Ok(()) => Ok(Probe::Ready(true)),
                Err(CustomRingError::ApplyNotDue | CustomRingError::ApplyTooSoon) => {
                    Ok(Probe::NotYet)
                }
                Err(error) => Err(RingError::from(error).into()),
            }
        })?;
        if !due {
            return Ok(());
        }
        match ctx.submit(RecordApplication::new(ctx.ring), payer, &[]) {
            Ok(_) => Ok(()),
            // A rival application can land after the due check.
            Err(_) if queue(ctx)?.head() >= self.tail => Ok(()),
            Err(error) => Err(error),
        }
    }
}

impl PendingWrites {
    /// Read again until the indexer serves the head and tail the chain holds.
    pub(crate) fn read(ctx: &Context) -> Result<Self> {
        wait_for("the indexer to serve the record queue", || {
            let queue = queue(ctx)?;
            let served = ctx
                .zolana
                .indexer()
                .get_ring_record_queue(GetRingRecordQueueRequest {
                    ring_program_id: ctx.ring.program_id().into(),
                })?;
            Ok(match Self::verified(&queue, &served)? {
                Some(pending) => Probe::Ready(pending),
                None => Probe::NotYet,
            })
        })
    }

    /// `None` while the indexer serves another head or tail.
    fn verified(queue: &RecordQueue, served: &GetRingRecordQueueResponse) -> Result<Option<Self>> {
        if served.head != queue.head() || served.tail != queue.tail() {
            return Ok(None);
        }
        let entries: Vec<QueueEntry> = served
            .entries
            .iter()
            .map(|entry| QueueEntry {
                member: entry.member.0,
                mask: entry.mask,
                value: entry.value,
                escrow_key: entry.escrow_key.0,
            })
            .collect();
        let chain = entries
            .iter()
            .try_fold(queue.chain_head, |chain, entry| queue_chain(&chain, entry))?;
        ensure!(
            chain == queue.chain_tail(),
            "the indexer serves record queue writes the chain does not hold"
        );
        Ok(Some(Self(entries)))
    }

    /// The applied record with each pending write of `member` laid over it in queue order.
    pub(crate) fn record_after(
        &self,
        member: &Member,
        applied: Option<&MemberRecord>,
    ) -> MemberRecord {
        let unwritten = MemberRecord {
            member: *member.as_bytes(),
            ..MemberRecord::default()
        };
        self.0
            .iter()
            .filter(|entry| entry.member == *member.as_bytes())
            .fold(applied.copied().unwrap_or(unwritten), |record, entry| {
                record.written(entry)
            })
    }

    pub(crate) fn registers(&self, member: &Member) -> bool {
        self.record_after(member, None).escrow_key != [0; 32]
    }
}

pub(crate) fn insert_fee(config: &CustomRingConfig, writer: &Address) -> u64 {
    config.insert_fee_for(writer).unwrap_or(0)
}

pub(crate) fn write_budget(config: &CustomRingConfig, writer: &Address) -> u64 {
    SENDER_FEE_BUDGET.saturating_add(insert_fee(config, writer))
}

pub(crate) fn queue(ctx: &Context) -> Result<RecordQueue> {
    Ok(ctx.block(ctx.ring.require_queue(ctx.chain()))?)
}

#[cfg(test)]
pub(crate) mod fixtures {
    use std::sync::atomic::{AtomicU8, Ordering};

    use custom_ring_interface::{MemberRegistry, QueueEntry};
    use custom_ring_sdk::CustomRing;
    use solana_account::Account;
    use solana_address::Address;
    use zolana_client::{
        ClientError, GetRingMemberOpeningsResponse, ProverClient, Rpc, WitnessReader,
    };
    use zolana_indexer_api::{
        Base64String, Context as Page, Hash, RingMemberOpening, RingMemberRecordView,
        RingRecordPathView, RingRegistryRootView,
    };
    use zolana_ring_client::SealedNullifierKey;
    use zolana_ring_member_registry::{MemberRegistryTree, RecordOpening, RecordStore, RecordTree};

    use super::*;

    pub(crate) fn ring() -> CustomRing {
        CustomRing::new(Address::new_from_array([9; 32]))
    }

    pub(crate) fn tree(entries: &[QueueEntry]) -> MemberRegistryTree {
        let mut tree = MemberRegistryTree::new().unwrap();
        tree.apply([0; 32], entries).unwrap();
        tree
    }

    /// `sealed` is served only beside a present record.
    pub(crate) struct IndexerAnswer<'a> {
        pub tree: &'a MemberRegistryTree,
        pub member: &'a [u8; 32],
        pub sealed: Option<&'a SealedNullifierKey>,
    }

    impl IndexerAnswer<'_> {
        pub(crate) fn openings(self) -> GetRingMemberOpeningsResponse {
            let (present, record, path) = match self.tree.opening(self.member).unwrap() {
                RecordOpening::Present { record, path } => (true, record, path),
                RecordOpening::Absent { low, path } => (false, low, path),
            };
            let sealed = self.sealed.filter(|_| present);
            GetRingMemberOpeningsResponse {
                context: Page::default(),
                root: RingRegistryRootView {
                    root: Hash(self.tree.root().unwrap()),
                    root_index: 1,
                    applied: 0,
                    next_index: self.tree.next_index().unwrap(),
                },
                openings: vec![RingMemberOpening {
                    present,
                    record: RingMemberRecordView {
                        member: Hash(record.member),
                        next: Hash(record.next),
                        lists: record.lists,
                        escrow_key: Hash(record.escrow_key),
                        owner_pubkey: None,
                        nullifier_pk: None,
                        eph_pk: sealed.map(|key| Base64String(key.eph_pk.as_bytes().to_vec())),
                        ciphertext: sealed.map(|key| Base64String(key.ciphertext.to_vec())),
                    },
                    path: RingRecordPathView {
                        index: path.index,
                        siblings: path.siblings.iter().map(|level| level.map(Hash)).collect(),
                    },
                }],
            }
        }
    }

    /// Serves the registry account, every read after the first under `advanced` when set.
    pub(crate) struct RegistryRpc {
        reads: AtomicU8,
        tree: MemberRegistryTree,
        advanced: Option<MemberRegistryTree>,
    }

    impl RegistryRpc {
        pub(crate) fn of(tree: MemberRegistryTree) -> Self {
            Self {
                reads: AtomicU8::new(0),
                tree,
                advanced: None,
            }
        }

        pub(crate) fn advancing_to(self, advanced: MemberRegistryTree) -> Self {
            Self {
                advanced: Some(advanced),
                ..self
            }
        }

        pub(crate) fn reads(&self) -> u8 {
            self.reads.load(Ordering::Relaxed)
        }
    }

    impl Rpc for RegistryRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            let (expected, bump) =
                Address::find_program_address(&[MemberRegistry::SEED], &ring().program_id());
            assert_eq!(address, expected);
            let reads = self.reads.fetch_add(1, Ordering::Relaxed);
            let tree = match &self.advanced {
                Some(advanced) if reads > 0 => advanced,
                _ => &self.tree,
            };
            let mut registry = MemberRegistry::new(bump, 0);
            registry.push_root(tree.root().unwrap(), 0, 0);
            Ok(Some(Account {
                lamports: 1,
                data: bytemuck::bytes_of(&registry).to_vec(),
                owner: ring().program_id(),
                executable: false,
                rent_epoch: 0,
            }))
        }
    }

    pub(crate) fn zolana<I: Rpc + WitnessReader + Send + Sync + 'static>(
        rpc: RegistryRpc,
        indexer: I,
    ) -> ZolanaClient<RegistryRpc, I> {
        ZolanaClient::new(rpc, indexer, ProverClient::local())
    }
}

#[cfg(test)]
mod tests {
    use zolana_indexer_api::{Context as Page, Hash, RingQueueEntryView};
    use zolana_ring_policy::ListId;

    use super::*;

    fn write(member: u8, mask: u64, value: u64) -> QueueEntry {
        QueueEntry {
            member: *Member::owner_tag(&[member; 32]).unwrap().as_bytes(),
            mask,
            value,
            escrow_key: [0; 32],
        }
    }

    fn served(queue: &RecordQueue, writes: &[QueueEntry]) -> GetRingRecordQueueResponse {
        GetRingRecordQueueResponse {
            context: Page::default(),
            head: queue.head(),
            tail: queue.tail(),
            chain_head: Hash(queue.chain_head),
            entries: (queue.head()..)
                .zip(writes)
                .map(|(position, write)| RingQueueEntryView {
                    position,
                    member: Hash(write.member),
                    mask: write.mask,
                    value: write.value,
                    escrow_key: Hash(write.escrow_key),
                    slot: 1,
                })
                .collect(),
        }
    }

    #[test]
    fn the_served_queue_must_reproduce_the_chain() {
        let bit = ListId::RingViewing.record_bit();
        let writes = [write(1, bit, bit), write(2, bit, 0)];
        let mut queue = RecordQueue::new(0);
        for write in &writes {
            queue.push(write, 1).unwrap();
        }
        let pending = PendingWrites::verified(&queue, &served(&queue, &writes)).unwrap();
        assert_eq!(pending.map(|pending| pending.0), Some(writes.to_vec()));
        let mut forged = writes;
        forged[1].value = bit;
        assert!(PendingWrites::verified(&queue, &served(&queue, &forged)).is_err());
        assert!(PendingWrites::verified(&queue, &served(&queue, &writes[..1])).is_err());
        let mut lagging = served(&queue, &writes[..1]);
        lagging.tail -= 1;
        assert!(PendingWrites::verified(&queue, &lagging).unwrap().is_none());
    }

    #[test]
    fn pending_writes_lay_over_the_applied_record_in_queue_order() {
        let (viewing, recovery) = (
            ListId::RingViewing.record_bit(),
            ListId::Recovery.record_bit(),
        );
        let member = Member::owner_tag(&[1; 32]).unwrap();
        let applied = MemberRecord {
            member: *member.as_bytes(),
            lists: recovery,
            ..MemberRecord::default()
        };
        let (join, leave) = (write(1, viewing, viewing), write(1, viewing, 0));
        let lists = |writes: Vec<QueueEntry>| {
            PendingWrites(writes)
                .record_after(&member, Some(&applied))
                .lists
        };
        assert_eq!(lists(vec![join]), recovery | viewing);
        assert_eq!(lists(vec![join, leave]), recovery);
        assert_eq!(lists(vec![write(2, viewing, viewing)]), recovery);
        let escrow = ListId::Escrow.record_bit();
        let registration = QueueEntry {
            escrow_key: [7; 32],
            ..write(1, escrow, escrow)
        };
        assert!(PendingWrites(vec![join, registration]).registers(&member));
        assert!(!PendingWrites(vec![join]).registers(&member));
        let other = Member::owner_tag(&[2; 32]).unwrap();
        assert!(!PendingWrites(vec![registration]).registers(&other));
    }
}
