//! Registry records, read under a root and applied by a due application or an authority write.

use std::collections::BTreeMap;

use custom_ring_interface::{
    key_catalog::RingCircuit, queue_chain, tag, ApplyRecordsIxData, AuthorityWriteRecordsIxData,
    CustomRingError, MemberRegistry, MemberWriteIxData, QueueEntry, RecordQueue, RecordWriteData,
    WriteRecordsIxData, APPLY_BATCH,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_client::{AsyncIndexer, AsyncRpc, AsyncZolanaClient};
use zolana_indexer_api::{
    GetRingApplyProofInputsRequest, GetRingMemberOpeningsRequest, Hash, RingListWriteView,
    MAX_RING_MEMBER_PAGE_LIMIT,
};
use zolana_interface::SYSTEM_PROGRAM_ID;
use zolana_ring_client::records::{apply_proof_inputs, EscrowedRecord, MemberOpeningRead};
use zolana_ring_member_registry::ApplyProofInputs;
use zolana_ring_policy::{ListSet, ListWrite, Member, Writer};

use crate::{
    projection::retry_projection_lag,
    prover::{to_instruction_proof, RingRequest},
    request::{ApplyRecords, RecordWrite},
    submission::BoundRoot,
    CustomRing, CustomRingConfig, RingError,
};

/// Members' records under the registry's current root.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberRecords<'a> {
    pub ring: CustomRing,
    pub members: &'a [Member],
}

impl MemberRecords<'_> {
    /// One opening per member in member order, each verified against the root.
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Vec<MemberOpeningRead>, RingError> {
        let members: Vec<[u8; 32]> = self
            .members
            .iter()
            .map(|member| *member.as_bytes())
            .collect();
        RecordReads {
            root: BoundRoot::newest(self.ring, rpc).await?,
            members: &members,
        }
        .read(rpc)
        .await
    }
}

pub(crate) type OpeningsByMember = BTreeMap<[u8; 32], MemberOpeningRead>;

pub(crate) struct RecordReads<'a> {
    pub root: BoundRoot,
    pub members: &'a [[u8; 32]],
}

impl RecordReads<'_> {
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Vec<MemberOpeningRead>, RingError> {
        let BoundRoot { ring, root, .. } = self.root;
        let mut reads = Vec::with_capacity(self.members.len());
        for chunk in self.members.chunks(MAX_RING_MEMBER_PAGE_LIMIT as usize) {
            let response = rpc
                .get_ring_member_openings(GetRingMemberOpeningsRequest {
                    ring_program_id: ring.program_id().into(),
                    members: chunk.iter().copied().map(Hash).collect(),
                    expected_root: Hash(root),
                })
                .await?;
            if response.openings.len() != chunk.len() {
                return Err(RingError::InvalidRecordOpening);
            }
            for (member, view) in chunk.iter().zip(&response.openings) {
                reads.push(MemberOpeningRead::verify(view, &root, member)?);
            }
        }
        Ok(reads)
    }

    pub async fn read_keyed(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<OpeningsByMember, RingError> {
        let members = self.members;
        Ok(members.iter().copied().zip(self.read(rpc).await?).collect())
    }
}

pub(crate) struct MemberRead {
    pub root: BoundRoot,
    pub member: [u8; 32],
}

impl MemberRead {
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<MemberOpeningRead, RingError> {
        RecordReads {
            root: self.root,
            members: core::slice::from_ref(&self.member),
        }
        .read(rpc)
        .await?
        .pop()
        .ok_or(RingError::InvalidRecordOpening)
    }
}

/// A member's opening read under a root the statement binds.
pub(crate) struct OwnerRead<'a> {
    pub owner: [u8; 32],
    pub read: &'a MemberOpeningRead,
}

impl<'a> OwnerRead<'a> {
    /// Refuses an owner whose record escrows no key for `nullifier_pk`.
    pub fn escrowed(self, nullifier_pk: &[u8; 32]) -> Result<EscrowedRecord<'a>, RingError> {
        match self.read.escrowed(nullifier_pk)? {
            Some(escrowed) => Ok(escrowed),
            None => Err(RingError::UnregisteredOutputKey {
                owner: Member::from_bytes(self.owner)?,
            }),
        }
    }
}

/// A member's write of its own lists, queued without a proof.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberListWrite {
    pub ring: CustomRing,
    /// Pays the insert fee the config charges a member.
    pub payer: Address,
    pub member: Address,
    pub lists: ListWrite,
}

impl MemberListWrite {
    pub fn instruction(self, config: &CustomRingConfig) -> Result<Instruction, RingError> {
        check_writer(self.lists, Writer::Member)?;
        let write = MemberWrite {
            ring: self.ring,
            config,
            member: self.member,
            payer: self.payer,
        };
        let mut data = vec![tag::WRITE_RECORDS];
        data.extend_from_slice(bytemuck::bytes_of(&MemberWriteIxData {
            lists: WriteRecordsIxData::new(self.lists),
            max_fee: write.max_fee(),
        }));
        Ok(Instruction {
            program_id: self.ring.program_id(),
            accounts: write.metas(),
            data,
        })
    }
}

/// Applied in one proof together with every pending member write.
#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityListWrite {
    ring: CustomRing,
    authority: Address,
    writes: Vec<(Member, ListWrite)>,
}

#[must_use]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenRecordWrite {
    pub instruction: Instruction,
    pub(crate) bound: BoundQueue,
}

/// A later write or application moves the queue and root the statement binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BoundQueue {
    pub ring: CustomRing,
    pub tail: u64,
    pub chain_tail: [u8; 32],
    pub root: [u8; 32],
}

impl AuthorityListWrite {
    pub fn new(ring: CustomRing, authority: Address) -> Self {
        Self {
            ring,
            authority,
            writes: Vec::new(),
        }
    }

    /// `member` is any record key, an owner identity or an asset.
    pub fn with_write(mut self, member: Member, write: ListWrite) -> Result<Self, RingError> {
        check_writer(write, Writer::Authority)?;
        if self.writes.iter().any(|(known, _)| *known == member) {
            return Err(RingError::DuplicateListWrite { member });
        }
        self.writes.push((member, write));
        Ok(self)
    }

    pub fn writes(&self) -> &[(Member, ListWrite)] {
        &self.writes
    }

    /// The first batch takes the room `pending` member writes leave.
    pub fn batches(&self, pending: u64) -> Vec<Self> {
        let first = APPLY_BATCH.saturating_sub(usize::try_from(pending).unwrap_or(APPLY_BATCH));
        let mut rest = self.writes.as_slice();
        let mut batches = Vec::new();
        let mut size = first;
        while !rest.is_empty() {
            // A full member share leaves the first batch empty, the writes start in the next.
            let (batch, tail) = rest.split_at(size.min(rest.len()));
            if !batch.is_empty() {
                batches.push(Self {
                    ring: self.ring,
                    authority: self.authority,
                    writes: batch.to_vec(),
                });
            }
            rest = tail;
            size = APPLY_BATCH;
        }
        batches
    }

    /// One batch against the registry and queue as the chain holds them.
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<ProvenRecordWrite, RingError> {
        if self.writes.is_empty() {
            return Err(RingError::EmptyListWrite);
        }
        let config = self.ring.require_config(client).await?;
        if config.authority != self.authority {
            return Err(CustomRingError::UnauthorizedAuthority.into());
        }
        let writes: Vec<RecordWriteData> = self
            .writes
            .iter()
            .map(|(member, write)| RecordWriteData {
                member: *member.as_bytes(),
                lists: WriteRecordsIxData::new(*write),
            })
            .collect();
        let entries = writes
            .iter()
            .map(RecordWriteData::entry)
            .collect::<Result<Vec<_>, _>>()?;
        let (application, apply) = retry_projection_lag(|| async {
            let (registry, queue) = self.chain_state(client).await?;
            let pending = queue.pending();
            if pending.saturating_add(writes.len() as u64) > APPLY_BATCH as u64 {
                return Err(RingError::AuthorityBatchSplit {
                    writes: writes.len(),
                    pending,
                    batches: self.batches(pending).len(),
                });
            }
            queue.admit_authority_writes(writes.len() as u64)?;
            let views = entries
                .iter()
                .map(|entry| RingListWriteView {
                    member: Hash(entry.member),
                    mask: entry.mask,
                    value: entry.value,
                })
                .collect();
            let inputs = Application::read(self.ring, client, views).await?;
            let application = Application::new(self.ring, inputs, &registry, &queue, &entries)?;
            let apply = application.prove(client).await?;
            Ok((application, apply))
        })
        .await?;
        let mut data = vec![tag::AUTHORITY_WRITE_RECORDS];
        data.extend(
            AuthorityWriteRecordsIxData {
                writes: &writes,
                apply: &apply,
            }
            .encode()?,
        );
        Ok(ProvenRecordWrite {
            instruction: Instruction {
                program_id: self.ring.program_id(),
                accounts: record_accounts(self.ring, RecordSigner::Authority(self.authority)),
                data,
            },
            bound: application.bound,
        })
    }

    async fn chain_state(
        &self,
        client: &(impl AsyncRpc + ?Sized),
    ) -> Result<(Box<MemberRegistry>, RecordQueue), RingError> {
        Ok((
            self.ring.require_registry(client).await?,
            self.ring.require_queue(client).await?,
        ))
    }
}

/// Permissionless, it applies every pending write.
#[must_use]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordApplication {
    ring: CustomRing,
}

impl RecordApplication {
    pub const fn new(ring: CustomRing) -> Self {
        Self { ring }
    }

    /// `None` while the queue is not due, an authority write applies it sooner.
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<Option<ProvenRecordWrite>, RingError> {
        retry_projection_lag(|| async {
            let registry = self.ring.require_registry(client).await?;
            let queue = self.ring.require_queue(client).await?;
            match queue.apply_due(client.get_slot().await?) {
                Ok(()) => {}
                Err(CustomRingError::ApplyNotDue | CustomRingError::ApplyTooSoon) => {
                    return Ok(None)
                }
                Err(error) => return Err(error.into()),
            }
            let inputs = Application::read(self.ring, client, Vec::new()).await?;
            let application = Application::new(self.ring, inputs, &registry, &queue, &[])?;
            let apply = application.prove(client).await?;
            let mut data = vec![tag::APPLY_RECORDS];
            data.extend_from_slice(bytemuck::bytes_of(&apply));
            Ok(Some(ProvenRecordWrite {
                instruction: Instruction {
                    program_id: self.ring.program_id(),
                    accounts: vec![
                        AccountMeta::new(self.ring.registry_pda(), false),
                        AccountMeta::new(self.ring.queue_pda(), false),
                    ],
                    data,
                },
                bound: application.bound,
            }))
        })
        .await
    }
}

struct Application {
    inputs: ApplyProofInputs,
    bound: BoundQueue,
}

impl Application {
    async fn read<R: AsyncRpc + ?Sized>(
        ring: CustomRing,
        client: &R,
        authority_writes: Vec<RingListWriteView>,
    ) -> Result<ApplyProofInputs, RingError> {
        let response = client
            .get_ring_apply_proof_inputs(GetRingApplyProofInputsRequest {
                ring_program_id: ring.program_id().into(),
                authority_writes,
            })
            .await?;
        Ok(apply_proof_inputs(&response)?)
    }

    /// Inputs off the chain's registry, queue or authority entries are a stale projection.
    fn new(
        ring: CustomRing,
        inputs: ApplyProofInputs,
        registry: &MemberRegistry,
        queue: &RecordQueue,
        authority: &[QueueEntry],
    ) -> Result<Self, RingError> {
        let pending =
            usize::try_from(queue.pending()).map_err(|_| RingError::RecordProjectionStale)?;
        let mut chain_end = queue.chain_tail();
        for entry in authority {
            chain_end = queue_chain(&chain_end, entry)?;
        }
        let tail_matches = inputs.writes.get(pending..).is_some_and(|tail| {
            tail.iter()
                .map(|write| write.entry)
                .eq(authority.iter().copied())
        });
        if inputs.old_root != registry.current_root()
            || inputs.old_next_index != u64::from(registry.next_index())
            || inputs.chain_start != queue.chain_head
            || inputs.chain_end != chain_end
            || inputs.writes.len() != pending + authority.len()
            || !tail_matches
        {
            return Err(RingError::RecordProjectionStale);
        }
        Ok(Self {
            bound: BoundQueue {
                ring,
                tail: queue.tail(),
                chain_tail: queue.chain_tail(),
                root: registry.current_root(),
            },
            inputs,
        })
    }
    async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<ApplyRecordsIxData, RingError> {
        let statement = self.inputs.statement()?;
        let circuit = RingCircuit::apply_records(statement.count);
        let RingCircuit::ApplyRecords { writes: batch } = circuit else {
            return Err(RingError::UnpinnedProvingKey(circuit));
        };
        let public_input_hash = statement.hash()?;
        let mut writes: Vec<Option<RecordWrite>> = self
            .inputs
            .writes
            .iter()
            .map(|write| Some(write.into()))
            .collect();
        writes.resize(usize::from(batch), None);
        let body = ApplyRecords {
            public_input_hash,
            old_root: statement.old_root,
            new_root: statement.new_root,
            old_next_index: statement.old_next_index,
            new_next_index: statement.new_next_index,
            chain_start: statement.chain_start,
            chain_end: statement.chain_end,
            count: u8::try_from(statement.count).map_err(|_| RingError::RecordProjectionStale)?,
            writes,
        };
        let proof = RingRequest::new(circuit, &body)?
            .prove(client, public_input_hash)
            .await?;
        Ok(ApplyRecordsIxData {
            proof: to_instruction_proof(proof)?,
            new_root: statement.new_root,
            new_next_index: statement.new_next_index.to_le_bytes(),
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) enum RecordSigner {
    Member(Address),
    Authority(Address),
}

/// `[signer, config, registry, queue]`, the authority's write also writes the registry.
pub(crate) fn record_accounts(ring: CustomRing, signer: RecordSigner) -> Vec<AccountMeta> {
    let (RecordSigner::Member(address) | RecordSigner::Authority(address)) = signer;
    vec![
        AccountMeta::new_readonly(address, true),
        AccountMeta::new_readonly(ring.config_pda(), false),
        match signer {
            RecordSigner::Authority(_) => AccountMeta::new(ring.registry_pda(), false),
            RecordSigner::Member(_) => AccountMeta::new_readonly(ring.registry_pda(), false),
        },
        AccountMeta::new(ring.queue_pda(), false),
    ]
}

#[must_use]
pub(crate) struct MemberWrite<'a> {
    pub ring: CustomRing,
    pub config: &'a CustomRingConfig,
    pub member: Address,
    pub payer: Address,
}

impl MemberWrite<'_> {
    /// The fee accounts follow when the config charges the member.
    pub(crate) fn metas(&self) -> Vec<AccountMeta> {
        let mut accounts = record_accounts(self.ring, RecordSigner::Member(self.member));
        if self.config.insert_fee_for(&self.member).is_some() {
            accounts.extend([
                AccountMeta::new(self.payer, true),
                AccountMeta::new(self.config.authority, false),
                AccountMeta::new_readonly(SYSTEM_PROGRAM_ID, false),
            ]);
        }
        accounts
    }

    /// A fee raise before the write lands refuses it.
    pub(crate) fn max_fee(&self) -> [u8; 8] {
        self.config.insert_fee.to_le_bytes()
    }
}

fn check_writer(write: ListWrite, writer: Writer) -> Result<(), RingError> {
    let writable = match writer {
        Writer::Member => ListSet::MEMBER_WRITES,
        Writer::Authority => ListSet::AUTHORITY_WRITES,
    };
    let lists = write.set().union(write.clear());
    match lists.difference(writable).iter().next() {
        Some(list) => Err(RingError::ListNotWritable { list, writer }),
        None => Ok(()),
    }
}
