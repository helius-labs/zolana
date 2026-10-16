//! Member records of a ring's registry. Reads verify the indexer's opening under the
//! root the chain publishes, writes prove a batch of record rewrites.

use std::collections::BTreeMap;

use custom_ring_interface::{
    tag, CustomRingProof, EscrowKey, MemberOpening, MemberRecord, MemberRegistryRoot, MemberUpdate,
    MerklePath, RingAccount, UpdateMembersIxData, UpdateMembersPublicInput, MAX_MEMBER_BATCH,
    MEMBER_REGISTRY_HEIGHT,
};
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use zolana_client::{AsyncIndexer, AsyncRpc, AsyncZolanaClient, ClientError};
use zolana_hasher::{Hasher, Poseidon};
use zolana_indexer_api::{
    GetRingMemberRecordRequest, GetRingMemberRecordResponse, GetRingMemberRegistryRootRequest,
    Hash, SerializablePubkey,
};
use zolana_keypair::{NullifierKey, X25519Pubkey, X25519Secret};
use zolana_ring_client::SealedNullifierKey;
use zolana_ring_member_registry::{check_batch, RegistryOverlay};
use zolana_ring_policy::{ListId, ListSet, Member, Writer};

use crate::{
    projection::retry_projection_lag,
    prover::RingRequest,
    request::{RecordUpdate, UpdateMembersBody},
    submission::BoundRoot,
    to_instruction_proof, CurrentRegistryRoot, CustomRing, RegistryBinding, RingError,
};

/// A member's state under one registry root, verified against it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordOpening {
    Present {
        record: MemberRecord,
        index: u64,
        path: Vec<[u8; 32]>,
        /// The sealed nullifier secret a registration published, `None` before one.
        sealed: Option<SealedNullifierKey>,
    },
    Absent {
        low: MemberRecord,
        low_index: u64,
        path: Vec<[u8; 32]>,
    },
}

impl RecordOpening {
    /// Bit `i` marks list id `i + 1`, zero for an absent member.
    pub fn lists(&self) -> u64 {
        match self {
            Self::Present { record, .. } => record.lists,
            Self::Absent { .. } => 0,
        }
    }

    pub fn escrow_key(&self) -> [u8; 32] {
        match self {
            Self::Present { record, .. } => record.escrow_key,
            Self::Absent { .. } => [0; 32],
        }
    }

    pub fn is_present(&self) -> bool {
        matches!(self, Self::Present { .. })
    }

    /// The lists as the policy names them.
    pub fn list_set(&self) -> ListSet {
        ListSet::from_bits(self.lists() as u8)
    }
}

/// A record read at the root the chain published when it was asked for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRecordRead {
    pub member: Member,
    pub root: CurrentRegistryRoot,
    pub opening: RecordOpening,
}

impl MemberRecordRead {
    /// The sealed key of a registered member, `None` before a registration.
    pub fn sealed_key(&self) -> Option<SealedKeyEntry> {
        match &self.opening {
            RecordOpening::Present {
                record,
                sealed: Some(sealed),
                ..
            } if record.escrow_key != [0; 32] => Some(SealedKeyEntry {
                sealed: *sealed,
                member: self.member,
                escrow_key: record.escrow_key,
            }),
            _ => None,
        }
    }
}

/// A registered key, its record verified under the root it was read at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedKeyEntry {
    pub sealed: SealedNullifierKey,
    member: Member,
    escrow_key: [u8; 32],
}

impl SealedKeyEntry {
    pub fn member(&self) -> Member {
        self.member
    }

    /// The opened key must reproduce the escrow key the record carries.
    pub fn open(&self, auditor: &X25519Secret) -> Result<NullifierKey, RingError> {
        let nullifier_key = self.sealed.open(auditor)?;
        self.verify_nullifier_pubkey(&nullifier_key.pubkey()?)?;
        Ok(nullifier_key)
    }

    /// Membership of a known nullifier public key, without the auditor's key.
    pub fn verify_nullifier_pubkey(&self, nullifier_pubkey: &[u8; 32]) -> Result<(), RingError> {
        let key = EscrowKey {
            nullifier_pk: nullifier_pubkey,
            ciphertext: &self.sealed.ciphertext,
        }
        .hash()?;
        if key != self.escrow_key {
            return Err(RingError::InvalidRecordOpening);
        }
        Ok(())
    }
}

/// Reads one member's record of a ring's registry.
#[must_use]
#[derive(Clone, Copy, Debug)]
pub struct ReadMemberRecord {
    pub ring: CustomRing,
    pub member: Member,
}

impl ReadMemberRecord {
    /// Under the chain's current root, read again while the indexer trails it. `None`
    /// when the ring has no registry.
    pub async fn read(
        self,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Option<MemberRecordRead>, RingError> {
        retry_projection_lag(|| async {
            let Some(root) = self.ring.member_registry_root(rpc).await? else {
                return Ok(None);
            };
            self.read_at(rpc, root).await.map(Some)
        })
        .await
    }

    /// Under `root`, which the response must name.
    pub async fn read_at(
        self,
        indexer: &(impl AsyncRpc + ?Sized),
        root: CurrentRegistryRoot,
    ) -> Result<MemberRecordRead, RingError> {
        let request = self.ring.member_record_request(&self.member, root);
        let response = indexer.get_ring_member_record(request).await?;
        self.decode(root, response)
    }

    pub(crate) fn decode(
        self,
        root: CurrentRegistryRoot,
        response: GetRingMemberRecordResponse,
    ) -> Result<MemberRecordRead, RingError> {
        let invalid = RingError::InvalidRecordOpening;
        if response.root.0 != root.root
            || response.next_index != root.next_index
            || response.root_index != root.history_index
        {
            return Err(invalid);
        }
        let member = *self.member.as_bytes();
        let opening = match (response.present, response.record, response.low) {
            (true, Some(view), None) => {
                let path = hashes(response.path)?;
                let record = MemberRecord {
                    member: view.member.0,
                    next: view.next.0,
                    lists: view.lists,
                    escrow_key: view.escrow_key.0,
                };
                if response.index == 0 || response.index >= root.next_index {
                    return Err(invalid);
                }
                let sealed = match (view.eph_pk, view.ciphertext) {
                    (Some(eph_pk), Some(ciphertext)) => {
                        let eph_pk = <[u8; 33]>::try_from(eph_pk.0.as_slice())
                            .ok()
                            .and_then(|bytes| X25519Pubkey::from_bytes(bytes).ok())
                            .ok_or(RingError::InvalidRecordOpening)?;
                        let ciphertext = <[u8; 32]>::try_from(ciphertext.0.as_slice())
                            .map_err(|_| RingError::InvalidRecordOpening)?;
                        Some(SealedNullifierKey { eph_pk, ciphertext })
                    }
                    (None, None) => None,
                    _ => return Err(invalid),
                };
                RecordOpening::Present {
                    record,
                    index: response.index,
                    path,
                    sealed,
                }
            }
            (false, None, Some(low)) => {
                if response.index != 0 || !response.path.is_empty() || low.index >= root.next_index
                {
                    return Err(invalid);
                }
                RecordOpening::Absent {
                    low: MemberRecord {
                        member: low.member.0,
                        next: low.next.0,
                        lists: low.lists,
                        escrow_key: low.escrow_key.0,
                    },
                    low_index: low.index,
                    path: hashes(low.path)?,
                }
            }
            _ => return Err(invalid),
        };
        verify(&opening, &root.root, &member)?;
        Ok(MemberRecordRead {
            member: self.member,
            root,
            opening,
        })
    }
}

/// The opening must reach `root`, with the lists and key the record states.
pub(crate) fn verify(
    opening: &RecordOpening,
    root: &[u8; 32],
    member: &[u8; 32],
) -> Result<(), RingError> {
    let checked = match opening {
        RecordOpening::Present {
            record,
            index,
            path,
            ..
        } => MemberOpening::Present {
            record: *record,
            path: MerklePath {
                index: *index,
                siblings: path,
            },
        },
        RecordOpening::Absent {
            low,
            low_index,
            path,
        } => MemberOpening::Absent {
            low: *low,
            path: MerklePath {
                index: *low_index,
                siblings: path,
            },
        },
    };
    match checked.verify(root, member) {
        Ok((lists, escrow_key))
            if lists == opening.lists() && escrow_key == opening.escrow_key() =>
        {
            Ok(())
        }
        _ => Err(RingError::InvalidRecordOpening),
    }
}

fn hashes(path: Vec<Hash>) -> Result<Vec<[u8; 32]>, RingError> {
    if path.len() != MEMBER_REGISTRY_HEIGHT {
        return Err(RingError::InvalidRecordOpening);
    }
    Ok(path.into_iter().map(|hash| hash.0).collect())
}

/// The registry tip with the path the next record appends along.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RegistryTip {
    pub root: CurrentRegistryRoot,
    pub append_path: Vec<[u8; 32]>,
}

impl RegistryTip {
    /// The chain root with the indexer's append path under it, a trailing indexer is lag.
    pub async fn fetch(
        ring: CustomRing,
        rpc: &(impl AsyncRpc + ?Sized),
    ) -> Result<Self, RingError> {
        let root = ring
            .member_registry_root(rpc)
            .await?
            .ok_or(RingError::MissingMemberRegistry)?;
        let response = rpc
            .get_ring_member_registry_root(GetRingMemberRegistryRootRequest {
                ring_program_id: SerializablePubkey::from(ring.program_id().to_bytes()),
            })
            .await?;
        if response.root.0 != root.root || response.next_index != root.next_index {
            return Err(RingError::Client(ClientError::RingRegistryRootChanged));
        }
        if response.root_index != root.history_index {
            return Err(RingError::InvalidRecordOpening);
        }
        let append_path = hashes(response.append_path)?;
        let empty = Poseidon::zero_bytes()[0];
        let reached = MerklePath {
            index: root.next_index,
            siblings: &append_path,
        }
        .root_of(empty)
        .map_err(|_| RingError::InvalidRecordOpening)?;
        if reached != root.root {
            return Err(RingError::InvalidRecordOpening);
        }
        Ok(Self { root, append_path })
    }
}

/// The lists a member gains and loses, the escrow key stays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemberWrite {
    pub member: Member,
    pub set: ListSet,
    pub clear: ListSet,
}

impl MemberWrite {
    pub fn add(member: Member, list_id: ListId) -> Self {
        Self {
            member,
            set: ListSet::single(list_id),
            clear: ListSet::EMPTY,
        }
    }

    pub fn remove(member: Member, list_id: ListId) -> Self {
        Self {
            member,
            set: ListSet::EMPTY,
            clear: ListSet::single(list_id),
        }
    }

    /// The signers the program requires for the bits the write changes.
    pub fn writers(&self) -> impl Iterator<Item = Writer> + '_ {
        self.set.union(self.clear).iter().map(ListId::writer)
    }
}

/// One proven batch over the records of up to sixteen members.
#[must_use]
#[derive(Clone, Debug)]
pub struct UpdateMembers {
    pub ring: CustomRing,
    pub writes: Vec<MemberWrite>,
    /// Sign the transaction, the authority for its lists and each member for its own.
    pub signers: Vec<Address>,
}

#[must_use]
#[derive(Clone, Debug)]
pub struct ProvenMemberUpdate {
    ring: CustomRing,
    signers: Vec<Address>,
    old_root: RegistryBinding,
    new_root: [u8; 32],
    items: Vec<MemberUpdate>,
    proof: CustomRingProof,
}

impl UpdateMembers {
    /// Proves the batch under the current root, the records read at that root.
    pub async fn prove<R: AsyncRpc, I: AsyncIndexer>(
        &self,
        client: &AsyncZolanaClient<R, I>,
    ) -> Result<ProvenMemberUpdate, RingError> {
        let (body, items, root) = retry_projection_lag(|| async {
            let tip = RegistryTip::fetch(self.ring, client).await?;
            let mut records = Vec::with_capacity(self.writes.len());
            for write in &self.writes {
                if records
                    .iter()
                    .any(|read: &MemberRecordRead| read.member == write.member)
                {
                    continue;
                }
                let read = ReadMemberRecord {
                    ring: self.ring,
                    member: write.member,
                };
                records.push(read.read_at(client, tip.root).await?);
            }
            let plan = BatchPlan::new(&tip, &self.writes, &records)?;
            let body = plan.body(&tip)?;
            Ok((body, plan.items, tip.root))
        })
        .await?;
        let proof = client.prove_request(&RingRequest(&body)).await?;
        Ok(ProvenMemberUpdate {
            ring: self.ring,
            signers: self.signers.clone(),
            old_root: RegistryBinding::of(root),
            new_root: body.new_root,
            items,
            proof: to_instruction_proof(proof)?,
        })
    }
}

impl ProvenMemberUpdate {
    pub fn items(&self) -> &[MemberUpdate] {
        &self.items
    }

    pub fn new_root(&self) -> [u8; 32] {
        self.new_root
    }

    pub(crate) fn bound_root(&self) -> Option<BoundRoot> {
        Some(BoundRoot::registry(self.ring, self.old_root))
    }

    /// `[config, member_registry_root, signers..]`, every signer signs the transaction.
    pub fn instruction(&self) -> Result<Instruction, RingError> {
        let mut data = vec![tag::UPDATE_MEMBERS];
        data.extend(wincode::serialize(&UpdateMembersIxData {
            proof: self.proof,
            old_root_index: self.old_root.root_index,
            new_root: self.new_root,
            items: self.items.clone(),
        })?);
        let mut accounts = vec![
            AccountMeta::new_readonly(self.ring.config_pda(), false),
            AccountMeta::new(self.ring.member_registry_root_pda(), false),
        ];
        accounts.extend(
            self.signers
                .iter()
                .map(|signer| AccountMeta::new_readonly(*signer, true)),
        );
        Ok(Instruction {
            program_id: self.ring.program_id(),
            accounts,
            data,
        })
    }
}

/// A fetched or written record and the path the indexer served it with.
#[derive(Clone, Debug)]
struct Known {
    index: u64,
    record: MemberRecord,
    /// The path under the base root, `None` for a record this batch inserts.
    base_path: Option<Vec<[u8; 32]>>,
}

/// The items of one batch and the witness of each, computed over the records as
/// the indexer served them and the writes earlier items made.
pub(crate) struct BatchPlan {
    pub items: Vec<MemberUpdate>,
    pub updates: Vec<RecordUpdate>,
    pub new_root: [u8; 32],
}

impl BatchPlan {
    pub fn new(
        tip: &RegistryTip,
        writes: &[MemberWrite],
        records: &[MemberRecordRead],
    ) -> Result<Self, RingError> {
        let mut known: BTreeMap<[u8; 32], Known> = BTreeMap::new();
        for read in records {
            match &read.opening {
                RecordOpening::Present {
                    record,
                    index,
                    path,
                    ..
                } => known.insert(
                    record.member,
                    Known {
                        index: *index,
                        record: *record,
                        base_path: Some(path.clone()),
                    },
                ),
                RecordOpening::Absent {
                    low,
                    low_index,
                    path,
                } => known.insert(
                    low.member,
                    Known {
                        index: *low_index,
                        record: *low,
                        base_path: Some(path.clone()),
                    },
                ),
            };
        }
        let items = plan_items(writes, records, tip.root.next_index)?;
        check_batch(&items).map_err(|_| {
            RingError::Program(custom_ring_interface::CustomRingError::MemberBatchTooLarge)
        })?;
        let mut overlay = RegistryOverlay::new(tip.root.next_index, tip.append_path.clone())
            .map_err(|_| RingError::InvalidRecordOpening)?;
        let mut root = tip.root.root;
        let mut updates = Vec::with_capacity(items.len());
        for item in &items {
            let tree_error = |_| RingError::InvalidRecordOpening;
            if let Some(existing) = known.get(&item.member).cloned() {
                let path = overlay
                    .path(existing.index, existing.base_path.as_deref())
                    .map_err(tree_error)?;
                let after = MemberRecord {
                    lists: item.lists,
                    escrow_key: item.escrow_key,
                    ..existing.record
                };
                root = overlay
                    .write(existing.index, after.hash()?, &path)
                    .map_err(tree_error)?;
                updates.push(RecordUpdate::rewrite(after.next, existing.index, path));
                known.insert(
                    item.member,
                    Known {
                        record: after,
                        ..existing
                    },
                );
                continue;
            }
            let (low_member, low) = known
                .range(..item.member)
                .next_back()
                .map(|(member, low)| (*member, low.clone()))
                .ok_or(RingError::InvalidRecordOpening)?;
            if !(low_member < item.member && item.member < low.record.next) {
                return Err(RingError::InvalidRecordOpening);
            }
            let low_path = overlay
                .path(low.index, low.base_path.as_deref())
                .map_err(tree_error)?;
            let relinked = MemberRecord {
                next: item.member,
                ..low.record
            };
            overlay
                .write(low.index, relinked.hash()?, &low_path)
                .map_err(tree_error)?;
            let path = overlay.path(item.index, None).map_err(tree_error)?;
            let record = MemberRecord {
                member: item.member,
                next: low.record.next,
                lists: item.lists,
                escrow_key: item.escrow_key,
            };
            root = overlay
                .write(item.index, record.hash()?, &path)
                .map_err(tree_error)?;
            updates.push(RecordUpdate::insert(
                &low.record,
                low.index,
                low_path,
                item.index,
                path,
            ));
            known.insert(
                low_member,
                Known {
                    record: relinked,
                    ..low
                },
            );
            known.insert(
                item.member,
                Known {
                    index: item.index,
                    record,
                    base_path: None,
                },
            );
        }
        Ok(Self {
            items,
            updates,
            new_root: root,
        })
    }

    pub fn body(&self, tip: &RegistryTip) -> Result<UpdateMembersBody, RingError> {
        let public_input_hash = UpdateMembersPublicInput {
            old_root: &tip.root.root,
            new_root: &self.new_root,
            items: &self.items,
        }
        .hash()?;
        Ok(UpdateMembersBody::new(
            public_input_hash,
            tip.root.root,
            self.new_root,
            &self.items,
            self.updates.clone(),
        ))
    }
}

/// Merges the writes per member into items in member order, inserts take the next free
/// indices in that order. A write that changes nothing is dropped.
fn plan_items(
    writes: &[MemberWrite],
    records: &[MemberRecordRead],
    next_index: u64,
) -> Result<Vec<MemberUpdate>, RingError> {
    let mut merged: BTreeMap<[u8; 32], (ListSet, ListSet)> = BTreeMap::new();
    for write in writes {
        let entry = merged
            .entry(*write.member.as_bytes())
            .or_insert((ListSet::EMPTY, ListSet::EMPTY));
        entry.0 = entry.0.union(write.set);
        entry.1 = entry.1.union(write.clear);
    }
    let mut items = Vec::with_capacity(merged.len());
    let mut inserts = 0;
    for (member, (set, clear)) in merged {
        if let Some(list_id) = set.iter().find(|list_id| clear.contains(*list_id)) {
            return Err(RingError::ConflictingListWrite(list_id));
        }
        let read = records
            .iter()
            .find(|read| *read.member.as_bytes() == member)
            .ok_or(RingError::InvalidRecordOpening)?;
        let (index, old_lists, escrow_key) = match &read.opening {
            RecordOpening::Present { record, index, .. } => {
                (*index, record.lists, record.escrow_key)
            }
            RecordOpening::Absent { .. } => {
                inserts += 1;
                (next_index + inserts - 1, 0, [0; 32])
            }
        };
        let lists = (old_lists | set.record_bits()) & !clear.record_bits();
        if lists == old_lists {
            if matches!(read.opening, RecordOpening::Absent { .. }) {
                inserts -= 1;
            }
            continue;
        }
        items.push(MemberUpdate {
            member,
            old_lists,
            old_escrow_key: escrow_key,
            lists,
            escrow_key,
            index,
        });
    }
    if items.is_empty() {
        return Err(RingError::EmptyMemberBatch);
    }
    if items.len() > MAX_MEMBER_BATCH {
        return Err(custom_ring_interface::CustomRingError::MemberBatchTooLarge.into());
    }
    Ok(items)
}

impl CustomRing {
    pub(crate) fn member_record_request(
        self,
        member: &Member,
        root: CurrentRegistryRoot,
    ) -> GetRingMemberRecordRequest {
        GetRingMemberRecordRequest {
            ring_program_id: SerializablePubkey::from(self.program_id().to_bytes()),
            member: Hash(*member.as_bytes()),
            expected_root: Hash(root.root),
            expected_next_index: root.next_index,
        }
    }

    /// The curator ring whose registry root sits at `registry`, and that root.
    pub async fn curator_registry(
        rpc: &(impl AsyncRpc + ?Sized),
        registry: Address,
    ) -> Result<(CustomRing, CurrentRegistryRoot), RingError> {
        let invalid = RingError::InvalidCuratorRegistry { address: registry };
        let account = rpc
            .get_account(registry)
            .await?
            .ok_or(RingError::InvalidCuratorRegistry { address: registry })?;
        let curator = CustomRing::new(account.owner);
        if curator.member_registry_root_pda() != registry {
            return Err(invalid);
        }
        let root = MemberRegistryRoot::decode(&account.owner, &account.owner, &account.data)
            .ok_or(RingError::InvalidCuratorRegistry { address: registry })?;
        let current = crate::account::current_root(&root)
            .ok_or(RingError::InvalidCuratorRegistry { address: registry })?;
        Ok((curator, current))
    }
}

#[cfg(test)]
#[path = "tests/member_registry.rs"]
pub(crate) mod tests;
