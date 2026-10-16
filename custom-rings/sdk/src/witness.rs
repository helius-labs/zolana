//! The policy half of the ring proof, the openings of the prepared transfer and the
//! member records of every live slot.

use custom_ring_interface::EscrowKey;
use futures::future::try_join_all;
use serde::Serialize;
use solana_address::Address;
use zolana_client::{prover::indexed::IndexedRegistry, AsyncRpc};
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::{
    merge_utils::ciphertext_hash,
    tree_slot::{tree_id_field, TreeSlot},
    DUMMY_DOMAIN, UTXO_DOMAIN,
};
use zolana_ring_policy::{
    Guard, ListId, ListSet, Member, Mode, PolicySource, Rule, RuleSource, SourceMap, Subject,
    MAX_INLINE_ASSETS, MAX_RULES, MAX_SOURCES, POLICY_INPUT_SLOTS, POLICY_OUTPUT_SLOTS,
};
use zolana_transaction::{instructions::transact::SppProofOutputUtxo, utxo::SppProofInputUtxo};

use crate::{
    account::source_map,
    member_registry::{MemberRecordRead, ReadMemberRecord, RecordOpening},
    prover::fe,
    request::{sources, subjects, tree_slots, CustomRingOpening, CustomRingOutputOpening},
    trees::{read_tree, TransactRoots},
    CurrentRegistryRoot, CustomRing, ForeignBinding, OutflowLimitProofInput, PinnedPolicy,
    PolicyReads, PolicyTreeContext, PoolTree, RegistryBinding, RingError,
};

/// One subject per transaction slot, inputs first.
pub(crate) const SUBJECT_SLOTS: usize = POLICY_INPUT_SLOTS + POLICY_OUTPUT_SLOTS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PolicyTree {
    pub tree: PoolTree,
    pub roots: TransactRoots,
}

impl PolicyTree {
    pub fn slot(&self) -> TreeSlot {
        self.roots.slot(self.tree.id)
    }

    pub fn resolved(&self) -> zolana_client::prover::indexed::ResolvedProofTree {
        zolana_client::prover::indexed::ResolvedProofTree {
            tree: self.tree.address,
            id: self.tree.id,
            utxo_root: self.roots.state,
            nullifier_root: self.roots.nullifier,
            context: self.roots.context(),
        }
    }
}

/// The registries the indexed prover opens the records in.
#[derive(Clone)]
pub(crate) struct IndexedRegistries {
    pub registry: IndexedRegistry,
    pub foreign: Option<IndexedRegistry>,
}

/// The policy witness, in the wire order of the policy body after the audit fields.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CustomRingWitness {
    #[serde(skip)]
    pub indexed: Option<IndexedRegistries>,
    #[serde(skip)]
    pub registry: RegistryBinding,
    #[serde(skip)]
    pub foreign: Option<ForeignBinding>,
    pub n_in: u8,
    pub n_out: u8,
    pub inputs: [CustomRingOpening; POLICY_INPUT_SLOTS],
    pub outputs: [CustomRingOutputOpening; POLICY_OUTPUT_SLOTS],
    #[serde(serialize_with = "fe::zero")]
    pub address_chain: (),
    #[serde(with = "fe")]
    pub private_tx_blinding: [u8; 32],
    #[serde(serialize_with = "sources")]
    pub sources: [PolicySource; MAX_SOURCES],
    pub policy_len: u8,
    /// The account rows verbatim, the pinned hash binds them.
    #[serde(rename = "ruleEnc", serialize_with = "fe::seq")]
    pub rules: [[u8; 32]; MAX_RULES],
    #[serde(serialize_with = "fe::seq")]
    pub inline_assets: [[u8; 32]; MAX_INLINE_ASSETS],
    #[serde(serialize_with = "fe::ints")]
    pub inline_limits: [u64; MAX_INLINE_ASSETS],
    pub inline_count: u8,
    #[serde(flatten)]
    pub limits: OutflowLimitProofInput,
    /// In slot order, at most `INPUT_TREES`.
    #[serde(rename = "treeSlots", serialize_with = "tree_slots")]
    pub trees: Vec<PolicyTree>,
    #[serde(serialize_with = "fe::short")]
    pub address_tree_id: u16,
    pub key_escrow: bool,
    #[serde(with = "fe")]
    pub member_registry_root: [u8; 32],
    /// Own-registry openings of the live slots, `None` where the prover fills them.
    #[serde(serialize_with = "subjects")]
    pub subjects: [Option<crate::request::SubjectWitness>; SUBJECT_SLOTS],
    /// Zero without a curator.
    #[serde(with = "fe")]
    pub foreign_root: [u8; 32],
    #[serde(serialize_with = "subjects")]
    pub foreign_subjects: [Option<crate::request::SubjectWitness>; SUBJECT_SLOTS],
}

impl CustomRingWitness {
    pub fn tree_slots(&self) -> Vec<TreeSlot> {
        self.trees.iter().map(PolicyTree::slot).collect()
    }

    pub fn reads(&self) -> PolicyReads {
        PolicyReads {
            trees: self
                .trees
                .iter()
                .map(|tree| PolicyTreeContext {
                    tree: tree.tree.address,
                    context: tree.roots.context(),
                })
                .collect(),
            registry: self.registry,
            foreign: self.foreign,
        }
    }
}

/// What the policy witness reads at prove time.
pub(crate) struct WitnessInput<'a> {
    pub ring: CustomRing,
    pub pinned: &'a PinnedPolicy,
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
    /// The tree the outputs are appended to, every output hashes under it.
    pub output_tree_id: u16,
    pub private_tx_blinding: [u8; 32],
    pub limits: OutflowLimitProofInput,
    /// Every live output owner's record must escrow the key the output uses.
    pub key_escrow: bool,
}

/// A live slot's owner and where it sits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    position: usize,
    member: Member,
}

/// The records of one slot in both registries, as the rules read them.
struct SubjectRecords {
    own: RecordOpening,
    foreign: Option<RecordOpening>,
}

impl SubjectRecords {
    /// Bit `i` from the registry that serves list `i + 1`.
    fn on_lists(&self, sources: &SourceMap) -> ListSet {
        let own = self.own.list_set();
        let foreign = self
            .foreign
            .as_ref()
            .map_or(ListSet::EMPTY, RecordOpening::list_set);
        let mut bits = 0u8;
        for list_id in ListId::ALL {
            let served = match sources.registry(list_id) {
                Some(registry) if *registry != [0; 32] => foreign,
                _ => own,
            };
            if served.contains(list_id) {
                bits |= ListSet::single(list_id).bits();
            }
        }
        ListSet::from_bits(bits)
    }
}

impl<'a> WitnessInput<'a> {
    /// Refuses client-side with a named rule before any prover round. On the indexed
    /// route the prover opens the records, the client only binds the roots.
    pub async fn build(
        self,
        client: &(impl AsyncRpc + ?Sized),
        indexed: bool,
    ) -> Result<Box<CustomRingWitness>, RingError> {
        if self.inputs.len() > POLICY_INPUT_SLOTS || self.outputs.len() > POLICY_OUTPUT_SLOTS {
            return Err(RingError::PolicyShapeUnsupported);
        }
        let config = &self.pinned.config;
        let address_tree = PoolTree::address_tree(config);
        let view = read_tree(client, address_tree.address).await?;
        if view.tree.id != address_tree.id {
            return Err(RingError::TreeIdMismatch {
                tree: address_tree.address,
                expected: view.tree.id,
                found: address_tree.id,
            });
        }
        let tree = PolicyTree {
            tree: address_tree,
            roots: view.roots,
        };
        let root = self
            .ring
            .member_registry_root(client)
            .await?
            .ok_or(RingError::MissingMemberRegistry)?;
        let curator = match config.curator() {
            Some(registry) => Some(CustomRing::curator_registry(client, registry).await?),
            None => None,
        };
        let slots = self.slots()?;
        let records = match indexed {
            true => None,
            false => Some(self.records(client, &slots, root, curator.as_ref()).await?),
        };
        self.assemble(tree, root, curator, slots, records, indexed)
    }

    /// Live slots in circuit order, inputs then outputs, with their owner tags.
    fn slots(&self) -> Result<Vec<Slot>, RingError> {
        let mut slots = Vec::new();
        for (position, input) in self.inputs.iter().enumerate() {
            if input.is_dummy() {
                continue;
            }
            slots.push(Slot {
                position,
                member: Member::from_bytes(input.utxo.owner.owner_proof_input_hash()?)?,
            });
        }
        for (position, output) in self.outputs.iter().enumerate() {
            let Some(address) = output.owner_address.as_ref() else {
                continue;
            };
            slots.push(Slot {
                position: POLICY_INPUT_SLOTS + position,
                member: Member::from_bytes(address.signing_pubkey.owner_proof_input_hash()?)?,
            });
        }
        Ok(slots)
    }

    /// One registry read per distinct member and registry.
    async fn records(
        &self,
        client: &(impl AsyncRpc + ?Sized),
        slots: &[Slot],
        root: CurrentRegistryRoot,
        curator: Option<&(CustomRing, CurrentRegistryRoot)>,
    ) -> Result<Vec<(Member, SubjectRecords)>, RingError> {
        let mut members: Vec<Member> = Vec::new();
        for slot in slots {
            if !members.contains(&slot.member) {
                members.push(slot.member);
            }
        }
        let reads = try_join_all(members.iter().map(|&member| async move {
            let own = ReadMemberRecord {
                ring: self.ring,
                member,
            }
            .read_at(client, root)
            .await?;
            let foreign = match curator {
                Some((ring, root)) => Some(
                    ReadMemberRecord {
                        ring: *ring,
                        member,
                    }
                    .read_at(client, *root)
                    .await?,
                ),
                None => None,
            };
            Ok::<_, RingError>((own, foreign))
        }))
        .await?;
        Ok(members
            .into_iter()
            .zip(reads)
            .map(|(member, (own, foreign))| {
                let records = SubjectRecords {
                    own: own.opening,
                    foreign: foreign.map(|read: MemberRecordRead| read.opening),
                };
                (member, records)
            })
            .collect())
    }

    fn assemble(
        self,
        tree: PolicyTree,
        root: CurrentRegistryRoot,
        curator: Option<(CustomRing, CurrentRegistryRoot)>,
        slots: Vec<Slot>,
        records: Option<Vec<(Member, SubjectRecords)>>,
        indexed: bool,
    ) -> Result<Box<CustomRingWitness>, RingError> {
        let config = &self.pinned.config;
        let sources = source_map(config)?;
        let mut subjects: [Option<_>; SUBJECT_SLOTS] = Default::default();
        let mut foreign_subjects: [Option<_>; SUBJECT_SLOTS] = Default::default();
        let mut ct_hashes = [[0; 32]; POLICY_OUTPUT_SLOTS];
        if let Some(records) = &records {
            self.check_rules(&sources, &slots, records)?;
            for slot in &slots {
                let (_, found) = records
                    .iter()
                    .find(|(member, _)| *member == slot.member)
                    .ok_or(RingError::PolicyRuleUnsatisfied)?;
                subjects[slot.position] = Some(crate::request::SubjectWitness::of(&found.own));
                foreign_subjects[slot.position] = found
                    .foreign
                    .as_ref()
                    .map(crate::request::SubjectWitness::of);
                if self.key_escrow && slot.position >= POLICY_INPUT_SLOTS {
                    let output = &self.outputs[slot.position - POLICY_INPUT_SLOTS];
                    ct_hashes[slot.position - POLICY_INPUT_SLOTS] =
                        escrowed_ct_hash(output, slot.member, &found.own)?;
                }
            }
        }
        let mut inputs = [CustomRingOpening::default(); POLICY_INPUT_SLOTS];
        for (slot, input) in inputs.iter_mut().zip(self.inputs) {
            *slot = input_opening(input)?;
        }
        let mut outputs = [CustomRingOutputOpening::default(); POLICY_OUTPUT_SLOTS];
        for (index, (slot, output)) in outputs.iter_mut().zip(self.outputs).enumerate() {
            *slot = CustomRingOutputOpening {
                opening: output_opening(output, self.output_tree_id)?,
                ct_hash: ct_hashes[index],
            };
        }
        let table = &config.rules;
        let foreign = curator.map(|(ring, root)| ForeignBinding {
            registry: ring.member_registry_root_pda(),
            curator: ring,
            root_index: root.history_index,
            root: root.root,
            next_index: root.next_index,
        });
        let indexed = indexed.then(|| IndexedRegistries {
            registry: IndexedRegistry {
                ring_program_id: self.ring.program_id(),
                root: root.root,
                next_index: root.next_index,
            },
            foreign: foreign.as_ref().map(|foreign| IndexedRegistry {
                ring_program_id: foreign.curator.program_id(),
                root: foreign.root,
                next_index: foreign.next_index,
            }),
        });
        Ok(Box::new(CustomRingWitness {
            indexed,
            registry: RegistryBinding {
                root_index: root.history_index,
                root: root.root,
            },
            foreign,
            n_in: self.inputs.len() as u8,
            n_out: self.active_output_count() as u8,
            inputs,
            outputs,
            address_chain: (),
            private_tx_blinding: self.private_tx_blinding,
            sources: *sources.slots(),
            policy_len: table.rule_count,
            rules: table.rules,
            inline_assets: table.inline_assets,
            inline_limits: table.inline_limits.map(u64::from_be_bytes),
            inline_count: table.inline_count,
            limits: self.limits,
            trees: vec![tree],
            address_tree_id: config.address_tree_id(),
            key_escrow: self.key_escrow,
            member_registry_root: root.root,
            subjects,
            foreign_root: foreign.map_or([0; 32], |foreign| foreign.root),
            foreign_subjects,
        }))
    }

    /// Every enabled rule must pass for each live subject, as the circuit evaluates it.
    fn check_rules(
        &self,
        sources: &SourceMap,
        slots: &[Slot],
        records: &[(Member, SubjectRecords)],
    ) -> Result<(), RingError> {
        let on_lists = |member: Member| {
            records
                .iter()
                .find(|(known, _)| *known == member)
                .map(|(_, found)| found.on_lists(sources))
                .ok_or(RingError::PolicyRuleUnsatisfied)
        };
        for rule in self.pinned.table.rules() {
            match rule.source {
                RuleSource::InlineAssets => {
                    for output in self.rule_outputs() {
                        if output.owner_address.is_none() {
                            continue;
                        }
                        let asset = Member::asset(&output.asset.asset)?;
                        let found = self.pinned.table.inline_assets().contains(asset.as_bytes());
                        if !found && !self.guard_exempts(rule, &asset)? {
                            return Err(RingError::PolicyRuleUnsatisfied);
                        }
                    }
                }
                RuleSource::Lists { present, absent } => {
                    for member in self.subjects(rule, slots)? {
                        if self.guard_exempts(rule, &member)? {
                            continue;
                        }
                        let lists = on_lists(member)?;
                        if !satisfied(rule, present, absent, lists) {
                            return Err(RingError::PolicyRuleUnsatisfied);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// The guard exempts a subject whose received total is at or below its threshold, as the circuit weighs it.
    fn guard_exempts(&self, rule: &Rule, member: &Member) -> Result<bool, RingError> {
        let owned = self
            .rule_outputs()
            .iter()
            .filter(|output| output.owner_address.is_some());
        match rule.guard {
            Guard::Always => Ok(false),
            Guard::AboveAmount(_)
                if matches!(rule.subject, Subject::Sender | Subject::ExitDestination) =>
            {
                Ok(false)
            }
            Guard::AboveAmount(threshold) => {
                let mut total = 0u128;
                for output in owned {
                    if self.subject_member(rule.subject, output)? == *member {
                        total += u128::from(output.amount);
                    }
                }
                Ok(total <= u128::from(threshold))
            }
            Guard::AboveAmountByAsset => {
                let assets = self.pinned.table.inline_assets();
                let mut totals = [0u128; MAX_INLINE_ASSETS];
                for output in owned {
                    if owner_member(output)? != *member {
                        continue;
                    }
                    let asset = Member::asset(&output.asset.asset)?;
                    let index = assets
                        .iter()
                        .position(|known| known == asset.as_bytes())
                        .ok_or(RingError::PolicyAssetUnsupported)?;
                    totals[index] += u128::from(output.amount);
                }
                let limits = self.pinned.table.inline_limits();
                Ok(totals
                    .iter()
                    .zip(limits)
                    .all(|(total, limit)| *total <= u128::from(*limit)))
            }
        }
    }

    fn subject_member(
        &self,
        subject: Subject,
        output: &SppProofOutputUtxo,
    ) -> Result<Member, RingError> {
        match subject {
            Subject::Asset => Ok(Member::asset(&output.asset.asset)?),
            _ => owner_member(output),
        }
    }

    /// Compact padding trails the money, so the active outputs lead.
    fn active_output_count(&self) -> usize {
        self.outputs
            .iter()
            .filter(|output| !output.is_compact())
            .count()
    }

    fn rule_outputs(&self) -> &[SppProofOutputUtxo] {
        self.outputs
            .get(..self.active_output_count())
            .unwrap_or_default()
    }

    /// The owners a list rule ranges over.
    fn subjects(&self, rule: &Rule, slots: &[Slot]) -> Result<Vec<Member>, RingError> {
        let outputs = self.rule_outputs().len();
        Ok(match rule.subject {
            Subject::OutputOwner => slots
                .iter()
                .filter(|slot| {
                    slot.position >= POLICY_INPUT_SLOTS
                        && slot.position - POLICY_INPUT_SLOTS < outputs
                })
                .map(|slot| slot.member)
                .collect(),
            Subject::Sender => slots
                .iter()
                .filter(|slot| slot.position < POLICY_INPUT_SLOTS)
                .map(|slot| slot.member)
                .collect(),
            // Asset rules read the inline pool, the table admits no list source for them.
            Subject::Asset | Subject::ExitDestination => Vec::new(),
        })
    }
}

/// On a primary list in the rule's mode, or off every alternative list.
fn satisfied(rule: &Rule, present: ListSet, absent: ListSet, lists: ListSet) -> bool {
    let (primary, alternative) = match rule.primary_mode() {
        Mode::Present => (present, absent),
        Mode::Absent => (absent, present),
    };
    let on_primary = lists.intersects(primary);
    let primary_holds = match rule.primary_mode() {
        Mode::Present => on_primary,
        Mode::Absent => !on_primary,
    };
    primary_holds || (!alternative.is_empty() && !lists.intersects(alternative))
}

/// The output owner's record must escrow the key the output uses.
fn escrowed_ct_hash(
    output: &SppProofOutputUtxo,
    owner: Member,
    record: &RecordOpening,
) -> Result<[u8; 32], RingError> {
    let RecordOpening::Present {
        record,
        sealed: Some(sealed),
        ..
    } = record
    else {
        return Err(RingError::UnregisteredOutputKey { owner });
    };
    let nullifier_pk = output
        .owner_address
        .as_ref()
        .ok_or(RingError::InvalidDummyOutput)?
        .nullifier_pubkey;
    let key = EscrowKey {
        nullifier_pk: &nullifier_pk,
        ciphertext: &sealed.ciphertext,
    }
    .hash()?;
    if key != record.escrow_key {
        return Err(RingError::UnregisteredOutputKey { owner });
    }
    Ok(ciphertext_hash(&sealed.ciphertext)?)
}

/// The identity SPP hashes the owner as, one list serves every owner curve.
fn owner_member(output: &SppProofOutputUtxo) -> Result<Member, RingError> {
    let address = output
        .owner_address
        .as_ref()
        .ok_or(RingError::InvalidDummyOutput)?;
    Ok(Member::from_bytes(
        address.signing_pubkey.owner_proof_input_hash()?,
    )?)
}

fn input_opening(input: &SppProofInputUtxo) -> Result<CustomRingOpening, RingError> {
    if input.is_dummy() {
        return Ok(CustomRingOpening {
            domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
            ..CustomRingOpening::default()
        });
    }
    let utxo = &input.utxo;
    Ok(CustomRingOpening {
        domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
        tree_id: tree_id_field(input.tree_id),
        owner_pk_hash: utxo.owner.owner_proof_input_hash()?,
        nullifier_pk: input.nullifier_pubkey,
        asset: hash_bytes(utxo.asset.asset.as_array())?,
        amount: right_align(&utxo.amount.to_be_bytes()),
        blinding: utxo.blinding,
        data_hash: input.data_hash.unwrap_or_default(),
        ring_data_hash: input.ring_data_hash.unwrap_or_default(),
        ring_program_id: ring_field(utxo.ring_program_id.as_ref())?,
    })
}

fn output_opening(
    output: &SppProofOutputUtxo,
    tree_id: u16,
) -> Result<CustomRingOpening, RingError> {
    let Some(address) = output.owner_address.as_ref() else {
        return Ok(CustomRingOpening {
            domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
            tree_id: tree_id_field(tree_id),
            blinding: output.blinding,
            ..CustomRingOpening::default()
        });
    };
    Ok(CustomRingOpening {
        domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
        tree_id: tree_id_field(tree_id),
        owner_pk_hash: address.signing_pubkey.owner_proof_input_hash()?,
        nullifier_pk: address.nullifier_pubkey,
        asset: hash_bytes(output.asset.asset.as_array())?,
        amount: right_align(&output.amount.to_be_bytes()),
        blinding: output.blinding,
        data_hash: output.data_hash.unwrap_or_default(),
        ring_data_hash: output.ring_data_hash.unwrap_or_default(),
        ring_program_id: ring_field(output.ring_program_id.as_ref())?,
    })
}

/// An absent ring id is the zero field element, not the hash of a zero address.
fn ring_field(ring: Option<&Address>) -> Result<[u8; 32], RingError> {
    ring.map_or(Ok([0; 32]), |address| Ok(hash_bytes(address.as_array())?))
}

#[cfg(test)]
#[path = "tests/witness.rs"]
mod tests;
