//! The policy half of the ring proof, the openings of the prepared transfer and
//! the entry facts the rules name.

use futures::future::try_join_all;
use serde::Serialize;
use zolana_client::{
    prover::indexed::{IndexedPolicyLookup, IndexedRegistry, ResolvedProofTree},
    AsyncRpc, IndexerRpcConfig, MerkleProof, NonInclusionProof,
};
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::{
    tree_slot::{tree_id_field, TreeSlot},
    DUMMY_DOMAIN, INPUT_TREES, UTXO_DOMAIN,
};
use zolana_ring_policy::{
    EntryState, Guard, ListId, ListNamespace, Member, Mode, Rule, SourceOwner, Subject,
    ANSWER_SLOTS, MAX_INLINE_ASSETS, MAX_RULES, MAX_SOURCES, POLICY_INPUT_SLOTS,
    POLICY_OUTPUT_SLOTS,
};
use zolana_transaction::{instructions::transact::SppProofOutputUtxo, utxo::SppProofInputUtxo};

use crate::{
    account::source_map,
    entry::{walk, EntryLookup, LineageLookup},
    escrow::{EscrowedKeys, KeyRegistry, OutputKey},
    prover::fe,
    request::{sources, tree_slots, CustomRingOpening, Escrow, RuleAnswer},
    trees::{read_tree, TransactRoots},
    EscrowBinding, LiveEntry, PinnedPolicy, PolicyReads, PolicyTreeContext, PoolTree, RingError,
    VelocityProofInput,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PolicyTree {
    pub tree: PoolTree,
    pub roots: TransactRoots,
}

impl PolicyTree {
    pub fn slot(&self) -> TreeSlot {
        self.roots.slot(self.tree.id)
    }

    pub fn resolved(&self) -> ResolvedProofTree {
        ResolvedProofTree {
            tree: self.tree.address,
            id: self.tree.id,
            utxo_root: self.roots.state,
            nullifier_root: self.roots.nullifier,
            context: self.roots.context(),
        }
    }
}

/// The policy witness, in the wire order of the policy body after the audit fields.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CustomRingWitness {
    #[serde(skip)]
    pub indexed: Option<Vec<IndexedPolicyLookup>>,
    #[serde(skip)]
    pub indexed_registry: Option<IndexedRegistry>,
    pub n_in: u8,
    pub n_out: u8,
    pub inputs: [CustomRingOpening; POLICY_INPUT_SLOTS],
    pub outputs: [CustomRingOpening; POLICY_OUTPUT_SLOTS],
    #[serde(serialize_with = "fe::zero")]
    pub address_chain: (),
    #[serde(with = "fe")]
    pub private_tx_blinding: [u8; 32],
    #[serde(serialize_with = "sources")]
    pub sources: [SourceOwner; MAX_SOURCES],
    pub policy_len: u8,
    /// The account rows verbatim, the pinned hash binds them.
    #[serde(rename = "ruleEnc", serialize_with = "fe::seq")]
    pub rules: [[u8; 32]; MAX_RULES],
    #[serde(serialize_with = "fe::seq")]
    pub inline_assets: [[u8; 32]; MAX_INLINE_ASSETS],
    #[serde(serialize_with = "fe::ints")]
    pub inline_limits: [u64; MAX_INLINE_ASSETS],
    pub inline_count: u8,
    /// In slot order, at most `INPUT_TREES`.
    #[serde(rename = "treeSlots", serialize_with = "tree_slots")]
    pub trees: Vec<PolicyTree>,
    #[serde(serialize_with = "fe::short")]
    pub address_tree_id: u16,
    #[serde(flatten)]
    pub escrow: Escrow,
    #[serde(flatten)]
    pub velocity: VelocityProofInput,
    pub answers: Vec<RuleAnswer>,
    #[serde(skip)]
    pub revocation_targets: [[u8; 32]; ANSWER_SLOTS],
    #[serde(skip)]
    pub revocation_tree_indexes: [u8; ANSWER_SLOTS],
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
            escrow: EscrowBinding::of(self.escrow.0),
            revocation_targets: self.revocation_targets,
            revocation_tree_indexes: self.revocation_tree_indexes,
        }
    }
}

/// What the policy witness reads at prove time.
pub(crate) struct WitnessInput<'a> {
    pub pinned: &'a PinnedPolicy,
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
    /// The tree the outputs are appended to, every output hashes under it.
    pub output_tree_id: u16,
    pub private_tx_blinding: [u8; 32],
    pub velocity: VelocityProofInput,
    /// A windowed rail places the record at the last real input and the last output.
    pub record: bool,
    pub key_registry: Option<KeyRegistry>,
    /// The entries are read once the indexer persisted `require_slot`.
    pub indexer_config: Option<IndexerRpcConfig>,
}

struct Demand {
    member: Member,
    /// `(lookup, mode)` per alternative of the rule.
    alternatives: Vec<(usize, Mode)>,
}

#[derive(Clone, Copy)]
enum EntryFact {
    /// A never claimed address proves absence by its own non-inclusion.
    Unclaimed {
        address: [u8; 32],
    },
    Live(LiveEntry),
}

impl EntryFact {
    fn satisfies(&self, mode: Mode) -> bool {
        let active = matches!(self, Self::Live(live) if live.entry.state == EntryState::Active);
        active == (mode == Mode::Present)
    }

    fn state_leaf(&self) -> Option<[u8; 32]> {
        match self {
            Self::Unclaimed { .. } => None,
            Self::Live(live) => Some(live.utxo_hash),
        }
    }

    fn absence_target(&self) -> [u8; 32] {
        match self {
            Self::Unclaimed { address } => *address,
            Self::Live(live) => live.nullifier,
        }
    }

    fn tree(&self, address_tree: PoolTree) -> PoolTree {
        match self {
            Self::Unclaimed { .. } => address_tree,
            Self::Live(live) => address_tree.sibling(live.tree_id),
        }
    }
}

struct Answer {
    list_id: ListId,
    member: Member,
    mode: Mode,
    fact: EntryFact,
    /// Index into the statement's trees.
    slot: u8,
}

struct TreeProofs {
    roots: TransactRoots,
    states: Vec<MerkleProof>,
    absences: Vec<NonInclusionProof>,
}

impl<'a> WitnessInput<'a> {
    /// Refuses client-side with a named rule before any prover round.
    pub async fn build(
        self,
        client: &(impl AsyncRpc + ?Sized),
        indexed: bool,
    ) -> Result<CustomRingWitness, RingError> {
        let (lookups, demands) = self.plan()?;
        let lineages = walk(client, &lookups, self.indexer_config).await?;
        let facts = lookups
            .iter()
            .zip(lineages)
            .map(|(lookup, live)| {
                Ok(match live {
                    None => EntryFact::Unclaimed {
                        address: lookup.address()?,
                    },
                    Some(live) => EntryFact::Live(live),
                })
            })
            .collect::<Result<Vec<_>, RingError>>()?;
        let address_tree = PoolTree::address_tree(&self.pinned.config);
        let (answers, trees) = resolve(&lookups, &demands, &facts, address_tree)?;
        let proofs = try_join_all(trees.iter().enumerate().map(|(slot, &tree)| {
            let answers = answers
                .iter()
                .filter(move |answer| usize::from(answer.slot) == slot);
            fetch(client, tree, answers, indexed)
        }))
        .await?;
        let escrow = match self.key_registry {
            Some(registry) if indexed => Some(registry.pending(client).await?),
            Some(registry) => Some(registry.openings(client, &self.output_keys()?).await?),
            None => None,
        };
        self.assemble(answers, trees, proofs, escrow, indexed)
    }

    /// One demand per rule subject the guard does not exempt, lookups deduplicated.
    fn plan(&self) -> Result<(Vec<EntryLookup>, Vec<Demand>), RingError> {
        if self.inputs.len() > POLICY_INPUT_SLOTS || self.outputs.len() > POLICY_OUTPUT_SLOTS {
            return Err(RingError::PolicyShapeUnsupported);
        }
        let sources = source_map(&self.pinned.config)?;
        let mut lookups: Vec<EntryLookup> = Vec::new();
        let mut demands = Vec::new();
        for rule in self.pinned.table.rules() {
            let rule_alternatives: Vec<(ListId, Mode)> = rule.alternatives().collect();
            if rule_alternatives.is_empty() {
                continue;
            }
            for member in self.subjects(rule)? {
                // The circuit needs no answer for an exempt subject, demanding one would refuse the transfer.
                if self.guard_exempts(rule, &member)? {
                    continue;
                }
                let mut alternatives = Vec::with_capacity(rule_alternatives.len());
                for &(list_id, mode) in &rule_alternatives {
                    let owner_hash = sources
                        .owner_hash(list_id)
                        .ok_or(RingError::MissingSourceOwner)?;
                    let lookup = EntryLookup {
                        owner: ListNamespace {
                            owner_hash: *owner_hash,
                        },
                        list_id,
                        member,
                        address_tree_id: self.pinned.config.address_tree_id(),
                    };
                    let index = lookups.iter().position(|known| *known == lookup);
                    alternatives.push((
                        index.unwrap_or_else(|| {
                            lookups.push(lookup);
                            lookups.len() - 1
                        }),
                        mode,
                    ));
                }
                demands.push(Demand {
                    member,
                    alternatives,
                });
            }
        }
        Ok((lookups, demands))
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

    fn active_input_count(&self) -> usize {
        match self.record {
            true => {
                crate::pipeline::record_input_position(self.inputs).map_or(0, |record| record + 1)
            }
            false => self.inputs.len(),
        }
    }

    /// Rule subjects skip the record slot the circuit excludes.
    fn rule_inputs(&self) -> &[SppProofInputUtxo] {
        let count =
            self.active_input_count() - usize::from(self.record && self.active_input_count() > 0);
        &self.inputs[..count]
    }

    /// Compact padding trails the record, so the record is the last active output.
    fn active_output_count(&self) -> usize {
        self.outputs
            .iter()
            .filter(|output| !output.is_compact())
            .count()
    }

    fn rule_outputs(&self) -> &[SppProofOutputUtxo] {
        let active = self.active_output_count();
        let count = active - usize::from(self.record && active > 0);
        self.outputs.get(..count).unwrap_or_default()
    }

    fn subjects(&self, rule: &Rule) -> Result<Vec<Member>, RingError> {
        let owned = self
            .rule_outputs()
            .iter()
            .filter(|output| output.owner_address.is_some());
        match rule.subject {
            Subject::OutputOwner => owned.map(owner_member).collect(),
            Subject::Sender => self
                .rule_inputs()
                .iter()
                .filter(|input| !input.is_dummy())
                .map(|input| {
                    Ok(Member::from_bytes(
                        input.utxo.owner.owner_proof_input_hash()?,
                    )?)
                })
                .collect(),
            // The circuit ranges asset rules over live outputs, hashing the mint as the opening does.
            Subject::Asset => owned
                .map(|output| Ok(Member::asset(&output.asset.asset)?))
                .collect(),
            // The rule table refuses this subject until a settlement-aware circuit exists.
            Subject::ExitDestination => Ok(Vec::new()),
        }
    }

    /// Unowned slots and namespace-owned records carry no key.
    fn output_keys(&self) -> Result<Vec<Option<OutputKey>>, RingError> {
        self.outputs
            .iter()
            .map(|output| {
                let Some(address) = output.owner_address.as_ref() else {
                    return Ok(None);
                };
                // Escrow admits the zero key only on the namespace owner, whose hash binds it.
                if address.owner_hash()? == self.pinned.config.namespace_owner_hash {
                    return Ok(None);
                }
                Ok(Some(OutputKey {
                    owner_pk_hash: address.signing_pubkey.owner_proof_input_hash()?,
                    nullifier_pk: address.nullifier_pubkey,
                }))
            })
            .collect()
    }

    fn assemble(
        self,
        answers: Vec<Answer>,
        trees: Vec<PoolTree>,
        proofs: Vec<TreeProofs>,
        escrow: Option<EscrowedKeys>,
        indexed: bool,
    ) -> Result<CustomRingWitness, RingError> {
        let mut lookups = Vec::with_capacity(ANSWER_SLOTS);
        let mut rule_answers = Vec::with_capacity(ANSWER_SLOTS);
        let mut revocation_targets = [[0; 32]; ANSWER_SLOTS];
        let mut revocation_tree_indexes = [0; ANSWER_SLOTS];
        let mut cursors = vec![(0, 0); proofs.len()];
        for (index, answer) in answers.iter().enumerate() {
            let slot = usize::from(answer.slot);
            let target = answer.fact.absence_target();
            lookups.push(IndexedPolicyLookup {
                tree_slot: answer.slot,
                commitment: answer.fact.state_leaf(),
                nullifier: Some(target),
            });
            revocation_targets[index] = target;
            revocation_tree_indexes[index] = answer.slot;
            let mut entry = RuleAnswer {
                enabled: true,
                tree_slot: answer.slot,
                mode: answer.mode as u8,
                list_id: answer.list_id as u8,
                member: *answer.member.as_bytes(),
                absent_branch: 1,
                ..RuleAnswer::default()
            };
            let (states, absences) = &mut cursors[slot];
            if !indexed {
                let absence = proofs[slot]
                    .absences
                    .get(*absences)
                    .ok_or(RingError::IncompleteProofSet)?;
                *absences += 1;
                entry.low = absence.low_element;
                entry.next = absence.high_element;
                entry.nullifier_path = absence.path.clone();
                entry.nullifier_path_index = absence.low_element_index;
            }
            if let EntryFact::Live(live) = answer.fact {
                entry.absent_branch = 2;
                entry.state = live.entry.state as u8;
                entry.version = live.entry.version;
                entry.blinding = live.entry.blinding;
                entry.content_hash = live.entry.content_hash;
                if !indexed {
                    let state = proofs[slot]
                        .states
                        .get(*states)
                        .ok_or(RingError::IncompleteProofSet)?;
                    *states += 1;
                    entry.state_path = state.path.clone();
                    entry.state_path_index = state.leaf_index;
                }
            }
            rule_answers.push(entry);
        }
        if cursors
            .iter()
            .zip(&proofs)
            .any(|((states, absences), proofs)| {
                *states != proofs.states.len() || *absences != proofs.absences.len()
            })
        {
            return Err(RingError::IncompleteProofSet);
        }
        rule_answers.resize_with(ANSWER_SLOTS, RuleAnswer::default);
        lookups.resize_with(ANSWER_SLOTS, || IndexedPolicyLookup {
            tree_slot: 0,
            commitment: None,
            nullifier: None,
        });
        let keys = escrow
            .as_ref()
            .map_or(&[][..], |escrow| escrow.keys.as_slice());
        let mut inputs = [CustomRingOpening::default(); POLICY_INPUT_SLOTS];
        for (slot, input) in inputs.iter_mut().zip(self.inputs) {
            *slot = input_opening(input)?;
        }
        let mut outputs = [CustomRingOpening::default(); POLICY_OUTPUT_SLOTS];
        for (index, (slot, output)) in outputs.iter_mut().zip(self.outputs).enumerate() {
            *slot = CustomRingOpening {
                key: keys.get(index).copied().flatten(),
                ..output_opening(output, self.output_tree_id)?
            };
        }
        let config = &self.pinned.config;
        let table = &config.rules;
        let indexed_registry = escrow
            .as_ref()
            .zip(self.key_registry)
            .filter(|_| indexed)
            .map(|(escrow, registry)| IndexedRegistry {
                ring_program_id: registry.ring.program_id(),
                root: escrow.root.root,
                next_index: escrow.root.next_index,
            });
        Ok(CustomRingWitness {
            indexed: indexed.then_some(lookups),
            indexed_registry,
            n_in: self.active_input_count() as u8,
            n_out: self.active_output_count() as u8,
            inputs,
            outputs,
            address_chain: (),
            private_tx_blinding: self.private_tx_blinding,
            sources: *source_map(config)?.slots(),
            policy_len: table.rule_count,
            rules: table.rules,
            inline_assets: table.inline_assets,
            inline_limits: table.inline_limits.map(u64::from_be_bytes),
            inline_count: table.inline_count,
            trees: trees
                .into_iter()
                .zip(&proofs)
                .map(|(tree, proofs)| PolicyTree {
                    tree,
                    roots: proofs.roots,
                })
                .collect(),
            address_tree_id: config.address_tree_id(),
            escrow: Escrow(escrow.map(|escrow| escrow.root)),
            velocity: self.velocity,
            answers: rule_answers,
            revocation_targets,
            revocation_tree_indexes,
        })
    }
}

/// One answer per distinct question, the first alternative the facts satisfy.
/// The facts span at most `INPUT_TREES` trees.
fn resolve(
    lookups: &[EntryLookup],
    demands: &[Demand],
    facts: &[EntryFact],
    address_tree: PoolTree,
) -> Result<(Vec<Answer>, Vec<PoolTree>), RingError> {
    let mut answers: Vec<Answer> = Vec::new();
    for demand in demands {
        let &(lookup, mode) = demand
            .alternatives
            .iter()
            .find(|(lookup, mode)| facts[*lookup].satisfies(*mode))
            .ok_or(RingError::PolicyRuleUnsatisfied)?;
        let list_id = lookups[lookup].list_id;
        if !answers.iter().any(|known| {
            known.list_id == list_id && known.member == demand.member && known.mode == mode
        }) {
            answers.push(Answer {
                list_id,
                member: demand.member,
                mode,
                fact: facts[lookup],
                slot: 0,
            });
        }
    }
    if answers.len() > ANSWER_SLOTS {
        return Err(RingError::PolicyShapeUnsupported);
    }
    // Unclaimed addresses live in the address tree, a statement without facts still binds it.
    let mut trees = Vec::with_capacity(INPUT_TREES);
    if answers.is_empty()
        || answers
            .iter()
            .any(|answer| matches!(answer.fact, EntryFact::Unclaimed { .. }))
    {
        trees.push(address_tree);
    }
    for answer in &mut answers {
        let tree = answer.fact.tree(address_tree);
        let slot = trees
            .iter()
            .position(|known| *known == tree)
            .unwrap_or_else(|| {
                trees.push(tree);
                trees.len() - 1
            });
        answer.slot = slot as u8;
    }
    if trees.len() > INPUT_TREES {
        return Err(RingError::TooManyPolicyTrees { count: trees.len() });
    }
    Ok((answers, trees))
}

/// The live roots, replaced by the one root each kind of proof was served under.
async fn fetch<'a>(
    client: &(impl AsyncRpc + ?Sized),
    tree: PoolTree,
    answers: impl Iterator<Item = &'a Answer>,
    indexed: bool,
) -> Result<TreeProofs, RingError> {
    let view = read_tree(client, tree.address).await?;
    if view.tree.id != tree.id {
        return Err(RingError::TreeIdMismatch {
            tree: tree.address,
            expected: view.tree.id,
            found: tree.id,
        });
    }
    let mut roots = view.roots;
    let facts: Vec<EntryFact> = answers.map(|answer| answer.fact).collect();
    if indexed {
        return Ok(TreeProofs {
            roots,
            states: Vec::new(),
            absences: Vec::new(),
        });
    }
    let leaves: Vec<_> = facts.iter().filter_map(EntryFact::state_leaf).collect();
    let targets: Vec<_> = facts.iter().map(EntryFact::absence_target).collect();
    let states = match leaves.is_empty() {
        true => Vec::new(),
        false => {
            client
                .get_merkle_proofs(tree.address, leaves.clone(), None)
                .await?
                .proofs
        }
    };
    let absences = client
        .get_non_inclusion_proofs(tree.address, targets.clone(), None)
        .await?
        .proofs;
    if states.len() != leaves.len() || absences.len() != targets.len() {
        return Err(RingError::IncompleteProofSet);
    }
    for (index, (proof, leaf)) in states.iter().zip(&leaves).enumerate() {
        proof.check_leaf(leaf, &tree.address, index)?;
    }
    for (index, (proof, target)) in absences.iter().zip(&targets).enumerate() {
        proof.check_leaf(target, &tree.address, index)?;
    }
    if let Some((state, index)) =
        single_root(states.iter().map(|proof| (proof.root, proof.root_index)))?
    {
        (roots.state, roots.state_index) = (state, index);
    }
    if let Some((nullifier, index)) =
        single_root(absences.iter().map(|proof| (proof.root, proof.root_index)))?
    {
        (roots.nullifier, roots.nullifier_index) = (nullifier, index);
    }
    Ok(TreeProofs {
        roots,
        states,
        absences,
    })
}

/// A tree slot binds one root of each kind.
fn single_root(
    mut roots: impl Iterator<Item = ([u8; 32], u16)>,
) -> Result<Option<([u8; 32], u16)>, RingError> {
    let Some(first) = roots.next() else {
        return Ok(None);
    };
    if roots.any(|root| root != first) {
        return Err(RingError::PolicyRootMismatch);
    }
    Ok(Some(first))
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
        key: None,
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
        key: None,
    })
}

/// An absent ring id is the zero field element, not the hash of a zero address.
fn ring_field(ring: Option<&solana_address::Address>) -> Result<[u8; 32], RingError> {
    ring.map_or(Ok([0; 32]), |address| Ok(hash_bytes(address.as_array())?))
}
