//! Assembles the policy half of the ring proof. The openings come from the
//! transfer the SDK already prepared, the answers from the entries the
//! rules name.

use custom_ring_interface::PolicyConfig;
use solana_account::Account;
use solana_address::Address;
use zolana_client::{AsyncRpc, MerkleProof, NonInclusionProof, Rpc};
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::{
    instruction::instruction_data::transact::TreeContext,
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR,
    tree_slot::{tree_id_field, TreeSlot},
    DUMMY_DOMAIN, INPUT_TREES, SHIELDED_POOL_PROGRAM_ID, UTXO_DOMAIN,
};
use zolana_ring_policy::{
    EntryState, Guard, ListId, ListNamespace, Member, Mode, Rule, RuleTable, SourceMap, Subject,
    ANSWER_SLOTS, MAX_INLINE_ASSETS, MAX_RULES, MAX_SOURCES, POLICY_INPUT_SLOTS,
    POLICY_OUTPUT_SLOTS,
};
use zolana_transaction::{instructions::transact::SppProofOutputUtxo, utxo::SppProofInputUtxo};
use zolana_tree::TreeAccount;

use crate::{
    escrow::{EscrowedKeys, KeyRegistry, OutputKey},
    instructions::entry::{EntryLookup, LineageLookup, Lineages, LiveEntry},
    instructions::spend::ReadEnvironment,
    instructions::transact::{
        CustomRingOpening, EscrowBinding, PolicyReads, PolicyTreeContext, RuleAnswer,
        SourceOwnerEntry, VelocityProofInput, NULLIFIER_PATH_LEN, STATE_PATH_LEN,
    },
    shared::source_map,
    IndexedMapRoot, PoolTree, TransferError,
};

/// Roots the statement binds, with the history entries they were read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactRoots {
    pub state: [u8; 32],
    pub state_index: u16,
    pub nullifier: [u8; 32],
    pub nullifier_index: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyTree {
    pub tree: PoolTree,
    pub roots: TransactRoots,
}

impl PolicyTree {
    pub fn slot(&self) -> TreeSlot {
        TreeSlot::new(self.tree.id, self.roots.state, self.roots.nullifier)
    }

    pub fn context(&self) -> PolicyTreeContext {
        PolicyTreeContext {
            tree: self.tree.address,
            context: TreeContext {
                utxo_tree_root_index: self.roots.state_index,
                nullifier_tree_root_index: self.roots.nullifier_index,
            },
        }
    }
}

/// The policy witness of one transfer, serialized into the proof request.
pub struct CustomRingWitness {
    /// In slot order, at most `INPUT_TREES`.
    pub trees: Vec<PolicyTree>,
    pub address_tree_id: u16,
    pub sources: [SourceOwnerEntry; MAX_SOURCES],
    pub inputs: [CustomRingOpening; POLICY_INPUT_SLOTS],
    pub outputs: [CustomRingOpening; POLICY_OUTPUT_SLOTS],
    pub n_in: u8,
    pub n_out: u8,
    /// The account rows verbatim, the pinned hash binds them.
    pub rules: [[u8; 32]; MAX_RULES],
    pub policy_len: u8,
    pub inline_assets: [[u8; 32]; MAX_INLINE_ASSETS],
    pub inline_limits: [u64; MAX_INLINE_ASSETS],
    pub inline_count: u8,
    pub velocity: VelocityProofInput,
    pub answers: Vec<RuleAnswer>,
    pub revocation_targets: [[u8; 32]; ANSWER_SLOTS],
    pub revocation_tree_indexes: [u8; ANSWER_SLOTS],
    /// `None` with escrow off.
    pub key_registry_root: Option<IndexedMapRoot>,
}

impl CustomRingWitness {
    pub fn tree_slots(&self) -> Vec<TreeSlot> {
        self.trees.iter().map(PolicyTree::slot).collect()
    }

    pub fn reads(&self) -> PolicyReads {
        PolicyReads {
            trees: self.trees.iter().map(PolicyTree::context).collect(),
            escrow: EscrowBinding::of(self.key_registry_root),
            revocation_targets: self.revocation_targets,
            revocation_tree_indexes: self.revocation_tree_indexes,
        }
    }
}

/// Gathers the witness from the chain and the indexer at prove time.
#[derive(Clone, Copy)]
pub struct CustomRingWitnessInput<'a> {
    pub policy: &'a RuleTable,
    pub policy_config: &'a PolicyConfig,
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
    /// The tree the outputs are appended to, every output hashes under it.
    pub output_tree_id: u16,
    /// Outflow proof inputs, with a nonzero window only when record slots are present.
    pub velocity: VelocityProofInput,
    /// `None` with escrow off.
    pub key_registry: Option<KeyRegistry>,
}

impl<'a> CustomRingWitnessInput<'a> {
    /// Refuses client-side with a named rule before any prover round.
    pub fn build<I: Rpc, R: Rpc>(
        self,
        indexer: &I,
        rpc: &R,
    ) -> Result<CustomRingWitness, TransferError> {
        let plan = self.plan()?;
        let lineages = plan.lineages().fetch(indexer).map_err(list_entry)?;
        let resolved = plan.resolve(lineages)?;
        let proofs = resolved
            .queries()
            .into_iter()
            .map(|query| query.fetch(indexer, rpc))
            .collect::<Result<Vec<_>, _>>()?;
        let escrow = match self.key_registry {
            Some(registry) => {
                Some(registry.openings(ReadEnvironment { indexer, rpc }, &self.output_keys()?)?)
            }
            None => None,
        };
        resolved.assemble(proofs, escrow)
    }

    pub async fn build_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        indexer: &I,
        rpc: &R,
    ) -> Result<CustomRingWitness, TransferError> {
        let plan = self.plan()?;
        let lineages = plan
            .lineages()
            .fetch_async(indexer)
            .await
            .map_err(list_entry)?;
        let resolved = plan.resolve(lineages)?;
        let proofs = futures::future::try_join_all(
            resolved
                .queries()
                .into_iter()
                .map(|query| query.fetch_async(indexer, rpc)),
        )
        .await?;
        let escrow = match self.key_registry {
            Some(registry) => Some(
                registry
                    .openings_async(ReadEnvironment { indexer, rpc }, &self.output_keys()?)
                    .await?,
            ),
            None => None,
        };
        resolved.assemble(proofs, escrow)
    }

    /// Unowned slots and namespace-owned records carry no key.
    fn output_keys(&self) -> Result<Vec<Option<OutputKey>>, TransferError> {
        self.outputs
            .iter()
            .map(|output| {
                let Some(address) = output.owner_address.as_ref() else {
                    return Ok(None);
                };
                // Escrow admits the zero key only on the namespace owner, whose hash binds it.
                if address
                    .owner_hash()
                    .map_err(|_| TransferError::PolicyHashing)?
                    == self.policy_config.namespace_owner_hash
                {
                    return Ok(None);
                }
                Ok(Some(OutputKey {
                    owner_pk_hash: address
                        .signing_pubkey
                        .owner_proof_input_hash()
                        .map_err(|_| TransferError::PolicyHashing)?,
                    nullifier_pk: address.nullifier_pubkey,
                }))
            })
            .collect()
    }

    fn plan(self) -> Result<WitnessPlan<'a>, TransferError> {
        if self.inputs.len() > POLICY_INPUT_SLOTS || self.outputs.len() > POLICY_OUTPUT_SLOTS {
            return Err(TransferError::PolicyShapeUnsupported);
        }
        let sources = source_map(self.policy_config)?;
        let mut demands = Vec::new();
        let mut lookups: Vec<EntryLookup> = Vec::new();
        for rule in self.policy.rules() {
            let alternatives: Vec<(ListId, Mode)> = rule.alternatives().collect();
            if alternatives.is_empty() {
                continue;
            }
            for member in self.subjects(rule)? {
                // A guarded subject at or below the threshold is exempt, the
                // circuit needs no answer for it and demanding one would refuse a
                // transfer the circuit accepts.
                if self.guard_exempts(rule, &member)? {
                    continue;
                }
                let alternatives = alternatives
                    .iter()
                    .map(|&(list_id, mode)| {
                        let owner_hash = sources
                            .owner_hash(list_id)
                            .ok_or(TransferError::MissingSourceOwner)?;
                        let lookup = EntryLookup {
                            owner: ListNamespace {
                                owner_hash: *owner_hash,
                            },
                            list_id,
                            member,
                            address_tree_id: self.policy_config.address_tree_id(),
                        };
                        let index = lookups
                            .iter()
                            .position(|known| *known == lookup)
                            .unwrap_or_else(|| {
                                lookups.push(lookup);
                                lookups.len() - 1
                            });
                        Ok(Alternative {
                            lookup: index,
                            mode,
                        })
                    })
                    .collect::<Result<Vec<_>, TransferError>>()?;
                demands.push(Demand {
                    alternatives,
                    member,
                });
            }
        }
        Ok(WitnessPlan {
            input: self,
            sources,
            demands,
            lookups,
        })
    }

    /// The rule's guard exempts the subject when the total it receives in the
    /// transaction is at or below the threshold, the same sum the circuit weighs.
    fn guard_exempts(&self, rule: &Rule, member: &Member) -> Result<bool, TransferError> {
        match rule.guard {
            Guard::Always => Ok(false),
            Guard::AboveAmount(threshold) => {
                if matches!(rule.subject, Subject::Sender | Subject::ExitDestination) {
                    return Ok(false);
                }
                Ok(self.subject_total(rule.subject, member)? <= u128::from(threshold))
            }
            Guard::AboveAmountByAsset => self.asset_limits_exempt(member),
        }
    }

    fn asset_limits_exempt(&self, owner: &Member) -> Result<bool, TransferError> {
        let assets = self.policy.inline_assets();
        let limits = self.policy.inline_limits();
        let mut totals = [0u128; MAX_INLINE_ASSETS];
        for output in self.rule_outputs() {
            let Some(address) = output.owner_address.as_ref() else {
                continue;
            };
            if owner_member(address.signing_pubkey.owner_proof_input_hash())? != *owner {
                continue;
            }
            let asset =
                Member::asset(&output.asset.asset).map_err(|_| TransferError::PolicyHashing)?;
            let index = assets
                .iter()
                .position(|known| known == asset.as_bytes())
                .ok_or(TransferError::PolicyAssetUnsupported)?;
            totals[index] += u128::from(output.amount);
        }
        Ok(totals
            .iter()
            .zip(limits)
            .all(|(total, limit)| *total <= u128::from(*limit)))
    }

    /// A windowed ring carries the record as its last input and output.
    fn has_record(&self) -> bool {
        self.velocity.window_slots != 0
    }

    /// Rule subjects skip the record slot the circuit excludes.
    fn rule_inputs(&self) -> &[SppProofInputUtxo] {
        match self.has_record() {
            true => &self.inputs[..self.inputs.len().saturating_sub(1)],
            false => self.inputs,
        }
    }

    fn rule_outputs(&self) -> &[SppProofOutputUtxo] {
        match self.has_record() {
            true => &self.outputs[..self.outputs.len().saturating_sub(1)],
            false => self.outputs,
        }
    }

    /// The total the subject value receives across live outputs, aggregated per
    /// owner or per asset as the circuit does.
    fn subject_total(&self, subject: Subject, member: &Member) -> Result<u128, TransferError> {
        let mut total: u128 = 0;
        for output in self.rule_outputs() {
            let Some(address) = output.owner_address.as_ref() else {
                continue;
            };
            let output_member = match subject {
                Subject::Asset => {
                    Member::asset(&output.asset.asset).map_err(|_| TransferError::PolicyHashing)?
                }
                _ => owner_member(address.signing_pubkey.owner_proof_input_hash())?,
            };
            if output_member == *member {
                total += u128::from(output.amount);
            }
        }
        Ok(total)
    }

    fn subjects(&self, rule: &Rule) -> Result<Vec<Member>, TransferError> {
        match rule.subject {
            Subject::OutputOwner => self
                .rule_outputs()
                .iter()
                .filter_map(|output| output.owner_address.as_ref())
                .map(|address| owner_member(address.signing_pubkey.owner_proof_input_hash()))
                .collect(),
            Subject::Sender => self
                .rule_inputs()
                .iter()
                .filter(|input_utxo| !input_utxo.is_dummy())
                .map(|input_utxo| owner_member(input_utxo.utxo.owner.owner_proof_input_hash()))
                .collect(),
            // The circuit ranges asset rules over live outputs, using the same
            // hashed mint field as output_opening.
            Subject::Asset => self
                .rule_outputs()
                .iter()
                .filter(|output| output.owner_address.is_some())
                .map(|output| {
                    Member::asset(&output.asset.asset).map_err(|_| TransferError::PolicyHashing)
                })
                .collect(),
            // RuleTableBuilder rejects this subject until a settlement-aware
            // circuit plane exists.
            Subject::ExitDestination => Ok(Vec::new()),
        }
    }
}

pub(crate) fn list_entry(error: crate::EntryProofError) -> TransferError {
    TransferError::ListEntry(Box::new(error))
}

struct Demand {
    alternatives: Vec<Alternative>,
    member: Member,
}

struct Alternative {
    lookup: usize,
    mode: Mode,
}

struct WitnessPlan<'a> {
    input: CustomRingWitnessInput<'a>,
    sources: SourceMap,
    demands: Vec<Demand>,
    lookups: Vec<EntryLookup>,
}

impl<'a> WitnessPlan<'a> {
    fn lineages(&self) -> Lineages<'_, EntryLookup> {
        Lineages {
            lookups: &self.lookups,
        }
    }

    /// One answer per demand, the first alternative the entries satisfy.
    fn resolve(
        self,
        lineages: Vec<Option<LiveEntry>>,
    ) -> Result<ResolvedWitness<'a>, TransferError> {
        let facts = self
            .lookups
            .iter()
            .zip(lineages)
            .map(|(lookup, live)| match live {
                None => Ok(EntryFact::Unclaimed {
                    address: lookup.address().map_err(list_entry)?,
                }),
                Some(live) => Ok(EntryFact::Live(live)),
            })
            .collect::<Result<Vec<_>, TransferError>>()?;
        let mut answers: Vec<ResolvedAnswer> = Vec::new();
        for demand in &self.demands {
            let answer = demand
                .alternatives
                .iter()
                .find(|alternative| facts[alternative.lookup].satisfies(alternative.mode))
                .map(|alternative| ResolvedAnswer {
                    list_id: self.lookups[alternative.lookup].list_id,
                    member: demand.member,
                    mode: alternative.mode,
                    fact: facts[alternative.lookup],
                })
                .ok_or(TransferError::PolicyRuleUnsatisfied)?;
            if !answers.iter().any(|known| known.same_question(&answer)) {
                answers.push(answer);
            }
        }
        if answers.len() > ANSWER_SLOTS {
            return Err(TransferError::PolicyShapeUnsupported);
        }
        let facts: Vec<EntryFact> = answers.iter().map(|answer| answer.fact).collect();
        Ok(ResolvedWitness {
            trees: FactTrees::plan(PoolTree::address_tree(self.input.policy_config), &facts)?,
            input: self.input,
            sources: self.sources,
            answers,
        })
    }
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
        let active = match self {
            Self::Unclaimed { .. } => false,
            Self::Live(live) => live.entry.state == EntryState::Active,
        };
        match mode {
            Mode::Present => active,
            Mode::Absent => !active,
        }
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

struct ResolvedAnswer {
    list_id: ListId,
    member: Member,
    mode: Mode,
    fact: EntryFact,
}

impl ResolvedAnswer {
    fn same_question(&self, other: &Self) -> bool {
        self.list_id == other.list_id && self.member == other.member && self.mode == other.mode
    }
}

struct ResolvedWitness<'a> {
    input: CustomRingWitnessInput<'a>,
    sources: SourceMap,
    answers: Vec<ResolvedAnswer>,
    trees: FactTrees,
}

impl ResolvedWitness<'_> {
    /// One query per tree, each tree's leaves in answer order.
    fn queries(&self) -> Vec<TreeQuery> {
        let mut queries: Vec<TreeQuery> = self
            .trees
            .trees
            .iter()
            .map(|&tree| TreeQuery {
                tree,
                states: Vec::new(),
                absences: Vec::new(),
            })
            .collect();
        for (answer, &slot) in self.answers.iter().zip(&self.trees.slots) {
            let query = &mut queries[usize::from(slot)];
            query.states.extend(answer.fact.state_leaf());
            query.absences.push(answer.fact.absence_target());
        }
        queries
    }

    fn assemble(
        self,
        proofs: Vec<TreeProofs>,
        escrow: Option<EscrowedKeys>,
    ) -> Result<CustomRingWitness, TransferError> {
        if proofs.len() != self.trees.trees.len() {
            return Err(TransferError::IncompleteProofSet);
        }
        let policy_trees = proofs.iter().map(TreeProofs::policy_tree).collect();
        let mut proofs: Vec<_> = proofs
            .into_iter()
            .map(|proofs| (proofs.states.into_iter(), proofs.absences.into_iter()))
            .collect();
        let mut answers = Vec::with_capacity(ANSWER_SLOTS);
        let mut revocation_targets = [[0u8; 32]; ANSWER_SLOTS];
        let mut revocation_tree_indexes = [0u8; ANSWER_SLOTS];
        for (index, (answer, &slot)) in self.answers.iter().zip(&self.trees.slots).enumerate() {
            let (states, absences) = &mut proofs[usize::from(slot)];
            let absence = absences.next().ok_or(TransferError::IncompleteProofSet)?;
            revocation_targets[index] = answer.fact.absence_target();
            revocation_tree_indexes[index] = slot;
            let mut entry = RuleAnswer {
                enabled: true,
                tree_slot: slot,
                mode: answer.mode as u8,
                list_id: answer.list_id as u8,
                member: *answer.member.as_bytes(),
                low: absence.low_element,
                next: absence.high_element,
                nullifier_path: padded(absence.path, NULLIFIER_PATH_LEN),
                nullifier_path_index: absence.low_element_index,
                ..RuleAnswer::default()
            };
            match answer.fact {
                EntryFact::Unclaimed { .. } => entry.absent_branch = 1,
                EntryFact::Live(live) => {
                    let state = states.next().ok_or(TransferError::IncompleteProofSet)?;
                    entry.absent_branch = 2;
                    entry.state = live.entry.state as u8;
                    entry.version = live.entry.version;
                    entry.blinding = live.entry.blinding;
                    entry.content_hash = live.entry.content_hash;
                    entry.state_path = padded(state.path, STATE_PATH_LEN);
                    entry.state_path_index = state.leaf_index;
                }
            }
            answers.push(entry);
        }
        if proofs
            .iter_mut()
            .any(|(states, absences)| states.next().is_some() || absences.next().is_some())
        {
            return Err(TransferError::IncompleteProofSet);
        }
        answers.resize_with(ANSWER_SLOTS, RuleAnswer::default);

        let input = self.input;
        let mut inputs = [CustomRingOpening::default(); POLICY_INPUT_SLOTS];
        for (slot, input_utxo) in inputs.iter_mut().zip(input.inputs) {
            *slot = input_opening(input_utxo)?;
        }
        let mut outputs = [CustomRingOpening::default(); POLICY_OUTPUT_SLOTS];
        let keys = escrow
            .as_ref()
            .map_or(&[][..], |escrow| escrow.keys.as_slice());
        for (index, (slot, output)) in outputs.iter_mut().zip(input.outputs).enumerate() {
            *slot = CustomRingOpening {
                key: keys.get(index).copied().flatten(),
                ..output_opening(output, input.output_tree_id)?
            };
        }
        let table = &input.policy_config.rules;
        Ok(CustomRingWitness {
            trees: policy_trees,
            address_tree_id: input.policy_config.address_tree_id(),
            sources: *self.sources.slots(),
            inputs,
            outputs,
            n_in: input.inputs.len() as u8,
            n_out: input.outputs.len() as u8,
            rules: table.rules,
            policy_len: table.rule_count,
            inline_assets: table.inline_assets,
            inline_limits: table.inline_limits.map(u64::from_be_bytes),
            inline_count: table.inline_count,
            velocity: input.velocity,
            answers,
            revocation_targets,
            revocation_tree_indexes,
            key_registry_root: escrow.map(|escrow| escrow.root),
        })
    }
}

struct FactTrees {
    trees: Vec<PoolTree>,
    /// Per fact, its index into `trees`.
    slots: Vec<u8>,
}

impl FactTrees {
    /// Unclaimed addresses live in the address tree, a statement without facts still binds it.
    fn plan(address_tree: PoolTree, facts: &[EntryFact]) -> Result<Self, TransferError> {
        let mut trees = Vec::with_capacity(INPUT_TREES);
        if facts.is_empty()
            || facts
                .iter()
                .any(|fact| matches!(fact, EntryFact::Unclaimed { .. }))
        {
            trees.push(address_tree);
        }
        let mut slots = Vec::with_capacity(facts.len());
        for fact in facts {
            let tree = fact.tree(address_tree);
            let slot = trees
                .iter()
                .position(|known| *known == tree)
                .unwrap_or_else(|| {
                    trees.push(tree);
                    trees.len() - 1
                });
            slots.push(slot);
        }
        if trees.len() > INPUT_TREES {
            return Err(TransferError::TooManyPolicyTrees { count: trees.len() });
        }
        Ok(Self {
            trees,
            // Below `INPUT_TREES`, every slot fits a byte.
            slots: slots.into_iter().map(|slot| slot as u8).collect(),
        })
    }
}

fn padded(mut path: Vec<[u8; 32]>, len: usize) -> Vec<[u8; 32]> {
    path.resize(len, [0u8; 32]);
    path
}

struct TreeQuery {
    tree: PoolTree,
    states: Vec<[u8; 32]>,
    absences: Vec<[u8; 32]>,
}

struct TreeProofs {
    tree: PoolTree,
    current: TransactRoots,
    states: Vec<MerkleProof>,
    absences: Vec<NonInclusionProof>,
}

impl TreeQuery {
    fn fetch<I: Rpc, R: Rpc>(self, indexer: &I, rpc: &R) -> Result<TreeProofs, TransferError> {
        let current = current_roots(rpc.get_account(self.tree.address)?, self.tree)?;
        let states = if self.states.is_empty() {
            Vec::new()
        } else {
            indexer
                .get_merkle_proofs(self.tree.address, self.states.clone(), None)?
                .proofs
        };
        let absences = if self.absences.is_empty() {
            Vec::new()
        } else {
            indexer
                .get_non_inclusion_proofs(self.tree.address, self.absences.clone(), None)?
                .proofs
        };
        self.proofs(TreeProofs {
            tree: self.tree,
            current,
            states,
            absences,
        })
    }

    async fn fetch_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        indexer: &I,
        rpc: &R,
    ) -> Result<TreeProofs, TransferError> {
        let current = current_roots(rpc.get_account(self.tree.address).await?, self.tree)?;
        let states = if self.states.is_empty() {
            Vec::new()
        } else {
            indexer
                .get_merkle_proofs(self.tree.address, self.states.clone(), None)
                .await?
                .proofs
        };
        let absences = if self.absences.is_empty() {
            Vec::new()
        } else {
            indexer
                .get_non_inclusion_proofs(self.tree.address, self.absences.clone(), None)
                .await?
                .proofs
        };
        self.proofs(TreeProofs {
            tree: self.tree,
            current,
            states,
            absences,
        })
    }

    /// `fetched.current` holds the live roots until the answered roots replace them.
    fn proofs(&self, fetched: TreeProofs) -> Result<TreeProofs, TransferError> {
        if fetched.states.len() != self.states.len()
            || fetched.absences.len() != self.absences.len()
        {
            return Err(TransferError::IncompleteProofSet);
        }
        let fixed = FixedRoots::from_proofs(&fetched.states, &fetched.absences)?;
        Ok(TreeProofs {
            current: fixed.at_current(fetched.current),
            ..fetched
        })
    }
}

impl TreeProofs {
    fn policy_tree(&self) -> PolicyTree {
        PolicyTree {
            tree: self.tree,
            roots: self.current,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct HistoryRoot {
    value: [u8; 32],
    index: u16,
}

/// The roots the proof responses fixed, a root no answer touched has none.
struct FixedRoots {
    state: Option<HistoryRoot>,
    nullifier: Option<HistoryRoot>,
}

impl FixedRoots {
    fn from_proofs(
        states: &[MerkleProof],
        absences: &[NonInclusionProof],
    ) -> Result<Self, TransferError> {
        Ok(Self {
            state: single_root(states.iter().map(|proof| HistoryRoot {
                value: proof.root,
                index: proof.root_index,
            }))?,
            nullifier: single_root(absences.iter().map(|proof| HistoryRoot {
                value: proof.root,
                index: proof.root_index,
            }))?,
        })
    }

    fn at_current(self, current: TransactRoots) -> TransactRoots {
        let state = self.state.unwrap_or(HistoryRoot {
            value: current.state,
            index: current.state_index,
        });
        let nullifier = self.nullifier.unwrap_or(HistoryRoot {
            value: current.nullifier,
            index: current.nullifier_index,
        });
        TransactRoots {
            state: state.value,
            state_index: state.index,
            nullifier: nullifier.value,
            nullifier_index: nullifier.index,
        }
    }
}

/// A tree slot binds one root of each kind.
fn single_root(
    mut roots: impl Iterator<Item = HistoryRoot>,
) -> Result<Option<HistoryRoot>, TransferError> {
    let Some(first) = roots.next() else {
        return Ok(None);
    };
    if roots.any(|root| root != first) {
        return Err(TransferError::PolicyRootMismatch);
    }
    Ok(Some(first))
}

fn current_roots(account: Option<Account>, tree: PoolTree) -> Result<TransactRoots, TransferError> {
    let mut account = account.ok_or(TransferError::MissingTree)?;
    if account.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID {
        return Err(TransferError::InvalidTreeOwner);
    }
    if account.data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(TransferError::InvalidTreeDiscriminator);
    }
    let mut tree_account = TreeAccount::from_bytes(&mut account.data, tree.address.to_bytes())?;
    if tree_account.tree_id() != tree.id {
        return Err(TransferError::TreeIdMismatch {
            tree: tree.address,
            expected: tree_account.tree_id(),
            found: tree.id,
        });
    }
    let state_index = tree_account.utxo_tree().current_root_index();
    let state = tree_account.get_utxo_tree_root(state_index)?;
    let nullifier_index = tree_account.nullifier_tree().get_root_index() as u16;
    let nullifier = tree_account.get_nullifier_tree_root(nullifier_index)?;
    Ok(TransactRoots {
        state,
        state_index,
        nullifier,
        nullifier_index,
    })
}

/// The identity SPP hashes the owner as, one list serves every owner curve.
fn owner_member(
    identity: Result<[u8; 32], zolana_keypair::KeypairError>,
) -> Result<Member, TransferError> {
    let identity = identity.map_err(|_| TransferError::PolicyHashing)?;
    Member::owner_identity(&identity).map_err(|_| TransferError::PolicyHashing)
}

fn input_opening(input_utxo: &SppProofInputUtxo) -> Result<CustomRingOpening, TransferError> {
    if input_utxo.is_dummy() {
        return Ok(CustomRingOpening {
            domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
            ..CustomRingOpening::default()
        });
    }
    Ok(CustomRingOpening {
        domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
        tree_id: tree_id_field(input_utxo.tree_id),
        owner_pk_hash: input_utxo
            .utxo
            .owner
            .owner_proof_input_hash()
            .map_err(|_| TransferError::PolicyHashing)?,
        nullifier_pk: input_utxo.nullifier_pubkey,
        asset: asset_field(&input_utxo.utxo.asset.asset)?,
        amount: right_align(&input_utxo.utxo.amount.to_be_bytes()),
        blinding: input_utxo.utxo.blinding,
        data_hash: input_utxo.data_hash.unwrap_or_default(),
        ring_data_hash: input_utxo.ring_data_hash.unwrap_or_default(),
        ring_program_id: ring_field(input_utxo.utxo.ring_program_id.as_ref())?,
        key: None,
    })
}

fn output_opening(
    output: &SppProofOutputUtxo,
    tree_id: u16,
) -> Result<CustomRingOpening, TransferError> {
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
        owner_pk_hash: address
            .signing_pubkey
            .owner_proof_input_hash()
            .map_err(|_| TransferError::PolicyHashing)?,
        nullifier_pk: address.nullifier_pubkey,
        asset: asset_field(&output.asset.asset)?,
        amount: right_align(&output.amount.to_be_bytes()),
        blinding: output.blinding,
        data_hash: output.data_hash.unwrap_or_default(),
        ring_data_hash: output.ring_data_hash.unwrap_or_default(),
        ring_program_id: ring_field(output.ring_program_id.as_ref())?,
        key: None,
    })
}

fn asset_field(asset: &Address) -> Result<[u8; 32], TransferError> {
    hash_bytes(asset.as_array()).map_err(|_| TransferError::PolicyHashing)
}

/// An absent ring id is the zero field element, not the hash of a zero address.
fn ring_field(ring: Option<&Address>) -> Result<[u8; 32], TransferError> {
    match ring {
        None => Ok([0u8; 32]),
        Some(address) => hash_bytes(address.as_array()).map_err(|_| TransferError::PolicyHashing),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use custom_ring_interface::{PolicyConfig, SourceSlot, N_SOURCE_SLOTS, POLICY_CONFIG};
    use solana_pubkey::Pubkey;
    use zolana_client::{
        rpc::GetShieldedTransactionsByNullifiersResponse, ClientError, Context,
        GetMerkleProofsResponse, GetNonInclusionProofsResponse, IndexerRpcConfig, MerkleContext,
        ShieldedTransaction,
    };
    use zolana_interface::state::{default_tree_fees, nullifier_tree_params};
    use zolana_keypair::ShieldedKeypair;
    use zolana_ring_policy::{ListSet, ZERO_NULLIFIER_PK};

    use super::*;
    use crate::instructions::entry::discovery::tests::{
        lookup, namespace, tree, Lineage, NullifierRpc,
    };
    use crate::RingIdentity;

    const SECOND_TREE_ID: u16 = 9;

    /// The configured address tree, its account id is zero.
    fn address_tree() -> PoolTree {
        PoolTree {
            address: tree(),
            id: 0,
        }
    }

    /// Every referenced list reads the ring's own entries.
    fn velocity_off() -> VelocityProofInput {
        VelocityProofInput::off(RingIdentity {
            ring_id: [0u8; 32],
            namespace_owner_hash: [0u8; 32],
        })
    }

    fn config(policy: &RuleTable) -> PolicyConfig {
        let mut sources = [SourceSlot {
            list_id: 0,
            namespace: Address::default(),
        }; N_SOURCE_SLOTS];
        for list_id in policy.referenced().iter() {
            sources[list_id.slot()] = SourceSlot {
                list_id: list_id as u8,
                namespace: namespace(),
            };
        }
        PolicyConfig {
            discriminator: POLICY_CONFIG,
            policy_hash: [0; 32],
            address_tree: tree(),
            address_tree_id: [0; 2],
            namespace_bump: 0,
            namespace_owner_hash: [0u8; 32],
            bump: 0,
            sources,
            rules: policy.encode(),
            generation: 1u32.to_le_bytes(),
            generation_slot: [0; 8],
        }
    }

    fn recipient() -> (Member, zolana_keypair::ShieldedAddress) {
        let keypair = ShieldedKeypair::new_ed25519().expect("recipient");
        let address = keypair.shielded_address().expect("address");
        let member = Member::owner_identity(
            &address
                .signing_pubkey
                .owner_proof_input_hash()
                .expect("identity"),
        )
        .expect("member");
        (member, address)
    }

    fn output(address: zolana_keypair::ShieldedAddress, amount: u64) -> SppProofOutputUtxo {
        output_asset(Address::new_from_array([9; 32]), address, amount)
    }

    fn output_asset(
        asset: Address,
        address: zolana_keypair::ShieldedAddress,
        amount: u64,
    ) -> SppProofOutputUtxo {
        SppProofOutputUtxo::new(zolana_transaction::Mint::new(asset, 2), amount, address)
            .expect("output")
    }

    const EMPTY: RuleTable = RuleTable::builder().build();

    const TWO_ALLOW: RuleTable = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow))
        .rule(Rule::require_any(
            Subject::OutputOwner,
            ListSet::of(&[ListId::Allow, ListId::Block]),
        ))
        .build();

    const ASSETS: &[[u8; 32]] = &[[9u8; 32]];

    /// An owner guard needs a single unguarded inline asset beside it.
    const GUARDED: RuleTable = RuleTable::builder()
        .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above(5))
        .rule(Rule::allow_only_assets())
        .inline_assets(ASSETS)
        .build();

    const BLOCK: RuleTable = RuleTable::builder()
        .rule(Rule::forbid(Subject::OutputOwner, ListId::Block))
        .build();

    #[test]
    fn dummy_output_opening_preserves_its_tree_and_blinding() {
        let output = SppProofOutputUtxo {
            blinding: [0x5a; 32],
            ..SppProofOutputUtxo::default()
        };
        let opening = output_opening(&output, 27).expect("dummy opening");
        assert_eq!(opening.domain, right_align(&DUMMY_DOMAIN.to_be_bytes()));
        assert_eq!(opening.tree_id, tree_id_field(27));
        assert_eq!(opening.blinding, output.blinding);
        assert_eq!(opening.owner_pk_hash, [0u8; 32]);
        assert_eq!(opening.nullifier_pk, [0u8; 32]);
        assert_eq!(opening.asset, [0u8; 32]);
        assert_eq!(opening.amount, [0u8; 32]);
        assert_eq!(opening.data_hash, [0u8; 32]);
        assert_eq!(opening.ring_data_hash, [0u8; 32]);
        assert_eq!(opening.ring_program_id, [0u8; 32]);
    }

    #[test]
    fn only_the_namespace_owned_record_skips_its_key_opening() {
        let mut config = config(&EMPTY);
        config.namespace_owner_hash = ListNamespace::new(namespace().as_array())
            .expect("namespace")
            .owner_hash;
        let (_, member) = recipient();
        let record = zolana_keypair::ShieldedAddress::for_pda(
            &namespace(),
            ZERO_NULLIFIER_PK,
            member.viewing_pubkey,
        );
        let zero_key = zolana_keypair::ShieldedAddress {
            nullifier_pubkey: ZERO_NULLIFIER_PK,
            ..member
        };
        let outputs = [
            output(record, 0),
            output(zero_key, 1),
            SppProofOutputUtxo::default(),
        ];
        let input = CustomRingWitnessInput {
            policy: &EMPTY,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        };
        let refused = OutputKey {
            owner_pk_hash: member
                .signing_pubkey
                .owner_proof_input_hash()
                .expect("identity"),
            nullifier_pk: ZERO_NULLIFIER_PK,
        };
        assert_eq!(
            input.output_keys().expect("keys"),
            vec![None, Some(refused), None]
        );
    }

    /// An approval overrides a block.
    const MIXED: RuleTable = RuleTable::builder()
        .rule(Rule::any_of(
            Subject::OutputOwner,
            ListSet::single(ListId::Approval),
            ListSet::single(ListId::Block),
        ))
        .rule(Rule::allow_only_assets())
        .inline_assets(ASSETS)
        .build();

    #[test]
    fn list_backed_asset_rules_name_each_live_output_asset() {
        let recipient = ShieldedKeypair::new_ed25519().expect("recipient");
        let asset = Address::new_from_array([9; 32]);
        let outputs = [
            SppProofOutputUtxo::new(
                zolana_transaction::Mint::new(asset, 2),
                1,
                recipient.shielded_address().expect("shielded address"),
            )
            .expect("output"),
            SppProofOutputUtxo::default(),
        ];
        let config = config(&EMPTY);
        let input = CustomRingWitnessInput {
            policy: &EMPTY,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        };

        assert_eq!(
            input
                .subjects(&Rule::require(Subject::Asset, ListId::Allow))
                .expect("asset subjects"),
            vec![Member::asset(&asset).expect("asset member")]
        );
    }

    #[test]
    fn a_guarded_rule_exempts_a_recipient_only_below_the_aggregated_threshold() {
        let (member, address) = recipient();
        let config = config(&EMPTY);
        // Two outputs to the same recipient sum to 2500, over the 2000 threshold.
        let outputs = [output(address, 1000), output(address, 1500)];
        let input = CustomRingWitnessInput {
            policy: &EMPTY,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        };
        let guarded = Rule::require(Subject::OutputOwner, ListId::Allow).above(2000);
        assert!(!input
            .guard_exempts(&guarded, &member)
            .expect("aggregated over"));
        assert!(!input
            .guard_exempts(&Rule::require(Subject::OutputOwner, ListId::Allow), &member)
            .expect("no guard"));
        let one = [output(address, 1000)];
        let below = CustomRingWitnessInput {
            policy: &EMPTY,
            policy_config: &config,
            inputs: &[],
            outputs: &one,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        };
        assert!(below
            .guard_exempts(&guarded, &member)
            .expect("below threshold"));
    }

    #[test]
    fn the_guard_sums_exactly_past_the_u64_range() {
        let (member, address) = recipient();
        let (other_member, other_address) = recipient();
        let config = config(&EMPTY);
        let guarded = Rule::require(Subject::OutputOwner, ListId::Allow).above(u64::MAX);
        let one_recipient = [output(address, u64::MAX), output(address, 1)];
        let input = CustomRingWitnessInput {
            policy: &EMPTY,
            policy_config: &config,
            inputs: &[],
            outputs: &one_recipient,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        };
        assert!(!input
            .guard_exempts(&guarded, &member)
            .expect("over the range"));
        let two_recipients = [output(address, u64::MAX), output(other_address, 1)];
        let split = CustomRingWitnessInput {
            policy: &EMPTY,
            policy_config: &config,
            inputs: &[],
            outputs: &two_recipients,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        };
        assert!(split
            .guard_exempts(&guarded, &member)
            .expect("at the threshold"));
        assert!(split
            .guard_exempts(&guarded, &other_member)
            .expect("below the threshold"));
    }

    #[test]
    fn per_asset_guard_uses_each_mint_limit_and_rejects_an_unknown_mint() {
        let (owner, address) = recipient();
        let first = Address::new_from_array([8; 32]);
        let second = Address::new_from_array([9; 32]);
        let members = [
            *Member::asset(&first).expect("first").as_bytes(),
            *Member::asset(&second).expect("second").as_bytes(),
        ];
        let policy = RuleTable::builder()
            .rule(Rule::require(Subject::OutputOwner, ListId::Allow).above_by_asset())
            .inline_assets(&members)
            .inline_limits(&[10, 20])
            .build();
        let config = config(&policy);
        let rule = &policy.rules()[0];
        let below = [
            output_asset(first, address, 4),
            output_asset(first, address, 6),
            output_asset(second, address, 20),
        ];
        let input = CustomRingWitnessInput {
            policy: &policy,
            policy_config: &config,
            inputs: &[],
            outputs: &below,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        };
        assert!(input.guard_exempts(rule, &owner).expect("at both limits"));

        let above = [output_asset(first, address, 11)];
        let input = CustomRingWitnessInput {
            policy: &policy,
            policy_config: &config,
            inputs: &[],
            outputs: &above,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        };
        assert!(!input
            .guard_exempts(rule, &owner)
            .expect("above first limit"));

        let unknown = [output_asset(Address::new_from_array([7; 32]), address, 1)];
        let input = CustomRingWitnessInput {
            policy: &policy,
            policy_config: &config,
            inputs: &[],
            outputs: &unknown,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        };
        assert!(matches!(
            input.guard_exempts(rule, &owner),
            Err(TransferError::PolicyAssetUnsupported)
        ));
    }

    #[test]
    fn a_sender_guard_never_exempts() {
        let (member, _) = recipient();
        let config = config(&EMPTY);
        let input = CustomRingWitnessInput {
            policy: &EMPTY,
            policy_config: &config,
            inputs: &[],
            outputs: &[],
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        };
        let guarded = Rule::require(Subject::Sender, ListId::Allow).above(u64::MAX);
        assert!(!input.guard_exempts(&guarded, &member).expect("sender"));
    }

    struct ProofRpc {
        lineages: NullifierRpc,
        state_roots: Vec<HistoryRoot>,
        nullifier_roots: Vec<HistoryRoot>,
        account: Option<Account>,
        /// Tree accounts besides the address tree.
        others: Vec<(PoolTree, Account)>,
        calls: Mutex<Calls>,
    }

    #[derive(Default)]
    struct Calls {
        merkle: Vec<Vec<[u8; 32]>>,
        non_inclusion: Vec<Vec<[u8; 32]>>,
        /// The tree of every merkle then non-inclusion request, in call order.
        trees: Vec<Address>,
        accounts: usize,
    }

    impl ProofRpc {
        fn new(spenders: Vec<ShieldedTransaction>) -> Self {
            let account = tree_account();
            let current = current_roots(Some(account.clone()), address_tree()).expect("tree roots");
            Self {
                lineages: NullifierRpc::new(spenders),
                state_roots: vec![HistoryRoot {
                    value: current.state,
                    index: current.state_index,
                }],
                nullifier_roots: vec![HistoryRoot {
                    value: current.nullifier,
                    index: current.nullifier_index,
                }],
                account: Some(account),
                others: Vec::new(),
                calls: Mutex::new(Calls::default()),
            }
        }

        fn with_tree(mut self, id: u16) -> Self {
            let tree = PoolTree::from_id(id);
            self.others.push((tree, tree_account_for(tree)));
            self
        }

        fn known(&self, address: Address) -> bool {
            address == tree() || self.others.iter().any(|(tree, _)| tree.address == address)
        }

        fn root(roots: &[HistoryRoot], position: usize) -> HistoryRoot {
            roots[position.min(roots.len() - 1)]
        }
    }

    impl Rpc for ProofRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            self.calls.lock().expect("calls").accounts += 1;
            if address == tree() {
                return Ok(self.account.clone());
            }
            Ok(self
                .others
                .iter()
                .find(|(tree, _)| tree.address == address)
                .map(|(_, account)| account.clone()))
        }

        fn get_shielded_transactions_by_nullifiers(
            &self,
            nullifiers: Vec<[u8; 32]>,
            cursor: Option<Vec<u8>>,
            limit: Option<u32>,
            config: Option<IndexerRpcConfig>,
        ) -> Result<GetShieldedTransactionsByNullifiersResponse, ClientError> {
            Rpc::get_shielded_transactions_by_nullifiers(
                &self.lineages,
                nullifiers,
                cursor,
                limit,
                config,
            )
        }

        fn get_merkle_proofs(
            &self,
            tree_account: Address,
            leaves: Vec<[u8; 32]>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetMerkleProofsResponse, ClientError> {
            assert!(self.known(tree_account));
            let mut calls = self.calls.lock().expect("calls");
            calls.merkle.push(leaves.clone());
            calls.trees.push(tree_account);
            drop(calls);
            let proofs = leaves
                .iter()
                .enumerate()
                .map(|(position, leaf)| {
                    let root = Self::root(&self.state_roots, position);
                    MerkleProof {
                        leaf: *leaf,
                        merkle_context: MerkleContext {
                            tree_type: 0,
                            tree: tree_account,
                        },
                        path: vec![[position as u8; 32]; STATE_PATH_LEN],
                        leaf_index: position as u64,
                        root: root.value,
                        root_seq: 0,
                        root_index: root.index,
                    }
                })
                .collect();
            Ok(GetMerkleProofsResponse {
                context: Context {
                    block_time: 0,
                    slot: 0,
                },
                proofs,
            })
        }

        fn get_non_inclusion_proofs(
            &self,
            tree_account: Address,
            leaves: Vec<[u8; 32]>,
            _config: Option<IndexerRpcConfig>,
        ) -> Result<GetNonInclusionProofsResponse, ClientError> {
            assert!(self.known(tree_account));
            let mut calls = self.calls.lock().expect("calls");
            calls.non_inclusion.push(leaves.clone());
            calls.trees.push(tree_account);
            drop(calls);
            let proofs = leaves
                .iter()
                .enumerate()
                .map(|(position, leaf)| {
                    let root = Self::root(&self.nullifier_roots, position);
                    NonInclusionProof {
                        leaf: *leaf,
                        merkle_context: MerkleContext {
                            tree_type: 1,
                            tree: tree_account,
                        },
                        path: vec![[0u8; 32]; NULLIFIER_PATH_LEN],
                        low_element: [position as u8; 32],
                        low_element_index: position as u64,
                        high_element: [0xff; 32],
                        high_element_index: position as u64 + 1,
                        root: root.value,
                        root_seq: 0,
                        root_index: root.index,
                    }
                })
                .collect();
            Ok(GetNonInclusionProofsResponse {
                context: Context {
                    block_time: 0,
                    slot: 0,
                },
                proofs,
            })
        }
    }

    fn tree_account() -> Account {
        tree_account_for(address_tree())
    }

    fn tree_account_for(tree: PoolTree) -> Account {
        let mut data = vec![0u8; TreeAccount::account_size()];
        let params = nullifier_tree_params();
        TreeAccount::init(
            &mut data,
            TREE_ACCOUNT_DISCRIMINATOR,
            32,
            tree.address.to_bytes(),
            tree.id,
            params,
            default_tree_fees(params.input_queue_zkp_batch_size).expect("default tree fees"),
        )
        .expect("tree account");
        Account {
            lamports: 1,
            data,
            owner: Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
            executable: false,
            rent_epoch: 0,
        }
    }

    #[test]
    fn two_outputs_to_one_recipient_under_two_rules_consult_the_pair_once() {
        let (member, address) = recipient();
        let lineage = Lineage::new(lookup(ListId::Allow, member), &[EntryState::Active]);
        let rpc = ProofRpc::new(lineage.spenders());
        let outputs = [output(address, 10), output(address, 20)];
        let config = config(&TWO_ALLOW);
        let witness = CustomRingWitnessInput {
            policy: &TWO_ALLOW,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        }
        .build(&rpc, &rpc)
        .expect("witness");

        let live = lineage.live().expect("live");
        let calls = rpc.calls.lock().expect("calls");
        assert_eq!(calls.merkle, vec![vec![live.utxo_hash]]);
        assert_eq!(calls.non_inclusion, vec![vec![live.nullifier]]);
        assert_eq!(calls.accounts, 1);
        let requests = rpc.lineages.requests.lock().expect("requests");
        // The claim round asks for both group addresses, the Allow lineage one
        // more round.
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].len(), 2);
        assert_eq!(requests[1], vec![live.nullifier]);
        let enabled: Vec<&RuleAnswer> = witness
            .answers
            .iter()
            .filter(|answer| answer.enabled)
            .collect();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].member, *member.as_bytes());
        assert_eq!(enabled[0].absent_branch, 2);
        assert_eq!(
            witness.trees[0].roots,
            current_roots(Some(tree_account()), address_tree()).expect("current roots")
        );
    }

    #[test]
    fn a_guard_exempt_subject_triggers_no_request() {
        let (_, address) = recipient();
        let mut rpc = ProofRpc::new(Vec::new());
        rpc.account = Some(tree_account());
        let outputs = [output(address, 1)];
        let config = config(&GUARDED);
        let witness = CustomRingWitnessInput {
            policy: &GUARDED,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        }
        .build(&rpc, &rpc)
        .expect("witness");
        assert!(rpc.lineages.requests.lock().expect("requests").is_empty());
        let calls = rpc.calls.lock().expect("calls");
        assert!(calls.merkle.is_empty() && calls.non_inclusion.is_empty());
        assert!(witness.answers.iter().all(|answer| !answer.enabled));
    }

    #[test]
    fn a_missing_entry_refuses_the_transfer_before_any_proof_call() {
        let (_, address) = recipient();
        let rpc = ProofRpc::new(Vec::new());
        let outputs = [output(address, 1)];
        let config = config(&TWO_ALLOW);
        let refused = CustomRingWitnessInput {
            policy: &TWO_ALLOW,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        }
        .build(&rpc, &rpc);
        assert!(matches!(refused, Err(TransferError::PolicyRuleUnsatisfied)));
        let calls = rpc.calls.lock().expect("calls");
        assert!(calls.merkle.is_empty() && calls.non_inclusion.is_empty());
    }

    #[test]
    fn responses_with_two_roots_are_refused() {
        let (member, address) = recipient();
        let (other_member, other_address) = recipient();
        let first = Lineage::new(lookup(ListId::Allow, member), &[EntryState::Active]);
        let second = Lineage::new(lookup(ListId::Allow, other_member), &[EntryState::Active]);
        let mut spenders = first.spenders();
        spenders.extend(second.spenders());
        let mut rpc = ProofRpc::new(spenders);
        rpc.state_roots.push(HistoryRoot {
            value: [5u8; 32],
            index: 5,
        });
        let outputs = [output(address, 1), output(other_address, 1)];
        let config = config(&TWO_ALLOW);
        let refused = CustomRingWitnessInput {
            policy: &TWO_ALLOW,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        }
        .build(&rpc, &rpc);
        assert!(matches!(refused, Err(TransferError::PolicyRootMismatch)));
    }

    #[test]
    fn absence_proofs_at_an_older_live_root_keep_their_own_root_and_index() {
        let (_, address) = recipient();
        let mut rpc = ProofRpc::new(Vec::new());
        let older = HistoryRoot {
            value: [0x33; 32],
            index: 2,
        };
        rpc.nullifier_roots = vec![older];
        let outputs = [output(address, 1)];
        let config = config(&BLOCK);
        let witness = CustomRingWitnessInput {
            policy: &BLOCK,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        }
        .build(&rpc, &rpc)
        .expect("witness");
        assert_eq!(witness.trees[0].roots.nullifier, older.value);
        assert_eq!(witness.trees[0].roots.nullifier_index, older.index);
    }

    #[test]
    fn unclaimed_answers_take_the_state_root_from_the_tree_account() {
        let (_, address) = recipient();
        let mut rpc = ProofRpc::new(Vec::new());
        rpc.account = Some(tree_account());
        let outputs = [output(address, 1)];
        let config = config(&BLOCK);
        let witness = CustomRingWitnessInput {
            policy: &BLOCK,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        }
        .build(&rpc, &rpc)
        .expect("witness");
        let current = current_roots(Some(tree_account()), address_tree()).expect("current roots");
        assert_eq!(witness.trees[0].roots.nullifier, current.nullifier);
        assert_eq!(
            witness.trees[0].roots.nullifier_index,
            current.nullifier_index
        );
        assert_eq!(witness.trees[0].roots.state, current.state);
        assert_eq!(witness.trees[0].roots.state_index, current.state_index);
        let calls = rpc.calls.lock().expect("calls");
        assert!(calls.merkle.is_empty());
        assert_eq!(calls.non_inclusion.len(), 1);
        assert_eq!(calls.accounts, 1);
        assert_eq!(witness.answers[0].absent_branch, 1);
    }

    #[test]
    fn a_table_without_answers_reads_both_roots_from_the_tree_account() {
        let mut rpc = ProofRpc::new(Vec::new());
        rpc.account = Some(tree_account());
        let config = config(&EMPTY);
        let witness = CustomRingWitnessInput {
            policy: &EMPTY,
            policy_config: &config,
            inputs: &[],
            outputs: &[],
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        }
        .build(&rpc, &rpc)
        .expect("witness");
        assert_eq!(
            witness.trees[0].roots,
            current_roots(Some(tree_account()), address_tree()).expect("current roots")
        );
        let calls = rpc.calls.lock().expect("calls");
        assert!(calls.merkle.is_empty() && calls.non_inclusion.is_empty());
        assert_eq!(calls.accounts, 1);
    }

    fn enabled(witness: &CustomRingWitness) -> Vec<&RuleAnswer> {
        witness
            .answers
            .iter()
            .filter(|answer| answer.enabled)
            .collect()
    }

    #[test]
    fn a_blocked_member_passes_through_its_approval() {
        let (member, address) = recipient();
        let approved = Lineage::new(lookup(ListId::Approval, member), &[EntryState::Active]);
        let blocked = Lineage::new(lookup(ListId::Block, member), &[EntryState::Active]);
        let mut spenders = approved.spenders();
        spenders.extend(blocked.spenders());
        let rpc = ProofRpc::new(spenders);
        let outputs = [output(address, 1)];
        let config = config(&MIXED);
        let witness = CustomRingWitnessInput {
            policy: &MIXED,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        }
        .build(&rpc, &rpc)
        .expect("witness");

        let answers = enabled(&witness);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].list_id, ListId::Approval as u8);
        assert_eq!(answers[0].mode, Mode::Present as u8);
        assert_eq!(answers[0].absent_branch, 2);
        assert_eq!(answers[0].state, EntryState::Active as u8);
        let live = approved.live().expect("live");
        let calls = rpc.calls.lock().expect("calls");
        assert_eq!(calls.merkle, vec![vec![live.utxo_hash]]);
        assert_eq!(calls.non_inclusion, vec![vec![live.nullifier]]);
        // Both alternatives are claimed in one round.
        let requests = rpc.lineages.requests.lock().expect("requests");
        assert_eq!(requests[0].len(), 2);
    }

    #[test]
    fn an_unlisted_member_passes_through_the_absent_alternative() {
        let (member, address) = recipient();
        let mut rpc = ProofRpc::new(Vec::new());
        rpc.account = Some(tree_account());
        let outputs = [output(address, 1)];
        let config = config(&MIXED);
        let witness = CustomRingWitnessInput {
            policy: &MIXED,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        }
        .build(&rpc, &rpc)
        .expect("witness");

        let answers = enabled(&witness);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].list_id, ListId::Block as u8);
        assert_eq!(answers[0].mode, Mode::Absent as u8);
        assert_eq!(answers[0].absent_branch, 1);
        let calls = rpc.calls.lock().expect("calls");
        assert!(calls.merkle.is_empty());
        assert_eq!(
            calls.non_inclusion,
            vec![vec![lookup(ListId::Block, member)
                .address()
                .expect("address")]]
        );
    }

    #[test]
    fn a_blocked_member_without_approval_is_refused() {
        let (member, address) = recipient();
        let blocked = Lineage::new(lookup(ListId::Block, member), &[EntryState::Active]);
        let rpc = ProofRpc::new(blocked.spenders());
        let outputs = [output(address, 1)];
        let config = config(&MIXED);
        let refused = CustomRingWitnessInput {
            policy: &MIXED,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        }
        .build(&rpc, &rpc);
        assert!(matches!(refused, Err(TransferError::PolicyRuleUnsatisfied)));
        let calls = rpc.calls.lock().expect("calls");
        assert!(calls.merkle.is_empty() && calls.non_inclusion.is_empty());
    }

    #[test]
    fn the_request_carries_the_account_rows_verbatim() {
        let (_, address) = recipient();
        let mut rpc = ProofRpc::new(Vec::new());
        rpc.account = Some(tree_account());
        let outputs = [output(address, 1)];
        let config = config(&MIXED);
        let witness = CustomRingWitnessInput {
            policy: &MIXED,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        }
        .build(&rpc, &rpc)
        .expect("witness");

        assert_eq!(witness.rules, config.rules.rules);
        assert_eq!(witness.policy_len, config.rules.rule_count);
        assert_eq!(witness.inline_assets, config.rules.inline_assets);
        assert_eq!(
            witness.inline_limits,
            config.rules.inline_limits.map(u64::from_be_bytes)
        );
        assert_eq!(witness.inline_count, config.rules.inline_count);
        assert_eq!(witness.rules[0][19], ListSet::single(ListId::Block).bits());
        assert_eq!(witness.inline_assets[0], ASSETS[0]);
        let mapped: Vec<u8> = witness
            .sources
            .iter()
            .map(|slot| slot.list_id)
            .filter(|list_id| *list_id != 0)
            .collect();
        assert_eq!(mapped, vec![ListId::Block as u8, ListId::Approval as u8]);
    }

    fn live_in(tree_id: u16, byte: u8) -> EntryFact {
        let lineage = Lineage::across(
            lookup(
                ListId::Block,
                crate::instructions::entry::discovery::tests::member(byte),
            ),
            &[EntryState::Cleared],
            &[tree_id],
        );
        EntryFact::Live(lineage.live().expect("live"))
    }

    #[test]
    fn fact_trees_dedupe_and_bind_the_address_tree_first() {
        let unclaimed = EntryFact::Unclaimed { address: [1; 32] };
        let facts = [live_in(9, 1), unclaimed, live_in(9, 2), live_in(0, 3)];
        let trees = FactTrees::plan(address_tree(), &facts).expect("trees");
        assert_eq!(
            trees.trees,
            vec![address_tree(), PoolTree::from_id(SECOND_TREE_ID)]
        );
        assert_eq!(trees.slots, vec![1, 0, 1, 0]);

        let live_only = FactTrees::plan(address_tree(), &[live_in(9, 1)]).expect("trees");
        assert_eq!(live_only.trees, vec![PoolTree::from_id(SECOND_TREE_ID)]);
        let no_facts = FactTrees::plan(address_tree(), &[]).expect("trees");
        assert_eq!(no_facts.trees, vec![address_tree()]);
    }

    #[test]
    fn facts_in_more_than_five_trees_are_refused() {
        let facts: Vec<EntryFact> = (1..=6).map(|id| live_in(id, id as u8)).collect();
        assert!(matches!(
            FactTrees::plan(address_tree(), &facts),
            Err(TransferError::TooManyPolicyTrees { count: 6 })
        ));
    }

    /// A cleared entry that moved to a second tree answers there, an unclaimed
    /// address answers in the address tree.
    #[test]
    fn facts_in_two_trees_select_their_own_slots() {
        let (moved, moved_address) = recipient();
        let (_, unclaimed_address) = recipient();
        let lineage = Lineage::across(
            lookup(ListId::Block, moved),
            &[EntryState::Active, EntryState::Cleared],
            &[0, SECOND_TREE_ID],
        );
        let rpc = ProofRpc::new(lineage.spenders()).with_tree(SECOND_TREE_ID);
        let outputs = [output(moved_address, 1), output(unclaimed_address, 1)];
        let config = config(&BLOCK);
        let witness = CustomRingWitnessInput {
            policy: &BLOCK,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
            output_tree_id: 0,
            velocity: velocity_off(),
            key_registry: None,
        }
        .build(&rpc, &rpc)
        .expect("witness");

        let second = PoolTree::from_id(SECOND_TREE_ID);
        assert_eq!(
            witness
                .trees
                .iter()
                .map(|tree| tree.tree)
                .collect::<Vec<_>>(),
            vec![address_tree(), second]
        );
        let enabled = enabled(&witness);
        assert_eq!(enabled[0].tree_slot, 1);
        assert_eq!(enabled[0].absent_branch, 2);
        assert_eq!(enabled[1].tree_slot, 0);
        assert_eq!(enabled[1].absent_branch, 1);
        assert_eq!(witness.revocation_tree_indexes[..2], [1, 0]);
        let live = lineage.live().expect("live");
        assert_eq!(witness.revocation_targets[0], live.nullifier);
        let calls = rpc.calls.lock().expect("calls");
        assert_eq!(calls.merkle, vec![vec![live.utxo_hash]]);
        assert_eq!(calls.trees, vec![tree(), second.address, second.address]);
        assert_eq!(calls.accounts, 2);
        assert_eq!(
            witness.reads().trees[1].tree,
            second.address,
            "the revocation PDA of fact 0 derives under the second tree"
        );
    }
}
