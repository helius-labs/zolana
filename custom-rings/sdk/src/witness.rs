//! Assembles the policy half of the ring proof. The openings come from the
//! transfer the SDK already prepared, the answers from the entries the
//! rules name.

use custom_ring_interface::PolicyConfig;
use solana_account::Account;
use solana_address::Address;
use zolana_client::{AsyncRpc, MerkleProof, NonInclusionProof, Rpc};
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::{
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, DUMMY_DOMAIN, SHIELDED_POOL_PROGRAM_ID,
    UTXO_DOMAIN,
};
use zolana_ring_policy::{
    EntryState, Guard, ListId, ListNamespace, Member, Mode, Rule, RuleTable, SourceMap, Subject,
    ANSWER_SLOTS, MAX_INLINE_ASSETS, MAX_RULES, MAX_SOURCES, POLICY_INPUT_SLOTS,
    POLICY_OUTPUT_SLOTS,
};
use zolana_transaction::instructions::{transact::SppProofOutputUtxo, types::SppProofInputUtxo};
use zolana_tree::TreeAccount;

use crate::{
    instructions::entry::{EntryLookup, Lineages, LiveEntry},
    instructions::transact::{
        CustomRingOpening, RuleAnswer, SourceOwnerEntry, NULLIFIER_PATH_LEN, STATE_PATH_LEN,
    },
    shared::source_map,
    TransferError,
};

/// Roots the statement binds, with the history entries they were read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransactRoots {
    pub state: [u8; 32],
    pub state_index: u16,
    pub nullifier: [u8; 32],
    pub nullifier_index: u16,
}

/// The policy witness of one transfer, serialized into the proof request.
pub struct CustomRingWitness {
    pub roots: TransactRoots,
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
    pub answers: Vec<RuleAnswer>,
}

/// Gathers the witness from the chain and the indexer at prove time.
#[derive(Clone, Copy)]
pub struct CustomRingWitnessInput<'a> {
    pub policy: &'a RuleTable,
    pub policy_config: &'a PolicyConfig,
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
}

impl<'a> CustomRingWitnessInput<'a> {
    /// Refuses client-side with a named rule before any prover round.
    pub fn build<I: Rpc, R: Rpc>(
        self,
        indexer: &I,
        rpc: &R,
    ) -> Result<CustomRingWitness, TransferError> {
        let tree = self.policy_config.entries_tree;
        let plan = self.plan()?;
        let lineages = plan.lineages().fetch(indexer).map_err(list_entry)?;
        let resolved = plan.resolve(lineages)?;
        let proofs = resolved.queries().fetch(indexer)?;
        let fixed = FixedRoots::from_proofs(&proofs)?;
        let roots = match fixed.complete() {
            Some(roots) => roots,
            None => fixed.fill(head_roots(rpc.get_account(tree)?, tree)?),
        };
        resolved.assemble(proofs, roots)
    }

    pub async fn build_async<I: AsyncRpc, R: AsyncRpc>(
        self,
        indexer: &I,
        rpc: &R,
    ) -> Result<CustomRingWitness, TransferError> {
        let tree = self.policy_config.entries_tree;
        let plan = self.plan()?;
        let lineages = plan
            .lineages()
            .fetch_async(indexer)
            .await
            .map_err(list_entry)?;
        let resolved = plan.resolve(lineages)?;
        let proofs = resolved.queries().fetch_async(indexer).await?;
        let fixed = FixedRoots::from_proofs(&proofs)?;
        let roots = match fixed.complete() {
            Some(roots) => roots,
            None => fixed.fill(head_roots(rpc.get_account(tree).await?, tree)?),
        };
        resolved.assemble(proofs, roots)
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
        for output in self.outputs {
            let Some(address) = output.owner_address.as_ref() else {
                continue;
            };
            let tag = address
                .confidential_view_tag()
                .map_err(|_| TransferError::PolicyHashing)?;
            if Member::owner_tag(&tag).map_err(|_| TransferError::PolicyHashing)? != *owner {
                continue;
            }
            let asset = Member::asset(&output.asset).map_err(|_| TransferError::PolicyHashing)?;
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

    /// The total the subject value receives across live outputs, aggregated per
    /// owner or per asset as the circuit does.
    fn subject_total(&self, subject: Subject, member: &Member) -> Result<u128, TransferError> {
        let mut total: u128 = 0;
        for output in self.outputs {
            let Some(address) = output.owner_address.as_ref() else {
                continue;
            };
            let output_member = match subject {
                Subject::Asset => {
                    Member::asset(&output.asset).map_err(|_| TransferError::PolicyHashing)?
                }
                _ => {
                    let tag = address
                        .confidential_view_tag()
                        .map_err(|_| TransferError::PolicyHashing)?;
                    Member::owner_tag(&tag).map_err(|_| TransferError::PolicyHashing)?
                }
            };
            if output_member == *member {
                total += u128::from(output.amount);
            }
        }
        Ok(total)
    }

    fn subjects(&self, rule: &Rule) -> Result<Vec<Member>, TransferError> {
        match rule.subject {
            Subject::OutputOwner => {
                let tags = self
                    .outputs
                    .iter()
                    .filter_map(|output| output.owner_address.as_ref())
                    .map(|address| address.confidential_view_tag())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| TransferError::PolicyHashing)?;
                tags.iter()
                    .map(|tag| Member::owner_tag(tag).map_err(|_| TransferError::PolicyHashing))
                    .collect()
            }
            Subject::Sender => {
                let tags = self
                    .inputs
                    .iter()
                    .filter(|spend| !spend.is_dummy())
                    .map(|spend| spend.utxo.owner.confidential_view_tag())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|_| TransferError::PolicyHashing)?;
                tags.iter()
                    .map(|tag| Member::owner_tag(tag).map_err(|_| TransferError::PolicyHashing))
                    .collect()
            }
            // The circuit ranges asset rules over live outputs, using the same
            // hashed mint field as output_opening.
            Subject::Asset => self
                .outputs
                .iter()
                .filter(|output| output.owner_address.is_some())
                .map(|output| {
                    Member::asset(&output.asset).map_err(|_| TransferError::PolicyHashing)
                })
                .collect(),
            // RuleTableBuilder rejects this subject until a settlement-aware
            // circuit plane exists.
            Subject::ExitDestination => Ok(Vec::new()),
        }
    }
}

fn list_entry(error: crate::EntryProofError) -> TransferError {
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
    fn lineages(&self) -> Lineages<'_> {
        Lineages {
            entries_tree: self.input.policy_config.entries_tree,
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
        Ok(ResolvedWitness {
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
}

impl ResolvedWitness<'_> {
    fn queries(&self) -> EntryQueries {
        EntryQueries {
            tree: self.input.policy_config.entries_tree,
            states: self
                .answers
                .iter()
                .filter_map(|answer| answer.fact.state_leaf())
                .collect(),
            absences: self
                .answers
                .iter()
                .map(|answer| answer.fact.absence_target())
                .collect(),
        }
    }

    fn assemble(
        self,
        proofs: EntryProofs,
        roots: TransactRoots,
    ) -> Result<CustomRingWitness, TransferError> {
        let live_count = self
            .answers
            .iter()
            .filter(|answer| answer.fact.state_leaf().is_some())
            .count();
        if proofs.states.len() != live_count || proofs.absences.len() != self.answers.len() {
            return Err(TransferError::IncompleteProofSet);
        }
        let mut states = proofs.states.into_iter();
        let mut answers = Vec::with_capacity(ANSWER_SLOTS);
        for (answer, absence) in self.answers.iter().zip(proofs.absences) {
            let mut entry = RuleAnswer {
                enabled: true,
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
                    entry.content_hash = live.entry.content_hash;
                    entry.state_path = padded(state.path, STATE_PATH_LEN);
                    entry.state_path_index = state.leaf_index;
                }
            }
            answers.push(entry);
        }
        answers.resize_with(ANSWER_SLOTS, RuleAnswer::default);

        let input = self.input;
        let mut inputs = [CustomRingOpening::default(); POLICY_INPUT_SLOTS];
        for (slot, spend) in inputs.iter_mut().zip(input.inputs) {
            *slot = input_opening(spend)?;
        }
        let mut outputs = [CustomRingOpening::default(); POLICY_OUTPUT_SLOTS];
        for (slot, output) in outputs.iter_mut().zip(input.outputs) {
            *slot = output_opening(output)?;
        }
        let table = &input.policy_config.rules;
        Ok(CustomRingWitness {
            roots,
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
            answers,
        })
    }
}

fn padded(mut path: Vec<[u8; 32]>, len: usize) -> Vec<[u8; 32]> {
    path.resize(len, [0u8; 32]);
    path
}

struct EntryQueries {
    tree: Address,
    states: Vec<[u8; 32]>,
    absences: Vec<[u8; 32]>,
}

struct EntryProofs {
    states: Vec<MerkleProof>,
    absences: Vec<NonInclusionProof>,
}

impl EntryQueries {
    fn fetch<I: Rpc>(self, indexer: &I) -> Result<EntryProofs, TransferError> {
        let states = if self.states.is_empty() {
            Vec::new()
        } else {
            indexer
                .get_merkle_proofs(self.tree, self.states, None)?
                .proofs
        };
        let absences = if self.absences.is_empty() {
            Vec::new()
        } else {
            indexer
                .get_non_inclusion_proofs(self.tree, self.absences, None)?
                .proofs
        };
        Ok(EntryProofs { states, absences })
    }

    async fn fetch_async<I: AsyncRpc>(self, indexer: &I) -> Result<EntryProofs, TransferError> {
        let states = if self.states.is_empty() {
            Vec::new()
        } else {
            indexer
                .get_merkle_proofs(self.tree, self.states, None)
                .await?
                .proofs
        };
        let absences = if self.absences.is_empty() {
            Vec::new()
        } else {
            indexer
                .get_non_inclusion_proofs(self.tree, self.absences, None)
                .await?
                .proofs
        };
        Ok(EntryProofs { states, absences })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct HistoryRoot {
    value: [u8; 32],
    index: u16,
}

/// The roots the proof responses fixed, a tree no answer touched has none.
struct FixedRoots {
    state: Option<HistoryRoot>,
    nullifier: Option<HistoryRoot>,
}

impl FixedRoots {
    fn from_proofs(proofs: &EntryProofs) -> Result<Self, TransferError> {
        Ok(Self {
            state: single_root(proofs.states.iter().map(|proof| HistoryRoot {
                value: proof.root,
                index: proof.root_index,
            }))?,
            nullifier: single_root(proofs.absences.iter().map(|proof| HistoryRoot {
                value: proof.root,
                index: proof.root_index,
            }))?,
        })
    }

    fn complete(&self) -> Option<TransactRoots> {
        let (state, nullifier) = (self.state?, self.nullifier?);
        Some(TransactRoots {
            state: state.value,
            state_index: state.index,
            nullifier: nullifier.value,
            nullifier_index: nullifier.index,
        })
    }

    /// The program admits any live state root and any nullifier root inside
    /// its window, the heads serve a tree no proof fixed.
    fn fill(self, heads: TransactRoots) -> TransactRoots {
        let state = self.state.unwrap_or(HistoryRoot {
            value: heads.state,
            index: heads.state_index,
        });
        let nullifier = self.nullifier.unwrap_or(HistoryRoot {
            value: heads.nullifier,
            index: heads.nullifier_index,
        });
        TransactRoots {
            state: state.value,
            state_index: state.index,
            nullifier: nullifier.value,
            nullifier_index: nullifier.index,
        }
    }
}

/// One call proves every leaf against one root.
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

fn head_roots(account: Option<Account>, tree: Address) -> Result<TransactRoots, TransferError> {
    let mut account = account.ok_or(TransferError::MissingTree)?;
    if account.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID {
        return Err(TransferError::InvalidTreeOwner);
    }
    if account.data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(TransferError::InvalidTreeDiscriminator);
    }
    let mut tree_account = TreeAccount::from_bytes(&mut account.data, tree.to_bytes())?;
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

fn input_opening(spend: &SppProofInputUtxo) -> Result<CustomRingOpening, TransferError> {
    if spend.is_dummy() {
        return Ok(CustomRingOpening {
            domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
            ..CustomRingOpening::default()
        });
    }
    let tag = spend
        .utxo
        .owner
        .confidential_view_tag()
        .map_err(|_| TransferError::PolicyHashing)?;
    Ok(CustomRingOpening {
        domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
        owner_pk_hash: hash_bytes(&tag).map_err(|_| TransferError::PolicyHashing)?,
        nullifier_pk: spend
            .nullifier_key
            .pubkey()
            .map_err(|_| TransferError::PolicyHashing)?,
        asset: asset_field(&spend.utxo.asset)?,
        amount: right_align(&spend.utxo.amount.to_be_bytes()),
        blinding: spend.utxo.blinding,
        data_hash: spend.data_hash.unwrap_or_default(),
        ring_data_hash: spend.ring_data_hash.unwrap_or_default(),
        ring_program_id: ring_field(spend.utxo.ring_program_id.as_ref())?,
    })
}

fn output_opening(output: &SppProofOutputUtxo) -> Result<CustomRingOpening, TransferError> {
    let Some(address) = output.owner_address.as_ref() else {
        return Ok(CustomRingOpening {
            domain: right_align(&DUMMY_DOMAIN.to_be_bytes()),
            ..CustomRingOpening::default()
        });
    };
    let tag = address
        .confidential_view_tag()
        .map_err(|_| TransferError::PolicyHashing)?;
    Ok(CustomRingOpening {
        domain: right_align(&UTXO_DOMAIN.to_be_bytes()),
        owner_pk_hash: hash_bytes(&tag).map_err(|_| TransferError::PolicyHashing)?,
        nullifier_pk: address.nullifier_pubkey,
        asset: asset_field(&output.asset)?,
        amount: right_align(&output.amount.to_be_bytes()),
        blinding: output.blinding,
        data_hash: output.data_hash.unwrap_or_default(),
        ring_data_hash: output.ring_data_hash.unwrap_or_default(),
        ring_program_id: ring_field(output.ring_program_id.as_ref())?,
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
    use zolana_ring_policy::ListSet;

    use super::*;
    use crate::instructions::entry::discovery::tests::{
        lookup, namespace, tree, Lineage, NullifierRpc,
    };

    /// Every referenced list reads the ring's own entries.
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
            entries_tree: tree(),
            namespace_bump: 0,
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
        let member =
            Member::owner_tag(&address.confidential_view_tag().expect("tag")).expect("member");
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
        SppProofOutputUtxo::new(asset, amount, address).expect("output")
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
                asset,
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
        };
        assert!(input.guard_exempts(rule, &owner).expect("at both limits"));

        let above = [output_asset(first, address, 11)];
        let input = CustomRingWitnessInput {
            policy: &policy,
            policy_config: &config,
            inputs: &[],
            outputs: &above,
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
        };
        let guarded = Rule::require(Subject::Sender, ListId::Allow).above(u64::MAX);
        assert!(!input.guard_exempts(&guarded, &member).expect("sender"));
    }

    struct ProofRpc {
        lineages: NullifierRpc,
        state_roots: Vec<HistoryRoot>,
        nullifier_roots: Vec<HistoryRoot>,
        account: Option<Account>,
        calls: Mutex<Calls>,
    }

    #[derive(Default)]
    struct Calls {
        merkle: Vec<Vec<[u8; 32]>>,
        non_inclusion: Vec<Vec<[u8; 32]>>,
        accounts: usize,
    }

    impl ProofRpc {
        fn new(spenders: Vec<ShieldedTransaction>) -> Self {
            Self {
                lineages: NullifierRpc::new(spenders),
                state_roots: vec![HistoryRoot {
                    value: [1u8; 32],
                    index: 3,
                }],
                nullifier_roots: vec![HistoryRoot {
                    value: [2u8; 32],
                    index: 4,
                }],
                account: None,
                calls: Mutex::new(Calls::default()),
            }
        }

        fn root(roots: &[HistoryRoot], position: usize) -> HistoryRoot {
            roots[position.min(roots.len() - 1)]
        }
    }

    impl Rpc for ProofRpc {
        fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
            assert_eq!(address, tree());
            self.calls.lock().expect("calls").accounts += 1;
            Ok(self.account.clone())
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
            assert_eq!(tree_account, tree());
            self.calls
                .lock()
                .expect("calls")
                .merkle
                .push(leaves.clone());
            let proofs = leaves
                .iter()
                .enumerate()
                .map(|(position, leaf)| {
                    let root = Self::root(&self.state_roots, position);
                    MerkleProof {
                        leaf: *leaf,
                        merkle_context: MerkleContext {
                            tree_type: 0,
                            tree: tree(),
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
            assert_eq!(tree_account, tree());
            self.calls
                .lock()
                .expect("calls")
                .non_inclusion
                .push(leaves.clone());
            let proofs = leaves
                .iter()
                .enumerate()
                .map(|(position, leaf)| {
                    let root = Self::root(&self.nullifier_roots, position);
                    NonInclusionProof {
                        leaf: *leaf,
                        merkle_context: MerkleContext {
                            tree_type: 1,
                            tree: tree(),
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
        let mut data = vec![0u8; TreeAccount::account_size()];
        let params = nullifier_tree_params();
        TreeAccount::init(
            &mut data,
            TREE_ACCOUNT_DISCRIMINATOR,
            32,
            tree().to_bytes(),
            0,
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
        let rpc = ProofRpc::new(lineage.spenders(tree()));
        let outputs = [output(address, 10), output(address, 20)];
        let config = config(&TWO_ALLOW);
        let witness = CustomRingWitnessInput {
            policy: &TWO_ALLOW,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
        }
        .build(&rpc, &rpc)
        .expect("witness");

        let live = lineage.live().expect("live");
        let calls = rpc.calls.lock().expect("calls");
        assert_eq!(calls.merkle, vec![vec![live.utxo_hash]]);
        assert_eq!(calls.non_inclusion, vec![vec![live.nullifier]]);
        assert_eq!(calls.accounts, 0);
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
            witness.roots,
            TransactRoots {
                state: [1u8; 32],
                state_index: 3,
                nullifier: [2u8; 32],
                nullifier_index: 4,
            }
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
        let mut spenders = first.spenders(tree());
        spenders.extend(second.spenders(tree()));
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
        }
        .build(&rpc, &rpc);
        assert!(matches!(refused, Err(TransferError::PolicyRootMismatch)));
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
        }
        .build(&rpc, &rpc)
        .expect("witness");
        let heads = head_roots(Some(tree_account()), tree()).expect("heads");
        assert_eq!(witness.roots.nullifier, [2u8; 32]);
        assert_eq!(witness.roots.nullifier_index, 4);
        assert_eq!(witness.roots.state, heads.state);
        assert_eq!(witness.roots.state_index, heads.state_index);
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
        }
        .build(&rpc, &rpc)
        .expect("witness");
        assert_eq!(
            witness.roots,
            head_roots(Some(tree_account()), tree()).expect("heads")
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
        let mut spenders = approved.spenders(tree());
        spenders.extend(blocked.spenders(tree()));
        let rpc = ProofRpc::new(spenders);
        let outputs = [output(address, 1)];
        let config = config(&MIXED);
        let witness = CustomRingWitnessInput {
            policy: &MIXED,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
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
        let rpc = ProofRpc::new(blocked.spenders(tree()));
        let outputs = [output(address, 1)];
        let config = config(&MIXED);
        let refused = CustomRingWitnessInput {
            policy: &MIXED,
            policy_config: &config,
            inputs: &[],
            outputs: &outputs,
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
}
