//! Assembles the policy half of the ring proof. The openings come from the
//! transfer the SDK already prepared, the answers from the entries the
//! rules name.

use custom_ring_interface::PolicyConfig;
use solana_address::Address;
use zolana_client::Rpc;
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::{
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, DUMMY_DOMAIN, SHIELDED_POOL_PROGRAM_ID,
    UTXO_DOMAIN,
};
use zolana_ring_policy::{
    entry_nullifier, EntryState, Guard, ListId, ListNamespace, Member, Mode, Rule, RuleSource,
    RuleTable, Subject, MAX_INLINE_ASSETS, MAX_RULES, MAX_SOURCES,
};
use zolana_transaction::instructions::{transact::SppProofOutputUtxo, types::SppProofInputUtxo};
use zolana_tree::TreeAccount;

use crate::{
    instructions::entry::read_entry,
    instructions::transact::{
        CustomRingOpening, RuleAnswer, SourceOwnerEntry, ANSWER_SLOTS, NULLIFIER_PATH_LEN,
        POLICY_INPUT_SLOTS, POLICY_OUTPUT_SLOTS, STATE_PATH_LEN,
    },
    TransferError,
};

/// Roots the statement binds, with the history entries they were read from.
#[derive(Clone, Copy, Debug)]
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
    pub rules: [[u8; 32]; MAX_RULES],
    pub policy_len: u8,
    pub inline_assets: [[u8; 32]; MAX_INLINE_ASSETS],
    pub inline_count: u8,
    pub answers: Vec<RuleAnswer>,
}

/// Gathers the witness from the chain and the indexer at prove time.
pub struct CustomRingWitnessInput<'a> {
    pub policy: &'a RuleTable,
    pub policy_config: &'a PolicyConfig,
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
}

impl CustomRingWitnessInput<'_> {
    /// Refuses client-side with a named rule before any prover round.
    pub fn build<I: Rpc, R: Rpc>(
        self,
        indexer: &I,
        rpc: &R,
    ) -> Result<CustomRingWitness, TransferError> {
        if self.inputs.len() > POLICY_INPUT_SLOTS || self.outputs.len() > POLICY_OUTPUT_SLOTS {
            return Err(TransferError::PolicyShapeUnsupported);
        }
        let roots = read_roots(rpc, self.policy_config.entries_tree)?;
        let mut sources = [SourceOwnerEntry::default(); MAX_SOURCES];
        for (entry, slot) in sources.iter_mut().zip(self.policy_config.sources) {
            if slot.list_id == 0 {
                continue;
            }
            let owner = ListNamespace::new(slot.namespace.as_array())
                .map_err(|_| TransferError::PolicyHashing)?;
            *entry = SourceOwnerEntry {
                list_id: slot.list_id,
                owner_hash: owner.owner_hash,
            };
        }

        let mut inputs = [CustomRingOpening::default(); POLICY_INPUT_SLOTS];
        for (slot, spend) in inputs.iter_mut().zip(self.inputs) {
            *slot = input_opening(spend)?;
        }
        let mut outputs = [CustomRingOpening::default(); POLICY_OUTPUT_SLOTS];
        for (slot, output) in outputs.iter_mut().zip(self.outputs) {
            *slot = output_opening(output)?;
        }

        let (rules, inline_assets, inline_count) = encode_table(self.policy);
        let answers = self.answer_rules(indexer)?;
        Ok(CustomRingWitness {
            roots,
            sources,
            inputs,
            outputs,
            n_in: self.inputs.len() as u8,
            n_out: self.outputs.len() as u8,
            rules,
            policy_len: self.policy.rules().len() as u8,
            inline_assets,
            inline_count,
            answers,
        })
    }

    /// One covering answer per subject a rule screens, a group is covered by any
    /// one of its lists.
    fn answer_rules<I: Rpc>(&self, indexer: &I) -> Result<Vec<RuleAnswer>, TransferError> {
        let mut answers: Vec<RuleAnswer> = Vec::new();
        for rule in self.policy.rules() {
            let lists: Vec<ListId> = rule.referenced_lists().collect();
            if lists.is_empty() {
                continue;
            }
            for member in self.subjects(rule)? {
                // A guarded subject at or below the threshold is exempt, the
                // circuit needs no answer for it and demanding one would refuse a
                // transfer the circuit accepts.
                if self.guard_exempts(rule, &member)? {
                    continue;
                }
                let answer = self.cover(indexer, &lists, &member, rule.mode)?;
                if answers.iter().any(|entry| {
                    entry.list_id == answer.list_id
                        && entry.member == answer.member
                        && entry.mode == answer.mode
                }) {
                    continue;
                }
                answers.push(answer);
            }
        }
        if answers.len() > ANSWER_SLOTS {
            return Err(TransferError::PolicyShapeUnsupported);
        }
        answers.resize_with(ANSWER_SLOTS, RuleAnswer::default);
        Ok(answers)
    }

    /// The first group list whose entry satisfies the mode, a member present in
    /// any allow list or absent from any block list covers the group.
    fn cover<I: Rpc>(
        &self,
        indexer: &I,
        lists: &[ListId],
        member: &Member,
        mode: Mode,
    ) -> Result<RuleAnswer, TransferError> {
        let mut unsatisfied = false;
        for &list_id in lists {
            match self.entry(indexer, list_id, member, mode) {
                Ok(answer) => return Ok(answer),
                Err(TransferError::PolicyRuleUnsatisfied) => unsatisfied = true,
                Err(other) => return Err(other),
            }
        }
        debug_assert!(unsatisfied);
        Err(TransferError::PolicyRuleUnsatisfied)
    }

    /// The rule's guard exempts the subject when the total it receives in the
    /// transaction is at or below the threshold, the same sum the circuit weighs.
    fn guard_exempts(&self, rule: &Rule, member: &Member) -> Result<bool, TransferError> {
        let Guard::AboveAmount(threshold) = rule.guard else {
            return Ok(false);
        };
        Ok(self.subject_total(rule.subject, member)? <= threshold)
    }

    /// The total the subject value receives across live outputs, aggregated per
    /// owner or per asset as the circuit does.
    fn subject_total(&self, subject: Subject, member: &Member) -> Result<u64, TransferError> {
        if matches!(subject, Subject::Sender | Subject::ExitDestination) {
            return Ok(0);
        }
        let mut total: u64 = 0;
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
                total = total.saturating_add(output.amount);
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

    fn entry<I: Rpc>(
        &self,
        indexer: &I,
        list_id: ListId,
        member: &Member,
        mode: Mode,
    ) -> Result<RuleAnswer, TransferError> {
        let entries = self
            .policy_config
            .source_for(list_id as u8)
            .ok_or(TransferError::MissingSourceOwner)?;
        let owner =
            ListNamespace::new(entries.as_array()).map_err(|_| TransferError::PolicyHashing)?;
        let address = owner
            .address(list_id, member)
            .map_err(|_| TransferError::PolicyHashing)?;
        let live = read_entry(indexer, entries, list_id, member)
            .map_err(|error| TransferError::ListEntry(Box::new(error)))?;
        let mut entry = RuleAnswer {
            enabled: true,
            mode: mode as u8,
            list_id: list_id as u8,
            member: *member.as_bytes(),
            ..RuleAnswer::default()
        };
        match live {
            // A never claimed address proves absence by its own non-inclusion.
            None => {
                if matches!(mode, Mode::Present) {
                    return Err(TransferError::PolicyRuleUnsatisfied);
                }
                entry.absent_branch = 1;
                let proof = non_inclusion(indexer, self.policy_config.entries_tree, address)?;
                entry.low = proof.low_element;
                entry.next = proof.high_element;
                entry.nullifier_path = proof.path;
                entry.nullifier_path_index = proof.low_element_index;
            }
            Some(live) => {
                let cleared = live.entry.state == EntryState::Cleared;
                if matches!(mode, Mode::Present) && cleared {
                    return Err(TransferError::PolicyRuleUnsatisfied);
                }
                if matches!(mode, Mode::Absent) && !cleared {
                    return Err(TransferError::PolicyRuleUnsatisfied);
                }
                entry.absent_branch = 2;
                entry.state = live.entry.state as u8;
                entry.version = live.entry.version;
                entry.content_hash = live.entry.content_hash;
                let state = merkle(indexer, self.policy_config.entries_tree, live.utxo_hash)?;
                entry.state_path = state.path;
                entry.state_path_index = state.leaf_index;
                let nullifier = entry_nullifier(&live.utxo_hash, &live.entry.blinding())
                    .map_err(|_| TransferError::PolicyHashing)?;
                let proof = non_inclusion(indexer, self.policy_config.entries_tree, nullifier)?;
                entry.low = proof.low_element;
                entry.next = proof.high_element;
                entry.nullifier_path = proof.path;
                entry.nullifier_path_index = proof.low_element_index;
            }
        }
        Ok(entry)
    }
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

fn encode_table(policy: &RuleTable) -> ([[u8; 32]; MAX_RULES], [[u8; 32]; MAX_INLINE_ASSETS], u8) {
    let mut rules = [[0u8; 32]; MAX_RULES];
    let mut inline = [[0u8; 32]; MAX_INLINE_ASSETS];
    let mut inline_count = 0usize;
    for (slot, rule) in rules.iter_mut().zip(policy.rules()) {
        *slot = rule.encoded();
        if let RuleSource::InlineAssets(members) = rule.source {
            for member in members {
                inline[inline_count] = *member;
                inline_count += 1;
            }
        }
    }
    (rules, inline, inline_count as u8)
}

struct MerklePath {
    path: Vec<[u8; 32]>,
    leaf_index: u64,
}

struct NonInclusionPath {
    low_element: [u8; 32],
    high_element: [u8; 32],
    path: Vec<[u8; 32]>,
    low_element_index: u64,
}

fn merkle<I: Rpc>(indexer: &I, tree: Address, leaf: [u8; 32]) -> Result<MerklePath, TransferError> {
    let proof = indexer
        .get_merkle_proofs(tree, vec![leaf], None)?
        .proofs
        .into_iter()
        .next()
        .ok_or(TransferError::PolicyRuleUnsatisfied)?;
    let mut path = proof.path;
    path.resize(STATE_PATH_LEN, [0u8; 32]);
    Ok(MerklePath {
        path,
        leaf_index: proof.leaf_index,
    })
}

fn non_inclusion<I: Rpc>(
    indexer: &I,
    tree: Address,
    leaf: [u8; 32],
) -> Result<NonInclusionPath, TransferError> {
    let proof = indexer
        .get_non_inclusion_proofs(tree, vec![leaf], None)?
        .proofs
        .into_iter()
        .next()
        .ok_or(TransferError::PolicyRuleUnsatisfied)?;
    let mut path = proof.path;
    path.resize(NULLIFIER_PATH_LEN, [0u8; 32]);
    Ok(NonInclusionPath {
        low_element: proof.low_element,
        high_element: proof.high_element,
        path,
        low_element_index: proof.low_element_index,
    })
}

fn read_roots<R: Rpc>(rpc: &R, tree: Address) -> Result<TransactRoots, TransferError> {
    let mut account = rpc
        .get_account(tree)?
        .ok_or(TransferError::MissingTree)?
        .clone();
    if account.owner.to_bytes() != SHIELDED_POOL_PROGRAM_ID {
        return Err(TransferError::InvalidTreeOwner);
    }
    if account.data.first() != Some(&TREE_ACCOUNT_DISCRIMINATOR) {
        return Err(TransferError::InvalidTreeDiscriminator);
    }
    let mut tree_account = TreeAccount::from_bytes(&mut account.data, tree.to_bytes())?;
    let state_index = tree_account.utxo_tree().current_root_index();
    let state = tree_account.get_utxo_tree_root(state_index)?;
    let nullifier_index = tree_account.nullifer_tree().get_root_index() as u16;
    let nullifier = tree_account.get_nullifier_tree_root(nullifier_index)?;
    Ok(TransactRoots {
        state,
        state_index,
        nullifier,
        nullifier_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use custom_ring_interface::{PolicyConfig, SourceSlot, N_SOURCE_SLOTS, POLICY_CONFIG};
    use zolana_keypair::ShieldedKeypair;

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
        let config = PolicyConfig {
            discriminator: POLICY_CONFIG,
            policy_hash: [0; 32],
            entries_tree: Address::default(),
            namespace_bump: 0,
            bump: 0,
            sources: [SourceSlot {
                list_id: 0,
                namespace: Address::default(),
            }; N_SOURCE_SLOTS],
        };
        let policy = RuleTable::builder().build();
        let input = CustomRingWitnessInput {
            policy: &policy,
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
        let recipient = ShieldedKeypair::new_ed25519().expect("recipient");
        let asset = Address::new_from_array([9; 32]);
        let address = recipient.shielded_address().expect("address");
        let member =
            Member::owner_tag(&address.confidential_view_tag().expect("tag")).expect("member");
        let config = PolicyConfig {
            discriminator: POLICY_CONFIG,
            policy_hash: [0; 32],
            entries_tree: Address::default(),
            namespace_bump: 0,
            bump: 0,
            sources: [SourceSlot {
                list_id: 0,
                namespace: Address::default(),
            }; N_SOURCE_SLOTS],
        };
        let policy = RuleTable::builder().build();
        // Two outputs to the same recipient sum to 2500, over the 2000 threshold.
        let outputs = [
            SppProofOutputUtxo::new(asset, 1000, address).expect("first output"),
            SppProofOutputUtxo::new(asset, 1500, address).expect("second output"),
        ];
        let input = CustomRingWitnessInput {
            policy: &policy,
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
        let one = [SppProofOutputUtxo::new(asset, 1000, address).expect("single output")];
        let below = CustomRingWitnessInput {
            policy: &policy,
            policy_config: &config,
            inputs: &[],
            outputs: &one,
        };
        assert!(below
            .guard_exempts(&guarded, &member)
            .expect("below threshold"));
    }
}
