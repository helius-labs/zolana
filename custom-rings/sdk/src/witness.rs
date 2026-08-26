//! Assembles the policy half of the ring proof. The openings come from the
//! transfer the SDK already prepared, the pool entries from the records the
//! rules name.

use solana_address::Address;
use zolana_client::Rpc;
use zolana_hasher::primitives::{hash_bytes, right_align};
use zolana_interface::{
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, DUMMY_DOMAIN, SHIELDED_POOL_PROGRAM_ID,
    UTXO_DOMAIN,
};
use zolana_ring_policy::{
    record_nullifier, Member, Mode, Policy, RecordKind, RecordState, RecordsOwner, Rule,
    RuleSource, Subject, MAX_INLINE_ASSETS, MAX_RULES,
};
use zolana_transaction::instructions::{transact::SppProofOutputUtxo, types::SppProofInputUtxo};
use zolana_tree::TreeAccount;

use crate::{
    instructions::record::read_record,
    instructions::transact::{
        CustomRingOpening, CustomRingPoolEntry, NULLIFIER_PATH_LEN, POLICY_INPUT_SLOTS,
        POLICY_OUTPUT_SLOTS, POLICY_POOL_SLOTS, STATE_PATH_LEN,
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

pub struct CustomRingWitness {
    pub roots: TransactRoots,
    pub records_owner_hash: [u8; 32],
    pub inputs: [CustomRingOpening; POLICY_INPUT_SLOTS],
    pub outputs: [CustomRingOpening; POLICY_OUTPUT_SLOTS],
    pub n_in: u8,
    pub n_out: u8,
    pub rules: [[u8; 32]; MAX_RULES],
    pub policy_len: u8,
    pub inline_assets: [[u8; 32]; MAX_INLINE_ASSETS],
    pub inline_count: u8,
    pub pool: Vec<CustomRingPoolEntry>,
}

pub struct CustomRingWitnessInput<'a> {
    pub policy: &'a Policy,
    pub records: Address,
    pub records_tree: Address,
    pub inputs: &'a [SppProofInputUtxo],
    pub outputs: &'a [SppProofOutputUtxo],
}

impl CustomRingWitnessInput<'_> {
    pub fn build<I: Rpc, R: Rpc>(
        self,
        indexer: &I,
        rpc: &R,
    ) -> Result<CustomRingWitness, TransferError> {
        if self.inputs.len() > POLICY_INPUT_SLOTS || self.outputs.len() > POLICY_OUTPUT_SLOTS {
            return Err(TransferError::PolicyShapeUnsupported);
        }
        let owner =
            RecordsOwner::new(self.records.as_array()).map_err(|_| TransferError::PolicyHashing)?;
        let roots = read_roots(rpc, self.records_tree)?;

        let mut inputs = [CustomRingOpening::default(); POLICY_INPUT_SLOTS];
        for (slot, spend) in inputs.iter_mut().zip(self.inputs) {
            *slot = input_opening(spend)?;
        }
        let mut outputs = [CustomRingOpening::default(); POLICY_OUTPUT_SLOTS];
        for (slot, output) in outputs.iter_mut().zip(self.outputs) {
            *slot = output_opening(output)?;
        }

        let (rules, inline_assets, inline_count) = encode_table(self.policy);
        let pool = self.build_pool(indexer, &owner)?;
        Ok(CustomRingWitness {
            roots,
            records_owner_hash: owner.owner_hash,
            inputs,
            outputs,
            n_in: self.inputs.len() as u8,
            n_out: self.outputs.len() as u8,
            rules,
            policy_len: self.policy.rules().len() as u8,
            inline_assets,
            inline_count,
            pool,
        })
    }

    /// One entry per distinct `(kind, member, mode)` the table asks about.
    fn build_pool<I: Rpc>(
        &self,
        indexer: &I,
        owner: &RecordsOwner,
    ) -> Result<Vec<CustomRingPoolEntry>, TransferError> {
        let mut pool: Vec<CustomRingPoolEntry> = Vec::new();
        for rule in self.policy.rules() {
            let RuleSource::Records(kind) = rule.source else {
                continue;
            };
            for member in self.subjects(rule)? {
                if pool.iter().any(|entry| {
                    entry.kind == kind as u8
                        && entry.member == *member.as_bytes()
                        && entry.mode == rule.mode as u8
                }) {
                    continue;
                }
                pool.push(self.entry(indexer, owner, kind, &member, rule.mode)?);
            }
        }
        if pool.len() > POLICY_POOL_SLOTS {
            return Err(TransferError::PolicyShapeUnsupported);
        }
        pool.resize_with(POLICY_POOL_SLOTS, CustomRingPoolEntry::default);
        Ok(pool)
    }

    fn subjects(&self, rule: &Rule) -> Result<Vec<Member>, TransferError> {
        let tags = match rule.subject {
            Subject::OutputOwner => self
                .outputs
                .iter()
                .filter_map(|output| output.owner_address.as_ref())
                .map(|address| address.confidential_view_tag())
                .collect::<Result<Vec<_>, _>>(),
            Subject::Sender => self
                .inputs
                .iter()
                .filter(|spend| !spend.is_dummy())
                .map(|spend| spend.utxo.owner.confidential_view_tag())
                .collect::<Result<Vec<_>, _>>(),
            // Exit destinations and assets are checked without a record.
            Subject::ExitDestination | Subject::Asset => Ok(Vec::new()),
        }
        .map_err(|_| TransferError::PolicyHashing)?;
        tags.iter()
            .map(|tag| Member::owner_tag(tag).map_err(|_| TransferError::PolicyHashing))
            .collect()
    }

    fn entry<I: Rpc>(
        &self,
        indexer: &I,
        owner: &RecordsOwner,
        kind: RecordKind,
        member: &Member,
        mode: Mode,
    ) -> Result<CustomRingPoolEntry, TransferError> {
        let address = owner
            .address(kind, member)
            .map_err(|_| TransferError::PolicyHashing)?;
        let live = read_record(indexer, self.records, kind, member)
            .map_err(|error| TransferError::Record(Box::new(error)))?;
        let mut entry = CustomRingPoolEntry {
            enabled: true,
            mode: mode as u8,
            kind: kind as u8,
            member: *member.as_bytes(),
            ..CustomRingPoolEntry::default()
        };
        match live {
            // A never claimed address proves absence by its own non-inclusion.
            None => {
                if matches!(mode, Mode::Present) {
                    return Err(TransferError::PolicyRuleUnsatisfied);
                }
                entry.absent_branch = 1;
                let proof = non_inclusion(indexer, self.records_tree, address)?;
                entry.low = proof.low_element;
                entry.next = proof.high_element;
                entry.nullifier_path = proof.path;
                entry.nullifier_path_index = proof.low_element_index;
            }
            Some(live) => {
                let cleared = live.record.state == RecordState::Cleared;
                if matches!(mode, Mode::Present) && cleared {
                    return Err(TransferError::PolicyRuleUnsatisfied);
                }
                if matches!(mode, Mode::Absent) && !cleared {
                    return Err(TransferError::PolicyRuleUnsatisfied);
                }
                entry.absent_branch = 2;
                entry.state = live.record.state as u8;
                entry.version = live.record.version;
                entry.payload_hash = live.record.payload_hash;
                let state = merkle(indexer, self.records_tree, live.utxo_hash)?;
                entry.state_path = state.path;
                entry.state_path_index = state.leaf_index;
                let nullifier = record_nullifier(&live.utxo_hash, &live.record.blinding())
                    .map_err(|_| TransferError::PolicyHashing)?;
                let proof = non_inclusion(indexer, self.records_tree, nullifier)?;
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

fn encode_table(policy: &Policy) -> ([[u8; 32]; MAX_RULES], [[u8; 32]; MAX_INLINE_ASSETS], u8) {
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
