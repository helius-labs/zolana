use bytemuck::Zeroable;
use custom_ring_interface::{
    PolicyConfig, PolicyTableIxData, SourceSlot, N_SOURCE_SLOTS, POLICY_CONFIG,
};
use pinocchio::{
    account::Ref,
    address::address_eq,
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::{
    cpi::{invoke_signed_with_bounds, Seed, Signer},
    instruction::{InstructionAccount, InstructionView},
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{
            confidential_encrypted_output_body, CircuitId, OwnerTag, TransactIxData,
            TransactOutput, TransactProof,
        },
        tag::TRANSACT,
        MessageData,
    },
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program::{TransactExternalData, TransactInputs};
use zolana_ring_policy::{
    entry_nullifier, mutation_private_tx_hash, spend_record_message_tag, EncodedRuleTable,
    ListEntry, ListId, ListNamespace, ListSet, Member, PolicyHashError, SourceMap, SpendRecord,
    TableParts, Writer, NAMESPACE_PDA_SEED,
};

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_config, load_policy_config, load_spp_tree_id},
        shared::PdaCheck,
    },
};

/// The ring's own namespace owner, curator sources enter only through the
/// authority gated source map writes.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub(crate) fn namespace_pda(program_id: &Address) -> Result<(Address, u8), CustomRingError> {
    Ok(Address::find_program_address(
        &[NAMESPACE_PDA_SEED],
        program_id,
    ))
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub(crate) fn namespace_pda(_program_id: &Address) -> Result<(Address, u8), CustomRingError> {
    Err(CustomRingError::InvalidNamespacePda)
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub(crate) fn namespace_address(
    program_id: &Address,
    bump: u8,
) -> Result<Address, CustomRingError> {
    Address::create_program_address(&[NAMESPACE_PDA_SEED, &[bump]], program_id)
        .map_err(|_| CustomRingError::InvalidNamespacePda)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub(crate) fn namespace_address(
    _program_id: &Address,
    _bump: u8,
) -> Result<Address, CustomRingError> {
    Err(CustomRingError::InvalidNamespacePda)
}

/// A curator's policy config, the `b"policy"` PDA of the program that owns
/// it, pinned to the same address tree.
pub(crate) fn load_curator_policy_config<'a>(
    account: &'a AccountView,
    address_tree: &Address,
) -> Result<Ref<'a, PolicyConfig>, ProgramError> {
    let curator_program = *account.owner();
    let data = account
        .try_borrow()
        .map_err(|_| CustomRingError::InvalidCuratorPolicyConfig)?;
    if data.len() != PolicyConfig::SIZE {
        return Err(CustomRingError::InvalidCuratorPolicyConfig.into());
    }
    let config: Ref<'a, PolicyConfig> = Ref::map(data, |data| bytemuck::from_bytes(data));
    if config.discriminator != POLICY_CONFIG {
        return Err(CustomRingError::InvalidCuratorPolicyConfig.into());
    }
    PdaCheck {
        program_id: &curator_program,
        address: account.address(),
        seeds: &[PolicyConfig::SEED],
        mismatch: CustomRingError::InvalidCuratorPolicyConfig,
    }
    .verify_stored_bump(config.bump)?;
    if !address_eq(&config.address_tree, address_tree) {
        return Err(CustomRingError::CuratorTreeMismatch.into());
    }
    Ok(config)
}

pub(crate) struct BoundTable {
    pub rules: EncodedRuleTable,
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
}

pub(crate) struct TableBinding<'a> {
    pub table: &'a PolicyTableIxData,
    pub curators: &'a [AccountView],
    pub own_namespace: &'a Address,
    pub address_tree: &'a Address,
}

impl TableBinding<'_> {
    /// The bound table must remain off the caller's SBF stack frame.
    #[inline(never)]
    pub fn bind(self) -> Result<Box<BoundTable>, ProgramError> {
        let rules = decode_policy_table(self.table)?;
        let sources = self.resolve_sources(rules.referenced())?;
        Ok(Box::new(BoundTable { rules, sources }))
    }

    /// The map is a bijection with the lists the table references.
    #[inline(never)]
    fn resolve_sources(
        &self,
        referenced: ListSet,
    ) -> Result<[SourceSlot; N_SOURCE_SLOTS], ProgramError> {
        let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
        let mut seen = ListSet::EMPTY;
        for spec in &self.table.sources {
            let list_id =
                ListId::try_from(spec.list_id).map_err(|_| CustomRingError::InvalidSource)?;
            if !referenced.contains(list_id) || seen.contains(list_id) {
                return Err(CustomRingError::InvalidSource.into());
            }
            seen = seen.union(ListSet::single(list_id));
            let namespace = match spec.source {
                0 => *self.own_namespace,
                n => {
                    let curator = self
                        .curators
                        .get(usize::from(n) - 1)
                        .ok_or(CustomRingError::InvalidSource)?;
                    // Copies the curator's resolved owner, a curator of a curator
                    // never chains.
                    load_curator_policy_config(curator, self.address_tree)?
                        .source_for(list_id)
                        .ok_or(CustomRingError::CuratorSourceMissing)?
                }
            };
            sources[list_id.slot()] = SourceSlot {
                list_id: list_id as u8,
                namespace,
            };
        }
        if seen != referenced {
            return Err(CustomRingError::InvalidSource.into());
        }
        Ok(sources)
    }
}

pub(crate) enum Repin<'a> {
    Table(&'a BoundTable),
    Sources(&'a [SourceSlot; N_SOURCE_SLOTS]),
}

#[inline(never)]
pub(crate) fn repin(live: &mut PolicyConfig, repin: Repin<'_>) -> ProgramResult {
    let generation = live
        .generation()
        .checked_add(1)
        .ok_or(CustomRingError::PolicyGenerationOverflow)?;
    let sources = match repin {
        Repin::Table(bound) => {
            live.rules = bound.rules;
            &bound.sources
        }
        Repin::Sources(sources) => sources,
    };
    live.policy_hash = compute_policy_hash(&live.rules, sources)?;
    live.sources = *sources;
    live.generation = generation.to_le_bytes();
    live.generation_slot = Clock::get()?.slot.to_le_bytes();
    Ok(())
}

#[inline(never)]
fn decode_policy_table(table: &PolicyTableIxData) -> Result<EncodedRuleTable, CustomRingError> {
    let velocity: Vec<_> = table.velocity.iter().map(Into::into).collect();
    TableParts {
        rows: &table.rules,
        inline_assets: &table.inline_assets,
        inline_limits: &table.inline_limits,
        window_slots: table.window_slots,
        velocity: &velocity,
    }
    .encode()
    .and_then(|encoded| encoded.decode().map(|_| encoded))
    .map_err(|_| CustomRingError::InvalidPolicyRules)
}

#[inline(never)]
pub(crate) fn compute_policy_hash(
    rules: &EncodedRuleTable,
    sources: &[SourceSlot; N_SOURCE_SLOTS],
) -> Result<[u8; 32], CustomRingError> {
    rules
        .hash(&source_map(sources)?)
        .map_err(|error| match error {
            PolicyHashError::Table(_) => CustomRingError::InvalidPolicyRules,
            PolicyHashError::MissingSource(_) => CustomRingError::InvalidSource,
            PolicyHashError::Hashing => CustomRingError::HashingFailed,
        })
}

/// The map `EncodedRuleTable::hash` binds, rebuilt from the stored slots.
fn source_map(sources: &[SourceSlot; N_SOURCE_SLOTS]) -> Result<SourceMap, CustomRingError> {
    let slots = core::array::from_fn(|i| (sources[i].list_id, *sources[i].namespace.as_array()));
    SourceMap::from_namespaces(&slots, |namespace| {
        ListNamespace::new(namespace).map(|owner| owner.owner_hash)
    })
    .map_err(|_| CustomRingError::InvalidPolicyConfigPda)
}

/// A claim inserts a fresh address, a replace spends the live leaf.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum MutationKind {
    Claim,
    Replace,
}

#[derive(Clone, Copy)]
pub(crate) struct MutationTrees {
    pub address: u16,
    pub input: u16,
    pub output: u16,
}

impl MutationTrees {
    pub fn entry_address(
        self,
        owner: &ListNamespace,
        entry: &ListEntry,
    ) -> Result<[u8; 32], CustomRingError> {
        owner
            .address(entry.list_id, &entry.member, self.address)
            .map_err(|_| CustomRingError::HashingFailed)
    }

    /// The live leaf in the input tree and its nullifier.
    pub fn spent_entry(
        self,
        owner: &ListNamespace,
        entry: &ListEntry,
    ) -> Result<([u8; 32], [u8; 32]), CustomRingError> {
        let address = self.entry_address(owner, entry)?;
        let leaf = entry
            .utxo_hash(owner, &address, self.input)
            .map_err(|_| CustomRingError::HashingFailed)?;
        let nullifier = entry_nullifier(&leaf, &entry.blinding())
            .map_err(|_| CustomRingError::HashingFailed)?;
        Ok((leaf, nullifier))
    }

    pub fn written_entry(
        self,
        owner: &ListNamespace,
        entry: &ListEntry,
    ) -> Result<[u8; 32], CustomRingError> {
        let address = self.entry_address(owner, entry)?;
        entry
            .utxo_hash(owner, &address, self.output)
            .map_err(|_| CustomRingError::HashingFailed)
    }
}

pub(crate) struct MutationAccounts<'a> {
    pub payer: &'a AccountView,
    pub namespace_address: Address,
    pub namespace_bump: u8,
    pub owner: ListNamespace,
    pub authority: Address,
    pub trees: MutationTrees,
    sources: [SourceSlot; N_SOURCE_SLOTS],
    pub window_slots: u64,
}

impl<'a> MutationAccounts<'a> {
    /// Everything after the two config accounts is forwarded to SPP position
    /// for position, the payer leads that slice.
    pub fn validate_and_parse(
        program_id: &Address,
        accounts: &'a mut [AccountView],
        kind: MutationKind,
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let config = iter.next_account("config")?;
        let policy_config = iter.next_account("policy_config")?;
        let payer = iter.next_signer_mut("payer")?;
        let output_tree = iter.next_mut("output_tree")?;
        let spp_program = iter.next_account("spp_program")?;
        let system_program = iter.next_account("system_program")?;
        let input_tree = iter.next_mut("input_tree")?;
        let _nullifier_pda = iter.next_mut("nullifier_pda")?;
        let entries = iter.next_account("entries")?;
        if !iter.iterator_is_empty() {
            return Err(ProgramError::InvalidArgument);
        }

        if !pinocchio_system::check_id(system_program.address()) {
            return Err(CustomRingError::InvalidSystemProgram.into());
        }
        if spp_program.address().as_array() != &SHIELDED_POOL_PROGRAM_ID
            || !spp_program.executable()
        {
            return Err(CustomRingError::InvalidShieldedPoolProgram.into());
        }
        let config = load_config(program_id, config)?;
        let policy_config: Ref<'_, PolicyConfig> = load_policy_config(program_id, policy_config)?;
        // SPP nullifies a claimed address in the input tree.
        if kind == MutationKind::Claim
            && !address_eq(input_tree.address(), &policy_config.address_tree)
        {
            return Err(CustomRingError::InvalidAddressTree.into());
        }
        let trees = MutationTrees {
            address: policy_config.address_tree_id(),
            input: load_spp_tree_id(input_tree, CustomRingError::InvalidPolicyTrees)?,
            output: load_spp_tree_id(output_tree, CustomRingError::InvalidPolicyTrees)?,
        };
        let namespace_bump = PdaCheck {
            program_id,
            address: entries.address(),
            seeds: &[NAMESPACE_PDA_SEED],
            mismatch: CustomRingError::InvalidNamespacePda,
        }
        .verify()?;
        if namespace_bump != policy_config.namespace_bump {
            return Err(CustomRingError::InvalidNamespacePda.into());
        }
        let owner = ListNamespace {
            owner_hash: policy_config.namespace_owner_hash,
        };

        Ok(Self {
            payer,
            namespace_address: *entries.address(),
            namespace_bump,
            owner,
            authority: config.authority,
            trees,
            sources: policy_config.sources,
            window_slots: policy_config.rules.window_slots(),
        })
    }

    /// A referenced list serves its mapped entries only, an unmapped list
    /// stays mutable against the ring's own.
    pub fn check_source(&self, list_id: ListId) -> ProgramResult {
        let slot = self.sources[list_id.slot()];
        if slot.list_id != 0 && !address_eq(&slot.namespace, &self.namespace_address) {
            return Err(CustomRingError::ForeignSource.into());
        }
        Ok(())
    }

    pub fn check_mutator(&self, list_id: ListId, member: &Member) -> ProgramResult {
        match list_id.writer() {
            Writer::Member => {
                let signer = Member::owner_tag(self.payer.address().as_array())
                    .map_err(|_| CustomRingError::HashingFailed)?;
                if signer != *member {
                    return Err(CustomRingError::UnauthorizedNamespaceSigner.into());
                }
            }
            Writer::Authority => {
                if self.payer.address() != &self.authority {
                    return Err(CustomRingError::UnauthorizedNamespaceSigner.into());
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct EntryTransition {
    pub entry: ListEntry,
    pub inputs: TransactInputs,
    pub input_hash: [u8; 32],
    /// The address a claim inserts, zero for a spend.
    pub address_nullifier: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    pub proof: TransactProof,
}

impl EntryTransition {
    pub fn into_transact(self, parsed: &MutationAccounts) -> Result<TransactIxData, ProgramError> {
        let output_hash = parsed.trees.written_entry(&parsed.owner, &self.entry)?;
        let content = self.entry.to_output_data();
        NamespaceWrite {
            output_hash,
            content: &content,
            inputs: self.inputs,
            input_hash: self.input_hash,
            address_nullifier: self.address_nullifier,
            private_tx_blinding: self.private_tx_blinding,
            proof: self.proof,
        }
        .into_transact(&parsed.namespace_address)
    }
}

/// Canonical SPP statement for creating or replacing one namespace-owned data
/// record.
pub(crate) struct NamespaceWrite<'a> {
    pub output_hash: [u8; 32],
    pub content: &'a [u8],
    pub inputs: TransactInputs,
    pub input_hash: [u8; 32],
    /// The address a claim inserts, zero for a spend.
    pub address_nullifier: [u8; 32],
    pub private_tx_blinding: [u8; 32],
    pub proof: TransactProof,
}

impl NamespaceWrite<'_> {
    pub fn into_transact(
        self,
        namespace_address: &Address,
    ) -> Result<TransactIxData, ProgramError> {
        let owner_bytes = namespace_address.to_bytes();
        let external = TransactExternalData::single_output(TransactOutput {
            utxo_hash: self.output_hash,
            owner_tag: OwnerTag::Inline(owner_bytes),
            data: Some(self.content.to_vec()),
        });
        let external_data_hash = external
            .hash(TRANSACT, &[], &[owner_bytes])
            .map_err(|_| CustomRingError::HashingFailed)?;
        let private_tx_hash = mutation_private_tx_hash(
            self.input_hash,
            self.output_hash,
            self.address_nullifier,
            &external_data_hash,
            &self.private_tx_blinding,
        )
        .map_err(|_| CustomRingError::HashingFailed)?;

        Ok(external.into_ix_data(
            private_tx_hash,
            CircuitId::ConfidentialEddsa(1, 1, N_PUBLIC_SLOTS as u8),
            self.proof,
            self.inputs,
        ))
    }
}

/// The namespace every spend record of the ring is addressed under.
pub(crate) struct RecordNamespace {
    pub owner: ListNamespace,
    pub address: Address,
    pub address_tree_id: u16,
}

/// The last output of a windowed transfer plus the messages carrying its plaintext.
pub(crate) struct SpendRecordCarrier<'a> {
    pub output: &'a TransactOutput,
    pub messages: &'a [MessageData],
    /// The successor leaf hashes under the tree it lands in.
    pub output_tree_id: u16,
}

impl SpendRecordCarrier<'_> {
    pub fn verify(&self, namespace: &RecordNamespace) -> Result<(), ProgramError> {
        // 1. Require the namespace-owned final output and its unique public
        // record message.
        if self.output.owner_tag != OwnerTag::Inline(namespace.address.to_bytes()) {
            return Err(CustomRingError::InvalidSpendRecord.into());
        }
        if self
            .output
            .data
            .as_deref()
            .and_then(confidential_encrypted_output_body)
            .is_none()
        {
            return Err(CustomRingError::InvalidSpendRecord.into());
        }
        let tag = spend_record_message_tag(namespace.address.as_array())
            .map_err(|_| CustomRingError::HashingFailed)?;
        let mut tagged = self
            .messages
            .iter()
            .filter(|message| message.view_tag == tag);
        let message = tagged.next().ok_or(CustomRingError::InvalidSpendRecord)?;
        if tagged.next().is_some() {
            return Err(CustomRingError::InvalidSpendRecord.into());
        }
        // 2. Rebuild the leaf from published record fields before granting the
        // namespace signature.
        let record = SpendRecord::from_output_data(&message.data)
            .ok_or(CustomRingError::InvalidSpendRecord)?;
        let address = namespace
            .owner
            .spend_address(&record.member, namespace.address_tree_id)
            .map_err(|_| CustomRingError::HashingFailed)?;
        let leaf = record
            .utxo_hash(&namespace.owner, &address, self.output_tree_id)
            .map_err(|_| CustomRingError::HashingFailed)?;
        if leaf != self.output.utxo_hash {
            return Err(CustomRingError::InvalidSpendRecord.into());
        }
        Ok(())
    }
}

/// Forwards `accounts[2..]` to SPP with the namespace PDA raised to a signer.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub(crate) fn cpi_spp_namespace_signed(
    namespace_address: &Address,
    namespace_bump: u8,
    accounts: &[AccountView],
    transact: &TransactIxData,
) -> ProgramResult {
    let spp_accounts = accounts
        .get(2..)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let metas: Vec<InstructionAccount> = spp_accounts
        .iter()
        .map(|account| {
            InstructionAccount::new(
                account.address(),
                account.is_writable(),
                account.is_signer() || address_eq(account.address(), namespace_address),
            )
        })
        .collect();
    let transact_bytes = transact
        .serialize()
        .map_err(|_| CustomRingError::InvalidInstructionData)?;
    let mut instruction_data = Vec::with_capacity(1 + transact_bytes.len());
    instruction_data.push(TRANSACT);
    instruction_data.extend_from_slice(&transact_bytes);
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    let instruction = InstructionView {
        program_id: &spp_id,
        accounts: &metas,
        data: &instruction_data,
    };
    let bump_seed = [namespace_bump];
    let signer_seeds = [
        Seed::from(NAMESPACE_PDA_SEED),
        Seed::from(bump_seed.as_ref()),
    ];
    invoke_signed_with_bounds::<8, _>(
        &instruction,
        spp_accounts,
        &[Signer::from(signer_seeds.as_ref())],
    )
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub(crate) fn cpi_spp_namespace_signed(
    _namespace_address: &Address,
    _namespace_bump: u8,
    _accounts: &[AccountView],
    _transact: &TransactIxData,
) -> ProgramResult {
    Err(ProgramError::InvalidArgument)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zolana_ring_policy::EntryState;

    const TREES: MutationTrees = MutationTrees {
        address: 1,
        input: 2,
        output: 3,
    };

    #[test]
    fn addresses_hash_under_the_address_tree_and_leaves_under_their_own() {
        let owner = ListNamespace::new(&[11u8; 32]).unwrap();
        let entry = ListEntry {
            list_id: ListId::Allow,
            member: Member::owner_tag(&[61u8; 32]).unwrap(),
            state: EntryState::Active,
            version: 3,
            content_hash: [0u8; 32],
            blinding: [5u8; 32],
        };
        let address = owner.address(entry.list_id, &entry.member, 1).unwrap();
        assert_eq!(TREES.entry_address(&owner, &entry), Ok(address));

        let (spent, nullifier) = TREES.spent_entry(&owner, &entry).unwrap();
        assert_eq!(spent, entry.utxo_hash(&owner, &address, 2).unwrap());
        assert_eq!(
            nullifier,
            entry_nullifier(&spent, &entry.blinding()).unwrap()
        );
        assert_eq!(
            TREES.written_entry(&owner, &entry),
            Ok(entry.utxo_hash(&owner, &address, 3).unwrap())
        );
        assert_ne!(spent, entry.utxo_hash(&owner, &address, 1).unwrap());
    }
}
