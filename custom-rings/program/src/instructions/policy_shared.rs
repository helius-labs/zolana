use bytemuck::Zeroable;
use custom_ring_interface::{
    CustomRingError, PolicyConfig, PolicyTableIxData, RingProgramConfig, SourceSlot, N_SOURCE_SLOTS,
};
use pinocchio::{
    address::address_eq,
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    instruction::{
        instruction_data::transact::{
            CircuitId, InputUtxo, OwnerTag, TransactOutput, TransactProof, TreeContext,
        },
        tag::TRANSACT,
    },
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program::{TransactExternalData, TransactInputs};
use zolana_ring_policy::{
    entry_nullifier, mutation_private_tx_hash, EncodedRuleTable, ListEntry, ListId, ListNamespace,
    ListSet, Member, SourceMap, TableParts, Writer,
};

use crate::instructions::{
    loader::{load, load_curator_policy_config, load_spp_tree_id},
    shared::{cpi_spp, namespace_address, SppSigners},
};

pub(crate) struct BoundTable {
    pub rules: EncodedRuleTable,
    pub sources: [SourceSlot; N_SOURCE_SLOTS],
}

/// The table must decode, and the sources map exactly the lists it references.
/// Boxed, the bound table stays off the caller's SBF stack frame.
#[inline(never)]
pub(crate) fn bind_table(
    table: &PolicyTableIxData,
    curators: &[AccountView],
    own_namespace: &Address,
    address_tree: &Address,
) -> Result<Box<BoundTable>, ProgramError> {
    let rules = decode_table(table)?;
    let sources = resolve_sources(
        table,
        rules.referenced(),
        curators,
        own_namespace,
        address_tree,
    )?;
    Ok(Box::new(BoundTable { rules, sources }))
}

#[inline(never)]
fn decode_table(table: &PolicyTableIxData) -> Result<EncodedRuleTable, CustomRingError> {
    let rules = TableParts {
        rows: &table.rules,
        inline_assets: &table.inline_assets,
        inline_limits: &table.inline_limits,
        limits: &table.limits,
    }
    .encode()?;
    rules.decode()?;
    Ok(rules)
}

/// A curator's namespace is copied as resolved, a curator of a curator never chains.
#[inline(never)]
fn resolve_sources(
    table: &PolicyTableIxData,
    referenced: ListSet,
    curators: &[AccountView],
    own_namespace: &Address,
    address_tree: &Address,
) -> Result<[SourceSlot; N_SOURCE_SLOTS], ProgramError> {
    let mut sources = [SourceSlot::zeroed(); N_SOURCE_SLOTS];
    let mut seen = ListSet::EMPTY;
    for spec in &table.sources {
        let list_id = ListId::try_from(spec.list_id).map_err(|_| CustomRingError::InvalidSource)?;
        if !referenced.contains(list_id) || seen.contains(list_id) {
            return Err(CustomRingError::InvalidSource.into());
        }
        seen = seen.union(ListSet::single(list_id));
        let namespace = match spec.source {
            0 => *own_namespace,
            n => {
                let curator = curators
                    .get(usize::from(n) - 1)
                    .ok_or(CustomRingError::InvalidSource)?;
                load_curator_policy_config(curator, address_tree)?
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

/// Pins the hash over the stored rules and `sources`, counting the write.
#[inline(never)]
pub(crate) fn repin(
    live: &mut PolicyConfig,
    sources: &[SourceSlot; N_SOURCE_SLOTS],
) -> ProgramResult {
    let generation = live
        .generation()
        .checked_add(1)
        .ok_or(CustomRingError::PolicyGenerationOverflow)?;
    live.policy_hash = compute_policy_hash(&live.rules, sources)?;
    live.sources = *sources;
    live.generation = generation.to_le_bytes();
    live.generation_slot = Clock::get()?.slot.to_le_bytes();
    Ok(())
}

/// The hash binds the map rebuilt from the stored `(list_id, namespace)` slots.
#[inline(never)]
pub(crate) fn compute_policy_hash(
    rules: &EncodedRuleTable,
    sources: &[SourceSlot; N_SOURCE_SLOTS],
) -> Result<[u8; 32], CustomRingError> {
    let slots = core::array::from_fn(|i| (sources[i].list_id, *sources[i].namespace.as_array()));
    let map = SourceMap::from_namespaces(&slots, |namespace| {
        ListNamespace::new(namespace).map(|owner| owner.owner_hash)
    })
    .map_err(|_| CustomRingError::InvalidPolicyConfigPda)?;
    Ok(rules.hash(&map)?)
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
        Ok(owner.address(entry.list_id, &entry.member, self.address)?)
    }

    /// The live leaf in the input tree and its nullifier.
    pub fn spent_entry(
        self,
        owner: &ListNamespace,
        entry: &ListEntry,
    ) -> Result<([u8; 32], [u8; 32]), CustomRingError> {
        let address = self.entry_address(owner, entry)?;
        let leaf = entry.utxo_hash(owner, &address, self.input)?;
        Ok((leaf, entry_nullifier(&leaf, &entry.blinding)?))
    }

    pub fn written_entry(
        self,
        owner: &ListNamespace,
        entry: &ListEntry,
    ) -> Result<[u8; 32], CustomRingError> {
        let address = self.entry_address(owner, entry)?;
        Ok(entry.utxo_hash(owner, &address, self.output)?)
    }
}

/// `[config, policy_config]`, then the SPP transact list the write forwards, payer first.
pub(crate) struct MutationAccounts {
    pub payer: Address,
    pub namespace: Address,
    pub namespace_bump: u8,
    pub owner: ListNamespace,
    pub authority: Address,
    pub trees: MutationTrees,
    sources: [SourceSlot; N_SOURCE_SLOTS],
}

impl MutationAccounts {
    pub fn validate_and_parse(
        program_id: &Address,
        accounts: &mut [AccountView],
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
        let authority = load::<RingProgramConfig>(program_id, config)?.authority;
        let policy = load::<PolicyConfig>(program_id, policy_config)?;
        // SPP nullifies a claimed address in the input tree.
        if kind == MutationKind::Claim && !address_eq(input_tree.address(), &policy.address_tree) {
            return Err(CustomRingError::InvalidAddressTree.into());
        }
        let trees = MutationTrees {
            address: policy.address_tree_id(),
            input: load_spp_tree_id(input_tree, CustomRingError::InvalidPolicyTrees)?,
            output: load_spp_tree_id(output_tree, CustomRingError::InvalidPolicyTrees)?,
        };
        if !address_eq(
            entries.address(),
            &namespace_address(program_id, policy.namespace_bump),
        ) {
            return Err(CustomRingError::InvalidNamespacePda.into());
        }
        Ok(Self {
            payer: *payer.address(),
            namespace: *entries.address(),
            namespace_bump: policy.namespace_bump,
            owner: ListNamespace {
                owner_hash: policy.namespace_owner_hash,
            },
            authority,
            trees,
            sources: policy.sources,
        })
    }

    /// A mapped list takes writes on its own source only, an unmapped list on
    /// the ring's, and only from the list's writer as payer.
    pub fn check_writer(&self, list_id: ListId, member: &Member) -> ProgramResult {
        let slot = self.sources[list_id.slot()];
        if slot.list_id != 0 && !address_eq(&slot.namespace, &self.namespace) {
            return Err(CustomRingError::ForeignSource.into());
        }
        let authorized = match list_id.writer() {
            Writer::Member => {
                Member::owner_tag(self.payer.as_array())
                    .map_err(|_| CustomRingError::HashingFailed)?
                    == *member
            }
            Writer::Authority => self.payer == self.authority,
        };
        if !authorized {
            return Err(CustomRingError::UnauthorizedNamespaceSigner.into());
        }
        Ok(())
    }
}

/// The one input slot of a namespace write.
pub(crate) enum Spend {
    /// A fresh address, nullified as the input.
    Claim([u8; 32]),
    /// The live leaf and its nullifier.
    Replace { leaf: [u8; 32], nullifier: [u8; 32] },
}

/// The canonical SPP statement creating or replacing one namespace-owned record.
pub(crate) struct NamespaceWrite<'a> {
    pub output_hash: [u8; 32],
    pub content: &'a [u8],
    pub spend: Spend,
    pub private_tx_blinding: [u8; 32],
    pub nullifier_tree_root_index: u16,
    pub utxo_tree_root_index: u16,
    pub proof: TransactProof,
}

impl NamespaceWrite<'_> {
    /// Forwards `accounts[2..]` to SPP with the namespace PDA raised to a signer.
    pub fn send(
        self,
        program_id: &Address,
        parsed: &MutationAccounts,
        accounts: &[AccountView],
    ) -> ProgramResult {
        let (input_hash, nullifier_hash, address_nullifier) = match self.spend {
            Spend::Claim(address) => ([0; 32], address, address),
            Spend::Replace { leaf, nullifier } => (leaf, nullifier, [0; 32]),
        };
        let private_tx_hash = mutation_private_tx_hash(
            input_hash,
            self.output_hash,
            address_nullifier,
            &self.private_tx_blinding,
        )
        .map_err(CustomRingError::from)?;
        let transact = TransactExternalData::single_output(TransactOutput {
            utxo_hash: self.output_hash,
            owner_tag: OwnerTag::Inline(parsed.namespace.to_bytes()),
            data: Some(self.content.to_vec()),
        })
        .into_ix_data(
            private_tx_hash,
            CircuitId::ConfidentialEd25519(1, 2, N_PUBLIC_SLOTS as u8),
            self.proof,
            TransactInputs {
                inputs: vec![InputUtxo {
                    nullifier_hash,
                    tree_index: 0,
                }],
                tree_contexts: vec![TreeContext {
                    utxo_tree_root_index: self.utxo_tree_root_index,
                    nullifier_tree_root_index: self.nullifier_tree_root_index,
                }],
            },
        );
        let mut data = vec![TRANSACT];
        data.extend_from_slice(
            &transact
                .serialize()
                .map_err(|_| CustomRingError::InvalidInstructionData)?,
        );
        let spp_accounts = accounts
            .get(2..)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        let signers = SppSigners::Namespace {
            bump: parsed.namespace_bump,
        };
        cpi_spp(program_id, spp_accounts, &data, signers)
    }
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
