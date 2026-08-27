use custom_ring_interface::{PolicyConfig, SourceSlot, N_SOURCE_SLOTS, POLICY_CONFIG, RULES};
use pinocchio::{
    account::Ref, address::address_eq, error::ProgramError, AccountView, Address, ProgramResult,
};
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::{
    cpi::{invoke_signed_with_bounds, Seed, Signer},
    instruction::{InstructionAccount, InstructionView},
};
use zolana_account_checks::AccountIterator;
use zolana_interface::{
    event::MessageData,
    instruction::{
        instruction_data::transact::{
            CircuitId, ExternalDataHash, InputUtxo, OwnerTag, ResolvedOutput, TransactIxData,
            TransactOutput, TransactProof,
        },
        tag::TRANSACT,
    },
    N_PUBLIC_SLOTS, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_ring_policy::{
    entry_nullifier, entry_seed, mutation_private_tx_hash, ListEntry, ListId, ListNamespace,
    Member, SourceMap, SourceOwner, Writer, MAX_SOURCES, NAMESPACE_PDA_SEED,
};

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_config, load_policy_config},
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

/// A curator's policy config, the `b"policy"` PDA of the program that owns
/// it, pinned to the same entries tree.
pub(crate) fn load_curator_policy_config<'a>(
    account: &'a AccountView,
    entries_tree: &Address,
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
    if !address_eq(&config.entries_tree, entries_tree) {
        return Err(CustomRingError::CuratorTreeMismatch.into());
    }
    Ok(config)
}

/// The map `RuleTable::hash` binds, rebuilt from the stored slots.
pub(crate) fn source_map(
    sources: &[SourceSlot; N_SOURCE_SLOTS],
) -> Result<SourceMap, CustomRingError> {
    let mut slots = [SourceOwner::default(); MAX_SOURCES];
    for (slot, stored) in slots.iter_mut().zip(sources) {
        if stored.list_id == 0 {
            continue;
        }
        *slot = SourceOwner {
            list_id: stored.list_id,
            owner_hash: ListNamespace::new(stored.namespace.as_array())
                .map_err(|_| CustomRingError::HashingFailed)?
                .owner_hash,
        };
    }
    SourceMap::from_slots(slots).map_err(|_| CustomRingError::InvalidPolicyConfigPda)
}

pub(crate) struct MutationAccounts<'a> {
    pub payer: &'a AccountView,
    pub namespace_address: Address,
    pub namespace_bump: u8,
    pub owner: ListNamespace,
    pub authority: Address,
}

impl<'a> MutationAccounts<'a> {
    /// Everything after the two config accounts is forwarded to SPP position
    /// for position, the payer leads that slice.
    pub fn validate_and_parse(
        program_id: &Address,
        accounts: &'a mut [AccountView],
        list_id: ListId,
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let config = iter.next_account("config")?;
        let policy_config = iter.next_account("policy_config")?;
        let payer = iter.next_signer_mut("payer")?;
        let input_tree = iter.next_mut("input_tree")?;
        let output_tree = iter.next_mut("output_tree")?;
        let spp_program = iter.next_account("spp_program")?;
        let system_program = iter.next_account("system_program")?;
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
        if !address_eq(input_tree.address(), &policy_config.entries_tree)
            || !address_eq(output_tree.address(), &policy_config.entries_tree)
        {
            return Err(CustomRingError::InvalidPolicyTree.into());
        }
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
        // A referenced list serves its mapped entries only, an unmapped list
        // stays mutable against the ring's own.
        let slot = policy_config.sources[list_id as usize - 1];
        if slot.list_id != 0 && !address_eq(&slot.namespace, entries.address()) {
            return Err(CustomRingError::ForeignSource.into());
        }

        let owner = ListNamespace::new(entries.address().as_array())
            .map_err(|_| CustomRingError::HashingFailed)?;
        let compiled = RULES
            .hash(&source_map(&policy_config.sources)?)
            .map_err(|_| CustomRingError::HashingFailed)?;
        if compiled != policy_config.policy_hash {
            return Err(CustomRingError::PolicyHashMismatch.into());
        }

        Ok(Self {
            payer,
            namespace_address: *entries.address(),
            namespace_bump,
            owner,
            authority: config.authority,
        })
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
    pub input: InputUtxo,
    pub input_hash: [u8; 32],
    pub address_utxo_hash: [u8; 32],
    pub proof: TransactProof,
}

impl EntryTransition {
    pub fn into_transact(
        self,
        owner: &ListNamespace,
        namespace_address: &Address,
    ) -> Result<TransactIxData, ProgramError> {
        let address = owner
            .address(self.entry.list_id, &self.entry.member)
            .map_err(|_| CustomRingError::HashingFailed)?;
        let output_hash = self
            .entry
            .utxo_hash(owner, &address)
            .map_err(|_| CustomRingError::HashingFailed)?;
        let content = self.entry.to_output_data();
        let entry_bytes = namespace_address.to_bytes();
        let resolved_output = [ResolvedOutput {
            utxo_hash: &output_hash,
            owner_tag: entry_bytes,
            data: Some(content.as_slice()),
        }];
        let messages: &[MessageData] = &[];
        let external_data_hash = ExternalDataHash {
            spp_instruction_discriminator: TRANSACT,
            expiry_unix_ts: u64::MAX,
            interface_transfers: &[],
            data_hash: None,
            ring_data_hash: None,
            tx_viewing_pk: &[0u8; 33],
            salt: &[0u8; 16],
            outputs: &resolved_output,
            messages,
        }
        .hash()
        .map_err(|_| CustomRingError::HashingFailed)?;
        let private_tx_hash = mutation_private_tx_hash(
            self.input_hash,
            output_hash,
            self.address_utxo_hash,
            &external_data_hash,
        )
        .map_err(|_| CustomRingError::HashingFailed)?;

        Ok(TransactIxData {
            expiry_unix_ts: u64::MAX,
            private_tx_hash,
            circuit: CircuitId::ConfidentialEddsa(1, 1, N_PUBLIC_SLOTS as u8),
            tx_viewing_pk: [0u8; 33],
            salt: [0u8; 16],
            proof: self.proof,
            inputs: vec![self.input],
            interface_transfers: Vec::new(),
            data_hash: None,
            ring_data_hash: None,
            outputs: vec![TransactOutput {
                utxo_hash: output_hash,
                owner_tag: OwnerTag::Inline(entry_bytes),
                data: Some(content.to_vec()),
            }],
            messages: Vec::new(),
        })
    }
}

pub(crate) fn entry_spend_input(
    owner: &ListNamespace,
    entry: &ListEntry,
) -> Result<([u8; 32], [u8; 32]), ProgramError> {
    let address = owner
        .address(entry.list_id, &entry.member)
        .map_err(|_| CustomRingError::HashingFailed)?;
    let spent_hash = entry
        .utxo_hash(owner, &address)
        .map_err(|_| CustomRingError::HashingFailed)?;
    let nullifier = entry_nullifier(&spent_hash, &entry.blinding())
        .map_err(|_| CustomRingError::HashingFailed)?;
    Ok((spent_hash, nullifier))
}

pub(crate) fn entry_address_input(
    owner: &ListNamespace,
    list_id: ListId,
    member: &Member,
) -> Result<([u8; 32], [u8; 32]), ProgramError> {
    let seed = entry_seed(list_id, member).map_err(|_| CustomRingError::HashingFailed)?;
    let address_utxo_hash = owner
        .address_utxo_hash(&seed)
        .map_err(|_| CustomRingError::HashingFailed)?;
    let address =
        entry_nullifier(&address_utxo_hash, &seed).map_err(|_| CustomRingError::HashingFailed)?;
    Ok((address_utxo_hash, address))
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
