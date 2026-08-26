use custom_ring_interface::{
    PolicyConfig, PolicySourceSlot, N_POLICY_SOURCE_SLOTS, POLICY, POLICY_CONFIG,
};
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
    mutation_private_tx_hash, record_nullifier, record_seed, Holder, Member, PolicySource,
    PolicySources, Record, RecordKind, RecordsOwner, MAX_POLICY_SOURCES, POLICY_RECORDS_PDA_SEED,
};

use crate::{
    error::CustomRingError,
    instructions::{
        loader::{load_config, load_policy_config},
        shared::PdaCheck,
    },
};

/// The ring's own records owner, curator sources enter only through the
/// authority gated source map writes.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub(crate) fn records_pda(program_id: &Address) -> Result<(Address, u8), CustomRingError> {
    Ok(Address::find_program_address(
        &[POLICY_RECORDS_PDA_SEED],
        program_id,
    ))
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub(crate) fn records_pda(_program_id: &Address) -> Result<(Address, u8), CustomRingError> {
    Err(CustomRingError::InvalidRecordsPda)
}

/// A curator's policy config, the canonical `b"policy"` PDA of the program
/// that owns the account, pinned to the same records tree.
pub(crate) fn load_curator_policy_config<'a>(
    account: &'a AccountView,
    records_tree: &Address,
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
    if !address_eq(&config.records_tree, records_tree) {
        return Err(CustomRingError::CuratorTreeMismatch.into());
    }
    Ok(config)
}

/// The map `Policy::hash` binds, rebuilt from the stored slots.
pub(crate) fn kind_owners(
    sources: &[PolicySourceSlot; N_POLICY_SOURCE_SLOTS],
) -> Result<PolicySources, CustomRingError> {
    let mut slots = [PolicySource::default(); MAX_POLICY_SOURCES];
    for (slot, stored) in slots.iter_mut().zip(sources) {
        if stored.kind == 0 {
            continue;
        }
        *slot = PolicySource {
            kind: stored.kind,
            owner_hash: RecordsOwner::new(stored.records.as_array())
                .map_err(|_| CustomRingError::HashingFailed)?
                .owner_hash,
        };
    }
    PolicySources::from_slots(slots).map_err(|_| CustomRingError::InvalidPolicyConfigPda)
}

pub(crate) struct MutationAccounts<'a> {
    pub payer: &'a AccountView,
    pub records_address: Address,
    pub records_bump: u8,
    pub owner: RecordsOwner,
    pub authority: Address,
}

impl<'a> MutationAccounts<'a> {
    /// Everything after the two config accounts is forwarded to SPP position
    /// for position, the payer leads that slice.
    pub fn validate_and_parse(
        program_id: &Address,
        accounts: &'a mut [AccountView],
    ) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let config = iter.next_account("config")?;
        let policy_config = iter.next_account("policy_config")?;
        let payer = iter.next_signer_mut("payer")?;
        let input_tree = iter.next_mut("input_tree")?;
        let output_tree = iter.next_mut("output_tree")?;
        let spp_program = iter.next_account("spp_program")?;
        let system_program = iter.next_account("system_program")?;
        let records = iter.next_account("records")?;
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
        if !address_eq(input_tree.address(), &policy_config.records_tree)
            || !address_eq(output_tree.address(), &policy_config.records_tree)
        {
            return Err(CustomRingError::InvalidPolicyTree.into());
        }
        let records_bump = PdaCheck {
            program_id,
            address: records.address(),
            seeds: &[POLICY_RECORDS_PDA_SEED],
            mismatch: CustomRingError::InvalidRecordsPda,
        }
        .verify()?;
        if records_bump != policy_config.records_bump {
            return Err(CustomRingError::InvalidRecordsPda.into());
        }

        let owner = RecordsOwner::new(records.address().as_array())
            .map_err(|_| CustomRingError::HashingFailed)?;
        let compiled = POLICY
            .hash(&kind_owners(&policy_config.sources)?)
            .map_err(|_| CustomRingError::HashingFailed)?;
        if compiled != policy_config.policy_hash {
            return Err(CustomRingError::PolicyHashMismatch.into());
        }

        Ok(Self {
            payer,
            records_address: *records.address(),
            records_bump,
            owner,
            authority: config.authority,
        })
    }

    pub fn check_mutator(&self, kind: RecordKind, member: &Member) -> ProgramResult {
        match kind.holder() {
            Holder::Member => {
                let signer = Member::owner_tag(self.payer.address().as_array())
                    .map_err(|_| CustomRingError::HashingFailed)?;
                if signer != *member {
                    return Err(CustomRingError::UnauthorizedRecordSigner.into());
                }
            }
            Holder::Authority => {
                if self.payer.address() != &self.authority {
                    return Err(CustomRingError::UnauthorizedRecordSigner.into());
                }
            }
        }
        Ok(())
    }
}

pub(crate) struct RecordTransition {
    pub record: Record,
    pub input: InputUtxo,
    pub input_hash: [u8; 32],
    pub address_utxo_hash: [u8; 32],
    pub proof: TransactProof,
}

impl RecordTransition {
    pub fn into_transact(
        self,
        owner: &RecordsOwner,
        records_address: &Address,
    ) -> Result<TransactIxData, ProgramError> {
        let address = owner
            .address(self.record.kind, &self.record.member)
            .map_err(|_| CustomRingError::HashingFailed)?;
        let output_hash = self
            .record
            .utxo_hash(owner, &address)
            .map_err(|_| CustomRingError::HashingFailed)?;
        let payload = self.record.to_output_data();
        let records_bytes = records_address.to_bytes();
        let resolved_output = [ResolvedOutput {
            utxo_hash: &output_hash,
            owner_tag: records_bytes,
            data: Some(payload.as_slice()),
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
                owner_tag: OwnerTag::Inline(records_bytes),
                data: Some(payload.to_vec()),
            }],
            messages: Vec::new(),
        })
    }
}

pub(crate) fn record_spend_input(
    owner: &RecordsOwner,
    record: &Record,
) -> Result<([u8; 32], [u8; 32]), ProgramError> {
    let address = owner
        .address(record.kind, &record.member)
        .map_err(|_| CustomRingError::HashingFailed)?;
    let spent_hash = record
        .utxo_hash(owner, &address)
        .map_err(|_| CustomRingError::HashingFailed)?;
    let nullifier = record_nullifier(&spent_hash, &record.blinding())
        .map_err(|_| CustomRingError::HashingFailed)?;
    Ok((spent_hash, nullifier))
}

pub(crate) fn record_address_input(
    owner: &RecordsOwner,
    kind: RecordKind,
    member: &Member,
) -> Result<([u8; 32], [u8; 32]), ProgramError> {
    let seed = record_seed(kind, member).map_err(|_| CustomRingError::HashingFailed)?;
    let address_utxo_hash = owner
        .address_utxo_hash(&seed)
        .map_err(|_| CustomRingError::HashingFailed)?;
    let address =
        record_nullifier(&address_utxo_hash, &seed).map_err(|_| CustomRingError::HashingFailed)?;
    Ok((address_utxo_hash, address))
}

/// Forwards `accounts[2..]` to SPP with the records PDA raised to a signer.
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub(crate) fn cpi_spp_records_signed(
    records_address: &Address,
    records_bump: u8,
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
                account.is_signer() || address_eq(account.address(), records_address),
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
    let bump_seed = [records_bump];
    let signer_seeds = [
        Seed::from(POLICY_RECORDS_PDA_SEED),
        Seed::from(bump_seed.as_ref()),
    ];
    invoke_signed_with_bounds::<8, _>(
        &instruction,
        spp_accounts,
        &[Signer::from(signer_seeds.as_ref())],
    )
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub(crate) fn cpi_spp_records_signed(
    _records_address: &Address,
    _records_bump: u8,
    _accounts: &[AccountView],
    _transact: &TransactIxData,
) -> ProgramResult {
    Err(ProgramError::InvalidArgument)
}
