#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use light_program_profiler::profile;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::{
    cpi::{invoke_signed_with_bounds, Seed, Signer},
    instruction::{InstructionAccount, InstructionView},
};
use solana_address::address;
use zolana_account_checks::AccountIterator;
use zolana_hasher::{hash_chain::create_hash_chain_from_slice, Hasher, Poseidon};
use zolana_interface::{
    event::MessageData,
    instruction::{
        instruction_data::transact::{
            CircuitId, ExternalDataHash, OwnerTag, ResolvedOutput, TransactIxData,
        },
        tag::TRANSACT,
    },
    N_PUBLIC_SLOTS,
};

use crate::{
    error::CompressionError,
    state::{
        derive_address, derive_blinding, derive_state, nullifier, plaintext_payload,
        state_utxo_hash,
    },
};

pub const DEFAULT_TREE: Address = address!("trEEbaNobcTESNmtsPBj3FX27q5sDCQePV2kb12FYho");
pub const SPP_PROGRAM: Address = address!("sppXZU59VoYodv9Accs4hHNTjYiuYmDFyFVjUjPxFsG");

pub struct Transition {
    pub old: Option<(u64, [u8; 32])>,
    pub new_value: u64,
    pub output_seed: [u8; 32],
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
pub fn derive_pda(authority: &Address) -> (Address, u8) {
    Address::find_program_address(&[crate::ACCOUNT_PDA_SEED, authority.as_array()], &crate::ID)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn derive_pda(_authority: &Address) -> (Address, u8) {
    unimplemented!("PDA derivation requires Solana runtime syscalls")
}

pub struct TransitionAccounts<'a> {
    pub authority: &'a AccountView,
    pub payer: &'a AccountView,
    pub input_tree: &'a AccountView,
    pub output_tree: &'a AccountView,
    pub spp_program: &'a AccountView,
    pub system_program: &'a AccountView,
    pub owner_pda: &'a AccountView,
    pub pda: Address,
    pub bump: u8,
}

impl<'a> TransitionAccounts<'a> {
    pub fn validate_and_parse(accounts: &'a mut [AccountView]) -> Result<Self, ProgramError> {
        let mut iter = AccountIterator::new(accounts);
        let authority = iter.next_signer("authority")?;
        let (pda, bump) = derive_pda(authority.address());
        let payer = iter.next_account("payer")?;
        if !address_eq(payer.address(), authority.address()) {
            return Err(CompressionError::InvalidAuthority.into());
        }
        let input_tree = iter.next_account("input_tree")?;
        if !address_eq(input_tree.address(), &DEFAULT_TREE) {
            return Err(CompressionError::InvalidTree.into());
        }
        let output_tree = iter.next_account("output_tree")?;
        if !address_eq(output_tree.address(), &DEFAULT_TREE) {
            return Err(CompressionError::InvalidTree.into());
        }
        let spp_program = iter.next_account("spp_program")?;
        if !address_eq(spp_program.address(), &SPP_PROGRAM) {
            return Err(CompressionError::InvalidAccounts.into());
        }
        let system_program = iter.next_account("system_program")?;
        if system_program.address() != &Address::default() {
            return Err(CompressionError::InvalidAccounts.into());
        }
        let owner_pda = iter.next_account("owner_pda")?;
        if !address_eq(owner_pda.address(), &pda) {
            return Err(CompressionError::InvalidPda.into());
        }
        if !iter.iterator_is_empty() {
            return Err(CompressionError::InvalidAccounts.into());
        }
        Ok(Self {
            authority,
            payer,
            input_tree,
            output_tree,
            spp_program,
            system_program,
            owner_pda,
            pda,
            bump,
        })
    }
}

pub fn validate_transact(
    authority: &Address,
    pda: &Address,
    transition: &Transition,
    transact: &TransactIxData,
) -> ProgramResult {
    if transact.expiry_unix_ts != u64::MAX
        || transact.circuit != CircuitId::ConfidentialEddsa(1, 1, N_PUBLIC_SLOTS as u8)
        || transact.tx_viewing_pk != [0u8; 33]
        || transact.salt != [0u8; 16]
        || !transact.interface_transfers.is_empty()
        || transact.data_hash.is_some()
        || transact.ring_data_hash.is_some()
        || !transact.messages.is_empty()
    {
        return Err(CompressionError::InvalidTransact.into());
    }
    let [input] = transact.inputs.as_slice() else {
        return Err(CompressionError::InvalidTransact.into());
    };
    let [output] = transact.outputs.as_slice() else {
        return Err(CompressionError::InvalidTransact.into());
    };
    let Some(output_data) = output.data.as_deref() else {
        return Err(CompressionError::InvalidTransact.into());
    };

    let pda_bytes = pda.to_bytes();
    let address = derive_address(&pda_bytes)?;
    let state = derive_state(&address.address, authority.as_array(), transition.new_value)?;
    let output_blinding = derive_blinding(&transition.output_seed)?;
    let expected_output_hash =
        state_utxo_hash(&address.owner_hash, &state.data_hash, &output_blinding)?;
    if output.utxo_hash != expected_output_hash || output.owner_tag != OwnerTag::Inline(pda_bytes) {
        return Err(CompressionError::InvalidState.into());
    }
    let expected_payload =
        plaintext_payload(&pda_bytes, &state.state_data, transition.output_seed)?;
    if output_data != expected_payload.as_slice() {
        return Err(CompressionError::InvalidState.into());
    }

    let resolved_output = [ResolvedOutput {
        utxo_hash: &output.utxo_hash,
        owner_tag: pda_bytes,
        data: Some(output_data),
    }];
    let messages: &[MessageData] = &[];
    let external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: TRANSACT,
        expiry_unix_ts: transact.expiry_unix_ts,
        interface_transfers: &[],
        data_hash: None,
        ring_data_hash: None,
        tx_viewing_pk: &transact.tx_viewing_pk,
        salt: &transact.salt,
        outputs: &resolved_output,
        messages,
    }
    .hash()
    .map_err(|_| CompressionError::HashingFailed)?;

    let (input_hash, address_hash, expected_nullifier) = match transition.old {
        None => (
            [0u8; 32],
            address.address_utxo_hash,
            nullifier(&address.address_utxo_hash, &address.address_seed)?,
        ),
        Some((old_value, old_blinding)) => {
            let old_state = derive_state(&address.address, authority.as_array(), old_value)?;
            let old_hash =
                state_utxo_hash(&address.owner_hash, &old_state.data_hash, &old_blinding)?;
            (old_hash, [0u8; 32], nullifier(&old_hash, &old_blinding)?)
        }
    };

    if input.nullifier_hash != expected_nullifier {
        return Err(CompressionError::InvalidAddress.into());
    }
    let expected_private_tx = private_tx_hash(
        input_hash,
        expected_output_hash,
        address_hash,
        &external_data_hash,
    )?;
    if transact.private_tx_hash != expected_private_tx {
        return Err(CompressionError::InvalidTransact.into());
    }
    Ok(())
}

fn private_tx_hash(
    input_hash: [u8; 32],
    output_hash: [u8; 32],
    address_hash: [u8; 32],
    external_data_hash: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    let input_chain =
        create_hash_chain_from_slice(&[input_hash]).map_err(|_| CompressionError::HashingFailed)?;
    let output_chain = create_hash_chain_from_slice(&[output_hash])
        .map_err(|_| CompressionError::HashingFailed)?;
    let address_chain = create_hash_chain_from_slice(&[address_hash])
        .map_err(|_| CompressionError::HashingFailed)?;
    Poseidon::hashv(&[
        &input_chain,
        &output_chain,
        &address_chain,
        external_data_hash,
    ])
    .map_err(|_| CompressionError::HashingFailed.into())
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
#[inline(never)]
#[profile]
pub fn cpi_spp_transact_signed(
    authority: &Address,
    pda: &Address,
    bump: u8,
    accounts: &[AccountView],
    transact_bytes: &[u8],
) -> ProgramResult {
    let spp_accounts = accounts
        .get(1..)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let metas: Vec<InstructionAccount> = spp_accounts
        .iter()
        .map(|account| {
            InstructionAccount::new(
                account.address(),
                account.is_writable(),
                account.is_signer() || address_eq(account.address(), pda),
            )
        })
        .collect();
    let mut instruction_data = Vec::with_capacity(1 + transact_bytes.len());
    instruction_data.push(TRANSACT);
    instruction_data.extend_from_slice(transact_bytes);
    let instruction = InstructionView {
        program_id: &SPP_PROGRAM,
        accounts: &metas,
        data: &instruction_data,
    };
    let bump_seed = [bump];
    let signer_seeds = [
        Seed::from(crate::ACCOUNT_PDA_SEED),
        Seed::from(authority.as_array().as_slice()),
        Seed::from(bump_seed.as_ref()),
    ];
    invoke_signed_with_bounds::<8, _>(
        &instruction,
        spp_accounts,
        &[Signer::from(signer_seeds.as_ref())],
    )
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
pub fn cpi_spp_transact_signed(
    _authority: &Address,
    _pda: &Address,
    _bump: u8,
    _accounts: &[AccountView],
    _transact_bytes: &[u8],
) -> ProgramResult {
    unimplemented!("SPP CPI requires Solana runtime syscalls")
}
