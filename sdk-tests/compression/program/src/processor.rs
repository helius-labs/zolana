#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::cpi::invoke_signed_with_bounds;
use pinocchio::{address::address_eq, error::ProgramError, AccountView, Address, ProgramResult};
#[cfg(any(target_os = "solana", target_arch = "bpf"))]
use pinocchio::{
    cpi::{Seed, Signer},
    instruction::{InstructionAccount, InstructionView},
};
use solana_address::address;
use zolana_hasher::{
    hash_chain::create_hash_chain_from_slice, primitives::hash_bytes, Hasher, Poseidon,
};
use zolana_interface::{
    event::MessageData,
    instruction::{
        instruction_data::transact::{ExternalDataHash, ResolvedOutput},
        tag::TRANSACT,
    },
    N_PUBLIC_SLOTS,
};

use crate::{
    error::CompressionError,
    wire::{derive_blinding, derive_state, nullifier, plaintext_payload, state_utxo_hash},
};

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
const ACCOUNT_PDA_SEED: &[u8] = b"compressed-account";

const SPP_ACCOUNT_COUNT: usize = 6;
const PAYER_INDEX: usize = 0;
const INPUT_TREE_INDEX: usize = 1;
const OUTPUT_TREE_INDEX: usize = 2;
const SPP_PROGRAM_INDEX: usize = 3;
const SYSTEM_PROGRAM_INDEX: usize = 4;
const OWNER_SIGNER_INDEX: usize = 5;
const CREATE_PREFIX_LEN: usize = 8 + 32;
const UPDATE_PREFIX_LEN: usize = 8 + 32 + 8 + 32;
const DEFAULT_TREE: Address = address!("trEEbaNobcTESNmtsPBj3FX27q5sDCQePV2kb12FYho");
const SPP_PROGRAM: Address = address!("sppXZU59VoYodv9Accs4hHNTjYiuYmDFyFVjUjPxFsG");

struct ParsedTransact<'a> {
    expiry_unix_ts: u64,
    private_tx_hash: &'a [u8; 32],
    input_nullifier: &'a [u8; 32],
    output_hash: &'a [u8; 32],
    output_owner_tag: &'a [u8; 32],
    output_data: &'a [u8],
}

struct Cursor<'a> {
    bytes: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    fn take<const N: usize>(&mut self) -> Result<&'a [u8; N], ProgramError> {
        let (value, remaining) = self.bytes.split_at_checked(N).ok_or_else(invalid_data)?;
        self.bytes = remaining;
        value.try_into().map_err(|_| invalid_data())
    }

    fn take_slice(&mut self, len: usize) -> Result<&'a [u8], ProgramError> {
        let (value, remaining) = self.bytes.split_at_checked(len).ok_or_else(invalid_data)?;
        self.bytes = remaining;
        Ok(value)
    }

    fn byte(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take::<1>()?[0])
    }

    fn finish(self) -> ProgramResult {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(invalid_data())
        }
    }
}

struct ParsedStateIx<'a> {
    old_value_and_blinding: Option<(u64, [u8; 32])>,
    new_value: u64,
    output_seed: [u8; 32],
    transact_bytes: &'a [u8],
}

fn invalid_data() -> ProgramError {
    CompressionError::InvalidInstructionData.into()
}

fn read_u64(bytes: &[u8]) -> Result<u64, ProgramError> {
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| invalid_data())?,
    ))
}

fn read_array_32(bytes: &[u8]) -> Result<[u8; 32], ProgramError> {
    bytes.try_into().map_err(|_| invalid_data())
}

fn parse_create(data: &[u8]) -> Result<ParsedStateIx<'_>, ProgramError> {
    let prefix = data.get(..CREATE_PREFIX_LEN).ok_or_else(invalid_data)?;
    let transact_bytes = data.get(CREATE_PREFIX_LEN..).ok_or_else(invalid_data)?;
    if transact_bytes.is_empty() {
        return Err(invalid_data());
    }
    Ok(ParsedStateIx {
        old_value_and_blinding: None,
        new_value: read_u64(prefix.get(..8).ok_or_else(invalid_data)?)?,
        output_seed: read_array_32(prefix.get(8..40).ok_or_else(invalid_data)?)?,
        transact_bytes,
    })
}

fn parse_update(data: &[u8]) -> Result<ParsedStateIx<'_>, ProgramError> {
    let prefix = data.get(..UPDATE_PREFIX_LEN).ok_or_else(invalid_data)?;
    let transact_bytes = data.get(UPDATE_PREFIX_LEN..).ok_or_else(invalid_data)?;
    if transact_bytes.is_empty() {
        return Err(invalid_data());
    }
    Ok(ParsedStateIx {
        old_value_and_blinding: Some((
            read_u64(prefix.get(..8).ok_or_else(invalid_data)?)?,
            read_array_32(prefix.get(8..40).ok_or_else(invalid_data)?)?,
        )),
        new_value: read_u64(prefix.get(40..48).ok_or_else(invalid_data)?)?,
        output_seed: read_array_32(prefix.get(48..80).ok_or_else(invalid_data)?)?,
        transact_bytes,
    })
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn derive_pda(authority: &Address) -> (Address, u8) {
    Address::find_program_address(&[ACCOUNT_PDA_SEED, authority.as_array()], &crate::ID)
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn derive_pda(_authority: &Address) -> (Address, u8) {
    unimplemented!("PDA derivation requires Solana runtime syscalls")
}

fn validate_accounts(
    accounts: &[AccountView],
) -> Result<(&AccountView, Address, u8), ProgramError> {
    if accounts.len() != SPP_ACCOUNT_COUNT {
        return Err(CompressionError::InvalidAccounts.into());
    }
    let authority = accounts
        .get(PAYER_INDEX)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !authority.is_signer() {
        return Err(CompressionError::InvalidAuthority.into());
    }
    for index in [INPUT_TREE_INDEX, OUTPUT_TREE_INDEX] {
        let tree = accounts
            .get(index)
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        if !address_eq(tree.address(), &DEFAULT_TREE) {
            return Err(CompressionError::InvalidTree.into());
        }
    }
    let spp_program = accounts
        .get(SPP_PROGRAM_INDEX)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !address_eq(spp_program.address(), &SPP_PROGRAM) {
        return Err(CompressionError::InvalidAccounts.into());
    }
    let system_program = accounts
        .get(SYSTEM_PROGRAM_INDEX)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    if system_program.address() != &Address::default() {
        return Err(CompressionError::InvalidAccounts.into());
    }

    let (pda, bump) = derive_pda(authority.address());
    let owner_signer = accounts
        .get(OWNER_SIGNER_INDEX)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    if !address_eq(owner_signer.address(), &pda) {
        return Err(CompressionError::InvalidPda.into());
    }
    Ok((authority, pda, bump))
}

fn parse_transact(bytes: &[u8]) -> Result<ParsedTransact<'_>, ProgramError> {
    let mut cursor = Cursor::new(bytes);
    let expiry_unix_ts = u64::from_le_bytes(*cursor.take::<8>()?);
    let private_tx_hash = cursor.take::<32>()?;
    let circuit = cursor.take::<5>()?;
    if circuit != &[0, 0, 1, 1, N_PUBLIC_SLOTS as u8]
        || cursor.take::<33>()? != &[0u8; 33]
        || cursor.take::<16>()? != &[0u8; 16]
    {
        return Err(CompressionError::InvalidTransact.into());
    }
    cursor.take_slice(32 + 64 + 32)?;

    if cursor.byte()? != 1 {
        return Err(CompressionError::InvalidTransact.into());
    }
    let input_nullifier = cursor.take::<32>()?;
    cursor.take_slice(2 + 2)?;
    if cursor.take::<4>()? != &[0, 0, 0, 1] {
        return Err(CompressionError::InvalidTransact.into());
    }

    let output_hash = cursor.take::<32>()?;
    if cursor.byte()? != 0 {
        return Err(CompressionError::InvalidTransact.into());
    }
    let owner_tag = cursor.take::<32>()?;
    if cursor.byte()? != 1 {
        return Err(CompressionError::InvalidTransact.into());
    }
    let output_len = usize::from(u16::from_le_bytes(*cursor.take::<2>()?));
    let output_data = cursor.take_slice(output_len)?;
    if cursor.byte()? != 0 {
        return Err(CompressionError::InvalidTransact.into());
    }
    cursor.finish()?;

    Ok(ParsedTransact {
        expiry_unix_ts,
        private_tx_hash,
        input_nullifier,
        output_hash,
        output_owner_tag: owner_tag,
        output_data,
    })
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

#[inline(never)]
fn validate_and_derive(
    authority: &AccountView,
    pda: &Address,
    parsed: &ParsedStateIx<'_>,
) -> ProgramResult {
    let ix = parse_transact(parsed.transact_bytes)?;
    if ix.expiry_unix_ts != u64::MAX {
        return Err(CompressionError::InvalidTransact.into());
    }

    let pda_bytes = pda.to_bytes();
    let state = derive_state(&pda_bytes, authority.address().as_array(), parsed.new_value)?;
    let output_blinding = derive_blinding(&parsed.output_seed)?;
    let expected_output_hash = state_utxo_hash(&state, &output_blinding)?;
    if ix.output_hash != &expected_output_hash || ix.output_owner_tag != &pda_bytes {
        return Err(CompressionError::InvalidState.into());
    }
    let expected_payload = plaintext_payload(&pda_bytes, &state.state_data, parsed.output_seed)?;
    if ix.output_data != expected_payload.as_slice() {
        return Err(CompressionError::InvalidState.into());
    }

    let resolved_output = [ResolvedOutput {
        utxo_hash: ix.output_hash,
        owner_tag: pda_bytes,
        data: Some(ix.output_data),
    }];
    let messages: &[MessageData] = &[];
    let external_data_hash = ExternalDataHash {
        spp_instruction_discriminator: TRANSACT,
        expiry_unix_ts: ix.expiry_unix_ts,
        interface_transfers: &[],
        data_hash: None,
        ring_data_hash: None,
        tx_viewing_pk: &[0u8; 33],
        salt: &[0u8; 16],
        outputs: &resolved_output,
        messages,
    }
    .hash()
    .map_err(|_| CompressionError::HashingFailed)?;

    let (input_hash, address_hash, expected_nullifier) = match parsed.old_value_and_blinding {
        None => {
            let address_seed =
                hash_bytes(&pda_bytes).map_err(|_| CompressionError::HashingFailed)?;
            (
                [0u8; 32],
                state.address_utxo_hash,
                nullifier(&state.address_utxo_hash, &address_seed)?,
            )
        }
        Some((old_value, old_blinding)) => {
            let old_state = derive_state(&pda_bytes, authority.address().as_array(), old_value)?;
            if old_state.address != state.address {
                return Err(CompressionError::InvalidAddress.into());
            }
            let old_hash = state_utxo_hash(&old_state, &old_blinding)?;
            (old_hash, [0u8; 32], nullifier(&old_hash, &old_blinding)?)
        }
    };

    if ix.input_nullifier != &expected_nullifier {
        return Err(CompressionError::InvalidAddress.into());
    }
    let expected_private_tx = private_tx_hash(
        input_hash,
        expected_output_hash,
        address_hash,
        &external_data_hash,
    )?;
    if ix.private_tx_hash != &expected_private_tx {
        return Err(CompressionError::InvalidTransact.into());
    }
    Ok(())
}

#[cfg(any(target_os = "solana", target_arch = "bpf"))]
fn invoke_spp(
    accounts: &[AccountView],
    authority: &Address,
    pda: &Address,
    bump: u8,
    transact_bytes: &[u8],
) -> ProgramResult {
    let metas: Vec<InstructionAccount> = accounts
        .iter()
        .map(|account| {
            InstructionAccount::new(
                account.address(),
                account.is_writable(),
                account.is_signer() || address_eq(account.address(), pda),
            )
        })
        .collect();
    let mut data = Vec::with_capacity(1 + transact_bytes.len());
    data.push(TRANSACT);
    data.extend_from_slice(transact_bytes);
    let instruction = InstructionView {
        program_id: &SPP_PROGRAM,
        accounts: &metas,
        data: &data,
    };
    let bump_seed = [bump];
    let signer_seeds = [
        Seed::from(ACCOUNT_PDA_SEED),
        Seed::from(authority.as_array().as_slice()),
        Seed::from(bump_seed.as_ref()),
    ];
    invoke_signed_with_bounds::<8, _>(
        &instruction,
        accounts,
        &[Signer::from(signer_seeds.as_ref())],
    )
}

#[cfg(not(any(target_os = "solana", target_arch = "bpf")))]
fn invoke_spp(
    _accounts: &[AccountView],
    _authority: &Address,
    _pda: &Address,
    _bump: u8,
    _transact_bytes: &[u8],
) -> ProgramResult {
    unimplemented!("SPP CPI requires Solana runtime syscalls")
}

pub(crate) fn process_create(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let parsed = parse_create(data)?;
    process(accounts, parsed)
}

pub(crate) fn process_update(accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let parsed = parse_update(data)?;
    process(accounts, parsed)
}

#[inline(never)]
fn process(accounts: &mut [AccountView], parsed: ParsedStateIx<'_>) -> ProgramResult {
    let (authority, pda, bump) = validate_accounts(accounts)?;
    validate_and_derive(authority, &pda, &parsed)?;
    invoke_spp(
        accounts,
        authority.address(),
        &pda,
        bump,
        parsed.transact_bytes,
    )
}
