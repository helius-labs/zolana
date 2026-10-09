//! Test batch settlement program for the SPP output-scaling prototype.
//!
//! The batch authority fills a batch account with input records
//! `(nullifier_hash, tree_index)` and output records `(utxo_hash, owner)` over
//! several write transactions. `settle` then pays every output in one SPP
//! `transact`: the caller supplies the serialized transact fields around the
//! output and input vectors, and the program splices the recorded outputs in
//! as inline outputs without ciphertext and the recorded inputs in as
//! `InputUtxo`s. The settle transaction carries only those fields and the
//! account list. Nothing here is trusted by SPP: every nullifier, output hash
//! and owner tag is bound by the proof's public input hash, so a tampered
//! batch account fails verification.

use pinocchio::{
    cpi::{invoke_signed_with_slice, invoke_with_slice, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use zolana_interface::{instruction::tag, RING_AUTH_PDA_SEED, SHIELDED_POOL_PROGRAM_ID};

pub const PROGRAM_ID: [u8; 32] = *b"spp_batch_program_aaaaaaaaaaaaaa";

pub const BATCH_SEED: &[u8] = b"batch";

pub const INIT_BATCH: u8 = 0;
pub const WRITE_BATCH: u8 = 1;
pub const SETTLE: u8 = 2;
pub const CLOSE_BATCH: u8 = 3;
/// `settle` as a ring program: the CPI is SPP `ring_transact`, signed by this
/// program's `ring_auth` PDA, which SPP takes as the ring config account.
pub const SETTLE_RING: u8 = 4;

pub const WRITE_OUTPUTS: u8 = 0;
pub const WRITE_INPUTS: u8 = 1;

pub const BATCH_DISCRIMINATOR: u8 = 1;

const AUTHORITY_OFFSET: usize = 1;
const OUTPUT_COUNT_OFFSET: usize = 33;
const OUTPUT_CAPACITY_OFFSET: usize = 35;
const INPUT_COUNT_OFFSET: usize = 37;
const INPUT_CAPACITY_OFFSET: usize = 38;

/// `discriminator u8 | authority [32] | output_count u16 (LE) |
/// output_capacity u16 (LE) | input_count u8 | input_capacity u8`, followed
/// by `input_capacity` input records, then `output_capacity` output records.
pub const HEADER_LEN: usize = 39;

/// `utxo_hash [32] | owner [32]`.
pub const RECORD_LEN: usize = 64;

/// `nullifier_hash [32] | tree_index u8`, the `InputUtxo` encoding.
pub const INPUT_RECORD_LEN: usize = 33;

/// One `TransactOutput` as SPP decodes it: `utxo_hash [32]`, the
/// `OwnerTag::Inline` variant byte and tag `[32]`, and `data: None`.
pub const TRANSACT_OUTPUT_LEN: usize = 32 + 1 + 32 + 1;

const OWNER_TAG_INLINE: u8 = 0;
const OPTION_NONE: u8 = 0;

/// Accounts `settle` reads before the forwarded SPP `transact` accounts.
pub const SETTLE_FIXED_ACCOUNTS: usize = 3;

pub const fn batch_account_size(capacity: usize, input_capacity: usize) -> usize {
    HEADER_LEN + INPUT_RECORD_LEN * input_capacity + RECORD_LEN * capacity
}

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let (ix_tag, rest) = data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match *ix_tag {
        INIT_BATCH => process_init_batch(program_id, accounts, rest),
        WRITE_BATCH => process_write_batch(program_id, accounts, rest),
        SETTLE => process_settle(program_id, accounts, rest, false),
        SETTLE_RING => process_settle(program_id, accounts, rest, true),
        CLOSE_BATCH => process_close_batch(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn read_u16(data: &[u8], offset: usize) -> Result<u16, ProgramError> {
    data.get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(ProgramError::InvalidInstructionData)
}

fn read_u8(data: &[u8], offset: usize) -> Result<u8, ProgramError> {
    data.get(offset)
        .copied()
        .ok_or(ProgramError::InvalidInstructionData)
}

/// The record regions of a batch account.
struct Layout {
    output_capacity: usize,
    input_capacity: usize,
}

impl Layout {
    fn read(data: &[u8]) -> Result<Self, ProgramError> {
        Ok(Self {
            output_capacity: usize::from(read_u16(data, OUTPUT_CAPACITY_OFFSET)?),
            input_capacity: usize::from(read_u8(data, INPUT_CAPACITY_OFFSET)?),
        })
    }

    fn outputs_start(&self) -> usize {
        HEADER_LEN + INPUT_RECORD_LEN * self.input_capacity
    }
}

/// Accounts: `[payer (signer, writable), authority (signer), batch (writable),
/// system program]`. Data: `batch_id u64 | output_capacity u16 |
/// input_capacity u8`.
fn process_init_batch(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let [payer, authority, batch, _system_program] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer() || !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let batch_id = data.get(..8).ok_or(ProgramError::InvalidInstructionData)?;
    let output_capacity = read_u16(data, 8)?;
    let input_capacity = read_u8(data, 10)?;
    if output_capacity == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (expected, bump) = Address::find_program_address(
        &[BATCH_SEED, authority.address().as_ref(), batch_id],
        program_id,
    );
    if batch.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    let bump_seed = [bump];
    let seeds = [
        Seed::from(BATCH_SEED),
        Seed::from(authority.address().as_ref()),
        Seed::from(batch_id),
        Seed::from(bump_seed.as_ref()),
    ];
    let space = batch_account_size(usize::from(output_capacity), usize::from(input_capacity));
    pinocchio_system::create_account_with_minimum_balance_signed(
        batch,
        space,
        program_id,
        payer,
        None,
        &[Signer::from(seeds.as_ref())],
    )?;
    let mut account_data = batch.try_borrow_mut()?;
    let header = account_data
        .get_mut(..HEADER_LEN)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let (discriminator, rest) = header
        .split_first_mut()
        .ok_or(ProgramError::AccountDataTooSmall)?;
    *discriminator = BATCH_DISCRIMINATOR;
    rest.get_mut(..32)
        .ok_or(ProgramError::AccountDataTooSmall)?
        .copy_from_slice(authority.address().as_ref());
    header
        .get_mut(OUTPUT_CAPACITY_OFFSET..OUTPUT_CAPACITY_OFFSET + 2)
        .ok_or(ProgramError::AccountDataTooSmall)?
        .copy_from_slice(&output_capacity.to_le_bytes());
    *header
        .get_mut(INPUT_CAPACITY_OFFSET)
        .ok_or(ProgramError::AccountDataTooSmall)? = input_capacity;
    Ok(())
}

/// The authority recorded in a batch account owned by this program.
fn check_batch(
    program_id: &Address,
    batch: &AccountView,
    authority: &AccountView,
) -> ProgramResult {
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if !batch.owned_by(program_id) {
        return Err(ProgramError::IncorrectProgramId);
    }
    let data = batch.try_borrow()?;
    if data.first() != Some(&BATCH_DISCRIMINATOR) {
        return Err(ProgramError::InvalidAccountData);
    }
    if data.get(AUTHORITY_OFFSET..OUTPUT_COUNT_OFFSET) != Some(authority.address().as_ref()) {
        return Err(ProgramError::IncorrectAuthority);
    }
    Ok(())
}

/// Accounts: `[authority (signer), batch (writable)]`. Data: `kind u8 |
/// offset u16 | records`, where `kind` selects output or input records and
/// `offset` is a record index.
fn process_write_batch(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let [authority, batch] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_batch(program_id, batch, authority)?;
    let kind = read_u8(data, 0)?;
    let offset = usize::from(read_u16(data, 1)?);
    let records = data.get(3..).ok_or(ProgramError::InvalidInstructionData)?;
    let mut account_data = batch.try_borrow_mut()?;
    let layout = Layout::read(&account_data)?;
    let (record_len, start, capacity) = match kind {
        WRITE_OUTPUTS => (RECORD_LEN, layout.outputs_start(), layout.output_capacity),
        WRITE_INPUTS => (INPUT_RECORD_LEN, HEADER_LEN, layout.input_capacity),
        _ => return Err(ProgramError::InvalidInstructionData),
    };
    if records.is_empty() || records.len() % record_len != 0 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let end = offset + records.len() / record_len;
    if end > capacity {
        return Err(ProgramError::InvalidInstructionData);
    }
    let start_byte = start + offset * record_len;
    account_data
        .get_mut(start_byte..start_byte + records.len())
        .ok_or(ProgramError::AccountDataTooSmall)?
        .copy_from_slice(records);
    match kind {
        WRITE_OUTPUTS => {
            let stored = usize::from(read_u16(&account_data, OUTPUT_COUNT_OFFSET)?);
            if end > stored {
                let end = u16::try_from(end).map_err(|_| ProgramError::InvalidInstructionData)?;
                account_data
                    .get_mut(OUTPUT_COUNT_OFFSET..OUTPUT_COUNT_OFFSET + 2)
                    .ok_or(ProgramError::AccountDataTooSmall)?
                    .copy_from_slice(&end.to_le_bytes());
            }
        }
        _ => {
            let stored = usize::from(read_u8(&account_data, INPUT_COUNT_OFFSET)?);
            if end > stored {
                *account_data
                    .get_mut(INPUT_COUNT_OFFSET)
                    .ok_or(ProgramError::AccountDataTooSmall)? =
                    u8::try_from(end).map_err(|_| ProgramError::InvalidInstructionData)?;
            }
        }
    }
    Ok(())
}

fn read_section(data: &[u8], offset: usize) -> Result<(&[u8], usize), ProgramError> {
    let len = usize::from(read_u16(data, offset)?);
    let start = offset + 2;
    let section = data
        .get(start..start + len)
        .ok_or(ProgramError::InvalidInstructionData)?;
    Ok((section, start + len))
}

/// Accounts: `[authority (signer), batch, SPP program, ..SPP transact
/// accounts]`. Data: `prefix_len u16 | prefix | middle_len u16 | middle |
/// suffix`, the serialized `TransactIxData` without its tag, cut around the
/// output vector (the prefix ends before the output count, the middle runs
/// from `messages` through `proof`) and around the input vector (the suffix is
/// `tree_contexts`).
fn process_settle(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
    ring: bool,
) -> ProgramResult {
    let (fixed, forwarded) = accounts.split_at(SETTLE_FIXED_ACCOUNTS);
    let [authority, batch, spp] = fixed else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_batch(program_id, batch, authority)?;
    let spp_id = Address::from(SHIELDED_POOL_PROGRAM_ID);
    if spp.address() != &spp_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    let (prefix, middle_offset) = read_section(data, 0)?;
    let (middle, suffix_offset) = read_section(data, middle_offset)?;
    let suffix = data
        .get(suffix_offset..)
        .ok_or(ProgramError::InvalidInstructionData)?;

    let batch_data = batch.try_borrow()?;
    let layout = Layout::read(&batch_data)?;
    let output_count = read_u16(&batch_data, OUTPUT_COUNT_OFFSET)?;
    let output_count_u8 =
        u8::try_from(output_count).map_err(|_| ProgramError::InvalidAccountData)?;
    let input_count = read_u8(&batch_data, INPUT_COUNT_OFFSET)?;
    let outputs_start = layout.outputs_start();
    let outputs = batch_data
        .get(outputs_start..outputs_start + usize::from(output_count) * RECORD_LEN)
        .ok_or(ProgramError::AccountDataTooSmall)?;
    let inputs = batch_data
        .get(HEADER_LEN..HEADER_LEN + usize::from(input_count) * INPUT_RECORD_LEN)
        .ok_or(ProgramError::AccountDataTooSmall)?;

    let mut ix_data = Vec::with_capacity(
        3 + prefix.len()
            + usize::from(output_count) * TRANSACT_OUTPUT_LEN
            + middle.len()
            + inputs.len()
            + suffix.len(),
    );
    ix_data.push(if ring {
        tag::RING_TRANSACT
    } else {
        tag::TRANSACT
    });
    ix_data.extend_from_slice(prefix);
    ix_data.push(output_count_u8);
    for record in outputs.as_chunks::<RECORD_LEN>().0 {
        let (utxo_hash, owner) = record.split_at(32);
        ix_data.extend_from_slice(utxo_hash);
        ix_data.push(OWNER_TAG_INLINE);
        ix_data.extend_from_slice(owner);
        ix_data.push(OPTION_NONE);
    }
    ix_data.extend_from_slice(middle);
    ix_data.push(input_count);
    ix_data.extend_from_slice(inputs);
    ix_data.extend_from_slice(suffix);
    drop(batch_data);

    let ring_auth = ring.then(|| Address::find_program_address(&[RING_AUTH_PDA_SEED], program_id));
    let metas: Vec<InstructionAccount> = forwarded
        .iter()
        .map(|account| {
            let is_ring_auth = ring_auth
                .as_ref()
                .is_some_and(|(address, _)| account.address() == address);
            InstructionAccount::new(
                account.address(),
                account.is_writable(),
                account.is_signer() || is_ring_auth,
            )
        })
        .collect();
    let instruction = InstructionView {
        program_id: &spp_id,
        accounts: &metas,
        data: &ix_data,
    };
    let Some((_, bump)) = ring_auth else {
        return invoke_with_slice(&instruction, forwarded);
    };
    let bump = [bump];
    let seeds = [Seed::from(RING_AUTH_PDA_SEED), Seed::from(&bump)];
    invoke_signed_with_slice(&instruction, forwarded, &[Signer::from(&seeds)])
}

/// Accounts: `[authority (signer), batch (writable), rent recipient
/// (writable)]`.
fn process_close_batch(program_id: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [authority, batch, rent_recipient] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_batch(program_id, batch, authority)?;
    let lamports = batch.lamports();
    let recipient_lamports = rent_recipient
        .lamports()
        .checked_add(lamports)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    rent_recipient.set_lamports(recipient_lamports);
    batch.set_lamports(0);
    batch.close()
}
