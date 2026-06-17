//! Test policy-zone program for shielded-pool integration tests.

use borsh::BorshDeserialize;
use pinocchio::{
    cpi::{invoke_signed, Seed, Signer},
    error::ProgramError,
    instruction::{InstructionAccount, InstructionView},
    AccountView, Address, ProgramResult,
};
use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use zolana_interface::{
    instruction::{
        create_zone_config, tag, CreateZoneConfigData, ProoflessShieldSplAccounts,
        ZoneProoflessShieldAccounts, ZoneProoflessShieldIxData, PUBLIC_AMOUNT_DEPOSIT_SOL,
        PUBLIC_AMOUNT_DEPOSIT_SPL,
    },
    SHIELDED_POOL_PROGRAM_ID, ZONE_AUTH_PDA_SEED,
};

const TREE: usize = 0;
const DEPOSITOR: usize = 1;
const ZONE_AUTH: usize = 2;

const SOL_SYSTEM_PROGRAM: usize = 3;
const SOL_INTERFACE: usize = 4;
const SOL_USER: usize = 5;
const SOL_SHIELDED_POOL_PROGRAM: usize = 6;
const SOL_FORWARDED_ACCOUNTS: usize = 7;

const SPL_USER_TOKEN: usize = 3;
const SPL_VAULT: usize = 4;
const SPL_REGISTRY: usize = 5;
const SPL_TOKEN_PROGRAM: usize = 6;
const SPL_SHIELDED_POOL_PROGRAM: usize = 7;
const SPL_FORWARDED_ACCOUNTS: usize = 8;

const CREATE_ZONE_PAYER: usize = 0;
const CREATE_ZONE_PROTOCOL_CONFIG: usize = 1;
const CREATE_ZONE_CONFIG: usize = 2;
const CREATE_ZONE_AUTH: usize = 3;
const CREATE_ZONE_SYSTEM: usize = 4;
const CREATE_ZONE_SHIELDED_POOL_PROGRAM: usize = 5;
const CREATE_ZONE_ACCOUNTS: usize = 6;

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let Some(ix_tag) = data.first() else {
        return Err(ProgramError::InvalidInstructionData);
    };
    match *ix_tag {
        tag::CREATE_ZONE_CONFIG => process_create_zone_config(program_id, accounts, data),
        tag::ZONE_PROOFLESS_SHIELD => process_zone_proofless_shield(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_create_zone_config(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let accounts = accounts
        .get(..CREATE_ZONE_ACCOUNTS)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let (zone_auth, bump) = Address::find_program_address(&[ZONE_AUTH_PDA_SEED], program_id);
    if accounts[CREATE_ZONE_AUTH].address() != &zone_auth {
        return Err(ProgramError::InvalidSeeds);
    }
    check_shielded_pool(accounts[CREATE_ZONE_SHIELDED_POOL_PROGRAM].address())?;

    let data = CreateZoneConfigData::try_from_slice(payload(data)?)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    let ix = create_zone_config(pubkey(accounts[CREATE_ZONE_PAYER].address()), data)
        .map_err(|_| ProgramError::InvalidSeeds)?;
    let bump = [bump];
    let seeds = [Seed::from(ZONE_AUTH_PDA_SEED), Seed::from(&bump)];
    let signer = Signer::from(&seeds);
    invoke_interface_ix_signed(
        &ix,
        [
            &accounts[CREATE_ZONE_PAYER],
            &accounts[CREATE_ZONE_PROTOCOL_CONFIG],
            &accounts[CREATE_ZONE_CONFIG],
            &accounts[CREATE_ZONE_AUTH],
            &accounts[CREATE_ZONE_SYSTEM],
        ],
        &signer,
    )
}

fn process_zone_proofless_shield(
    program_id: &Address,
    accounts: &[AccountView],
    data: &[u8],
) -> ProgramResult {
    let data = ZoneProoflessShieldIxData::deserialize(payload(data)?)
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    match data.public_amount_mode {
        PUBLIC_AMOUNT_DEPOSIT_SOL => process_zone_proofless_sol(program_id, accounts, data),
        PUBLIC_AMOUNT_DEPOSIT_SPL => process_zone_proofless_spl(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn process_zone_proofless_sol(
    program_id: &Address,
    accounts: &[AccountView],
    data: ZoneProoflessShieldIxData,
) -> ProgramResult {
    let accounts = accounts
        .get(..SOL_FORWARDED_ACCOUNTS)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let (zone_auth, bump) = Address::find_program_address(&[ZONE_AUTH_PDA_SEED], program_id);
    if accounts[ZONE_AUTH].address() != &zone_auth {
        return Err(ProgramError::InvalidSeeds);
    }
    check_shielded_pool(accounts[SOL_SHIELDED_POOL_PROGRAM].address())?;

    let ix = data
        .cpi_instruction(ZoneProoflessShieldAccounts::sol(
            pubkey(accounts[TREE].address()),
            pubkey(accounts[DEPOSITOR].address()),
        ))
        .map_err(|_| ProgramError::InvalidSeeds)?;
    let bump = [bump];
    let seeds = [Seed::from(ZONE_AUTH_PDA_SEED), Seed::from(&bump)];
    let signer = Signer::from(&seeds);
    invoke_interface_ix_signed(
        &ix,
        [
            &accounts[TREE],
            &accounts[DEPOSITOR],
            &accounts[ZONE_AUTH],
            &accounts[SOL_SYSTEM_PROGRAM],
            &accounts[SOL_INTERFACE],
            &accounts[SOL_USER],
            &accounts[SOL_SHIELDED_POOL_PROGRAM],
        ],
        &signer,
    )
}

fn process_zone_proofless_spl(
    program_id: &Address,
    accounts: &[AccountView],
    data: ZoneProoflessShieldIxData,
) -> ProgramResult {
    let accounts = accounts
        .get(..SPL_FORWARDED_ACCOUNTS)
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let (zone_auth, bump) = Address::find_program_address(&[ZONE_AUTH_PDA_SEED], program_id);
    if accounts[ZONE_AUTH].address() != &zone_auth {
        return Err(ProgramError::InvalidSeeds);
    }
    check_shielded_pool(accounts[SPL_SHIELDED_POOL_PROGRAM].address())?;

    let ix = data
        .cpi_instruction(ZoneProoflessShieldAccounts::spl(
            pubkey(accounts[TREE].address()),
            pubkey(accounts[DEPOSITOR].address()),
            ProoflessShieldSplAccounts {
                user_token: pubkey(accounts[SPL_USER_TOKEN].address()),
                vault: pubkey(accounts[SPL_VAULT].address()),
                registry: pubkey(accounts[SPL_REGISTRY].address()),
                token_program: pubkey(accounts[SPL_TOKEN_PROGRAM].address()),
            },
        ))
        .map_err(|_| ProgramError::InvalidSeeds)?;
    let bump = [bump];
    let seeds = [Seed::from(ZONE_AUTH_PDA_SEED), Seed::from(&bump)];
    let signer = Signer::from(&seeds);
    invoke_interface_ix_signed(
        &ix,
        [
            &accounts[TREE],
            &accounts[DEPOSITOR],
            &accounts[ZONE_AUTH],
            &accounts[SPL_USER_TOKEN],
            &accounts[SPL_VAULT],
            &accounts[SPL_REGISTRY],
            &accounts[SPL_TOKEN_PROGRAM],
            &accounts[SPL_SHIELDED_POOL_PROGRAM],
        ],
        &signer,
    )
}

fn check_shielded_pool(account: &Address) -> Result<(), ProgramError> {
    if account != &Address::from(SHIELDED_POOL_PROGRAM_ID) {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}

fn payload(data: &[u8]) -> Result<&[u8], ProgramError> {
    data.get(1..).ok_or(ProgramError::InvalidInstructionData)
}

fn pubkey(address: &Address) -> Pubkey {
    Pubkey::new_from_array(address.to_bytes())
}

fn invoke_interface_ix_signed<const N: usize>(
    ix: &Instruction,
    accounts: [&AccountView; N],
    signer: &Signer,
) -> ProgramResult {
    if ix.accounts.len() != N {
        return Err(ProgramError::InvalidArgument);
    }

    let metas: [InstructionAccount<'_>; N] = core::array::from_fn(|i: usize| {
        let meta = &ix.accounts[i];
        InstructionAccount::new(accounts[i].address(), meta.is_writable, meta.is_signer)
    });
    let program_id = Address::from(ix.program_id.to_bytes());
    let instruction = InstructionView {
        program_id: &program_id,
        accounts: &metas,
        data: &ix.data,
    };
    invoke_signed(&instruction, &accounts, core::slice::from_ref(signer))
}
