use borsh::BorshDeserialize;
use light_program_profiler::profile;
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use zolana_tree::nullifier_tree::{
    layout::NullifierTreeLayout, merkle_tree_update::InstructionDataBatchNullifyInputs,
};
use zolana_tree::{NullifierTreeInitParams, TreeAccount, TreeFeeSchedule, UTXO_TREE_HEIGHT};

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

const HEIGHT: u8 = UTXO_TREE_HEIGHT as u8;
const DISCRIMINATOR: u8 = 7;

const ADDRESS_ZKP: usize = 120;

type AddressTree = NullifierTreeLayout<ADDRESS_ZKP>;

fn load_address_tree(account_data: &mut [u8]) -> Result<&mut AddressTree, ProgramError> {
    let layout: &mut AddressTree =
        wincode::deserialize_mut(account_data).map_err(|_| ProgramError::InvalidAccountData)?;
    layout
        .validate()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(layout)
}

const OP_INIT: u8 = 0;
const OP_DESERIALIZE: u8 = 1;
const OP_APPEND: u8 = 2;
const OP_NULLIFIER_INSERT: u8 = 3;
const OP_APPEND_BATCH: u8 = 4;
const OP_BATCH_UPDATE_NULLIFIER_TREE: u8 = 5;

pub fn process_instruction(
    _program_id: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    let opcode = *data.first().ok_or(ProgramError::InvalidInstructionData)?;
    let n = {
        let bytes = data.get(1..3).ok_or(ProgramError::InvalidInstructionData)?;
        let arr: [u8; 2] = bytes
            .try_into()
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        u16::from_le_bytes(arr)
    };

    let account = accounts
        .first_mut()
        .ok_or(ProgramError::NotEnoughAccountKeys)?;
    let pubkey = account.address().to_bytes();
    let mut store = account
        .try_borrow_mut()
        .map_err(|_| ProgramError::AccountBorrowFailed)?;

    match opcode {
        OP_INIT => bench_init(&mut store, pubkey),
        OP_DESERIALIZE => bench_deserialize(&mut store, pubkey),
        OP_APPEND => {
            let values: Vec<[u8; 32]> = (0..n).map(|i| derive_value(i as u64)).collect();
            let mut tree = TreeAccount::from_bytes(&mut store, pubkey)
                .map_err(|_| ProgramError::InvalidAccountData)?;
            bench_append(&mut tree, &values, Clock::get()?.slot)
        }
        OP_NULLIFIER_INSERT => {
            let values: Vec<[u8; 32]> = (0..n).map(|i| derive_value(i as u64)).collect();
            let mut tree = TreeAccount::from_bytes(&mut store, pubkey)
                .map_err(|_| ProgramError::InvalidAccountData)?;
            bench_nullifier_insert(&mut tree, &values)
        }
        OP_APPEND_BATCH => {
            let values: Vec<[u8; 32]> = (0..n).map(|i| derive_value(i as u64)).collect();
            let mut tree = TreeAccount::from_bytes(&mut store, pubkey)
                .map_err(|_| ProgramError::InvalidAccountData)?;
            bench_append_batch(&mut tree, &values, Clock::get()?.slot)
        }
        OP_BATCH_UPDATE_NULLIFIER_TREE => {
            let ix = InstructionDataBatchNullifyInputs::try_from_slice(
                data.get(1..).ok_or(ProgramError::InvalidInstructionData)?,
            )
            .map_err(|_| ProgramError::InvalidInstructionData)?;
            let tree = load_address_tree(&mut store)?;
            bench_batch_update_nullifier_tree(tree, pubkey, ix)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[profile]
fn bench_init(bytes: &mut [u8], pubkey: [u8; 32]) -> ProgramResult {
    let params = NullifierTreeInitParams::default();
    let fees = TreeFeeSchedule {
        fee_per_nullifier: 190,
        append_reimbursement: 5_000,
        close_reimbursement: 170,
    };
    TreeAccount::init(bytes, DISCRIMINATOR, HEIGHT, pubkey, 0, params, fees)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(())
}

#[profile]
fn bench_deserialize(bytes: &mut [u8], pubkey: [u8; 32]) -> ProgramResult {
    let tree =
        TreeAccount::from_bytes(bytes, pubkey).map_err(|_| ProgramError::InvalidAccountData)?;
    core::hint::black_box(&tree);
    Ok(())
}

#[profile]
fn bench_append(tree: &mut TreeAccount<'_>, values: &[[u8; 32]], slot: u64) -> ProgramResult {
    for value in values {
        tree.utxo_tree()
            .append(*value, slot)
            .map_err(|_| ProgramError::InvalidAccountData)?;
    }
    Ok(())
}

#[profile]
fn bench_append_batch(tree: &mut TreeAccount<'_>, values: &[[u8; 32]], slot: u64) -> ProgramResult {
    tree.utxo_tree()
        .append_batch(values.iter(), slot)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(())
}

#[profile]
fn bench_batch_update_nullifier_tree(
    tree: &mut AddressTree,
    pubkey: [u8; 32],
    ix: InstructionDataBatchNullifyInputs,
) -> ProgramResult {
    tree.update_tree_from_queue(pubkey, ix)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(())
}

#[profile]
fn bench_nullifier_insert(tree: &mut TreeAccount<'_>, values: &[[u8; 32]]) -> ProgramResult {
    let nullifier = tree.nullifier_tree();
    for value in values.iter() {
        nullifier
            .insert_nullifier_into_queue(value)
            .map_err(|_| ProgramError::InvalidAccountData)?;
    }
    Ok(())
}

fn derive_value(counter: u64) -> [u8; 32] {
    let mut value = [0u8; 32];
    for (dst, src) in value.iter_mut().zip(counter.to_le_bytes().iter()) {
        *dst = *src;
    }
    value
}
