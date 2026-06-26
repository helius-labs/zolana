use light_program_profiler::profile;
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};
use zolana_tree::{InitAddressTreeAccountsInstructionData, TreeAccount};

#[cfg(not(feature = "no-entrypoint"))]
mod entrypoint {
    pinocchio::entrypoint!(crate::process_instruction);
}

const HEIGHT: u8 = 26;
const DISCRIMINATOR: u8 = 7;
const OWNER: [u8; 32] = [1u8; 32];

const OP_INIT: u8 = 0;
const OP_DESERIALIZE: u8 = 1;
const OP_APPEND: u8 = 2;
const OP_NULLIFIER_INSERT: u8 = 3;
const OP_APPEND_BATCH: u8 = 4;

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
            bench_append(&mut tree, &values)
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
            bench_append_batch(&mut tree, &values)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[profile]
fn bench_init(bytes: &mut [u8], pubkey: [u8; 32]) -> ProgramResult {
    let params = InitAddressTreeAccountsInstructionData::default();
    TreeAccount::init(bytes, DISCRIMINATOR, HEIGHT, OWNER, pubkey, params)
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
fn bench_append(tree: &mut TreeAccount<'_>, values: &[[u8; 32]]) -> ProgramResult {
    for value in values {
        tree.utxo_tree().append(*value);
    }
    Ok(())
}

#[profile]
fn bench_append_batch(tree: &mut TreeAccount<'_>, values: &[[u8; 32]]) -> ProgramResult {
    tree.utxo_tree().append_batch(values.iter());
    Ok(())
}

#[profile]
fn bench_nullifier_insert(tree: &mut TreeAccount<'_>, values: &[[u8; 32]]) -> ProgramResult {
    let mut nullifier = tree.nullifer_tree();
    for (i, value) in values.iter().enumerate() {
        nullifier
            .insert_address_into_queue(value, &(i as u64))
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
