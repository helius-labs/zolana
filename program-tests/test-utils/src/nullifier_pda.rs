use borsh::BorshDeserialize;
use solana_account::Account;
use solana_pubkey::Pubkey;
use zolana_client::{ClientError, Rpc};
use zolana_interface::{pda, NullifierPda, NULLIFIER_PDA_SIZE, PROGRAM_ID_PUBKEY};
use zolana_tree::{TreeAccount, TreeFeeSchedule};

use crate::test_validator_asserts::{fetch_account, fetch_optional_account};

pub fn nullifier_pda_rent<R: Rpc>(rpc: &R) -> Result<u64, ClientError> {
    rpc.get_minimum_balance_for_rent_exemption(NULLIFIER_PDA_SIZE)
}

pub fn nullifier_pda_addresses(tree: &Pubkey, nullifiers: &[[u8; 32]]) -> Vec<Pubkey> {
    nullifiers
        .iter()
        .map(|nullifier| pda::nullifier_pda(tree, nullifier).0)
        .collect()
}

pub fn tree_id<R: Rpc>(rpc: &R, tree: &Pubkey) -> Result<u16, ClientError> {
    let mut account = fetch_account(rpc, tree)?;
    let tree_account = TreeAccount::from_bytes(&mut account.data, tree.to_bytes())
        .map_err(|error| ClientError::Rpc(format!("load tree {tree}: {error:?}")))?;
    Ok(tree_account.tree_id())
}

pub fn tree_close_before_index<R: Rpc>(rpc: &R, tree: &Pubkey) -> Result<u64, ClientError> {
    let mut account = fetch_account(rpc, tree)?;
    let tree_account = TreeAccount::from_bytes(&mut account.data, tree.to_bytes())
        .map_err(|error| ClientError::Rpc(format!("load tree {tree}: {error:?}")))?;
    Ok(tree_account.close_before_index())
}

pub fn nullifier_queue_next_index<R: Rpc>(rpc: &R, tree: &Pubkey) -> Result<u64, ClientError> {
    let account = fetch_account(rpc, tree)?;
    nullifier_queue_next_index_from(&account, tree)
}

pub fn nullifier_queue_next_index_from(
    account: &Account,
    tree: &Pubkey,
) -> Result<u64, ClientError> {
    let mut data = account.data.clone();
    let mut tree_account = TreeAccount::from_bytes(&mut data, tree.to_bytes())
        .map_err(|error| ClientError::Rpc(format!("load tree {tree}: {error:?}")))?;
    Ok(tree_account.nullifier_tree().queue_next_index)
}

pub fn tree_fees_from(
    account: &Account,
    tree: &Pubkey,
) -> Result<(TreeFeeSchedule, u64), ClientError> {
    let mut data = account.data.clone();
    let tree_account = TreeAccount::from_bytes(&mut data, tree.to_bytes())
        .map_err(|error| ClientError::Rpc(format!("load tree {tree}: {error:?}")))?;
    Ok((tree_account.fees(), tree_account.fee_balance()))
}

pub fn tree_fees<R: Rpc>(rpc: &R, tree: &Pubkey) -> Result<(TreeFeeSchedule, u64), ClientError> {
    let account = fetch_account(rpc, tree)?;
    tree_fees_from(&account, tree)
}

pub fn forester_fee_for_inputs(
    tree_before: &Account,
    tree: &Pubkey,
    num_inputs: u64,
) -> Result<u64, ClientError> {
    let (fees, _) = tree_fees_from(tree_before, tree)?;
    fees.fee_per_nullifier
        .checked_mul(num_inputs)
        .ok_or_else(|| ClientError::Rpc("invalid nullifier forester fee".to_owned()))
}

pub fn expected_tree_lamports_after_spend(
    tree_lamports_before: u64,
    forester_fee: u64,
    num_inputs: u64,
    nullifier_pda_rent: u64,
) -> u64 {
    tree_lamports_before + forester_fee - num_inputs * nullifier_pda_rent
}

#[track_caller]
pub fn assert_tree_lamports_after_spend<R: Rpc>(
    rpc: &R,
    tree: &Pubkey,
    tree_before: &Account,
    num_inputs: u64,
) -> Result<Account, ClientError> {
    let nullifier_pda_rent = nullifier_pda_rent(rpc)?;
    let forester_fee = forester_fee_for_inputs(tree_before, tree, num_inputs)?;
    let tree_after = fetch_account(rpc, tree)?;
    let expected_lamports = expected_tree_lamports_after_spend(
        tree_before.lamports,
        forester_fee,
        num_inputs,
        nullifier_pda_rent,
    );
    assert_eq!(
        (
            tree_after.lamports,
            tree_after.owner,
            tree_after.data.len(),
            tree_after.executable,
        ),
        (
            expected_lamports,
            tree_before.owner,
            tree_before.data.len(),
            tree_before.executable,
        ),
        "tree collects the forester fee and funds one nullifier PDA per input"
    );
    Ok(tree_after)
}

#[track_caller]
pub fn decode_nullifier_pda(
    tree: &Pubkey,
    nullifier: &[u8; 32],
    nullifier_pda: &Pubkey,
    account: &Account,
    nullifier_pda_rent: u64,
    tree_id: u16,
) -> NullifierPda {
    let (expected_nullifier_pda, _) = pda::nullifier_pda(tree, nullifier);
    assert_eq!(
        *nullifier_pda, expected_nullifier_pda,
        "nullifier PDA address"
    );
    let decoded = NullifierPda::try_from_slice(&account.data)
        .unwrap_or_else(|error| panic!("decode nullifier PDA {nullifier_pda}: {error}"));
    let expected_nullifier_pda = NullifierPda {
        queue_index: decoded.queue_index,
        tree_id,
    };
    let expected_account = Account {
        lamports: nullifier_pda_rent,
        data: borsh::to_vec(&expected_nullifier_pda).expect("serialize expected nullifier PDA"),
        owner: PROGRAM_ID_PUBKEY,
        executable: false,
        rent_epoch: account.rent_epoch,
    };
    assert_eq!(
        account, &expected_account,
        "nullifier PDA {nullifier_pda} account"
    );
    decoded
}

#[track_caller]
pub fn assert_nullifier_pda<R: Rpc>(
    rpc: &R,
    tree: &Pubkey,
    nullifier: &[u8; 32],
    expected_queue_index: u64,
) -> Result<Pubkey, ClientError> {
    let nullifier_pda_rent = nullifier_pda_rent(rpc)?;
    let tree_id = tree_id(rpc, tree)?;
    let (nullifier_pda, _) = pda::nullifier_pda(tree, nullifier);
    let account = fetch_account(rpc, &nullifier_pda)?;
    let decoded = decode_nullifier_pda(
        tree,
        nullifier,
        &nullifier_pda,
        &account,
        nullifier_pda_rent,
        tree_id,
    );
    assert_eq!(
        decoded.queue_index, expected_queue_index,
        "nullifier PDA {nullifier_pda} queue index"
    );
    Ok(nullifier_pda)
}

#[track_caller]
pub fn assert_nullifier_pdas<R: Rpc>(
    rpc: &R,
    tree: &Pubkey,
    nullifiers: &[[u8; 32]],
) -> Result<Vec<NullifierPda>, ClientError> {
    let nullifier_pda_rent = nullifier_pda_rent(rpc)?;
    let tree_id = tree_id(rpc, tree)?;
    nullifiers
        .iter()
        .zip(nullifier_pda_addresses(tree, nullifiers))
        .map(|(nullifier, nullifier_pda)| {
            let account = fetch_account(rpc, &nullifier_pda)?;
            Ok(decode_nullifier_pda(
                tree,
                nullifier,
                &nullifier_pda,
                &account,
                nullifier_pda_rent,
                tree_id,
            ))
        })
        .collect()
}

#[track_caller]
pub fn assert_nullifier_pdas_absent<R: Rpc>(
    rpc: &R,
    tree: &Pubkey,
    nullifiers: &[[u8; 32]],
) -> Result<(), ClientError> {
    for nullifier_pda in nullifier_pda_addresses(tree, nullifiers) {
        let account = fetch_optional_account(rpc, &nullifier_pda)?;
        assert!(
            account.is_none_or(|account| account.lamports == 0),
            "nullifier PDA {nullifier_pda} must not exist"
        );
    }
    Ok(())
}
