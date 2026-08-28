use borsh::BorshDeserialize;
use solana_account::Account;
use solana_pubkey::Pubkey;
use zolana_client::{ClientError, Rpc};
use zolana_interface::{
    pda, state::forester_fee_per_queue_element, NullifierMarker, NULLIFIER_MARKER_SIZE,
    SHIELDED_POOL_PROGRAM_ID,
};
use zolana_tree::TreeAccount;

use crate::test_validator_asserts::{fetch_account, fetch_optional_account};

pub fn nullifier_marker_rent<R: Rpc>(rpc: &R) -> Result<u64, ClientError> {
    rpc.get_minimum_balance_for_rent_exemption(NULLIFIER_MARKER_SIZE)
}

pub fn marker_addresses(tree: &Pubkey, nullifiers: &[[u8; 32]]) -> Vec<Pubkey> {
    nullifiers
        .iter()
        .map(|nullifier| pda::nullifier_marker(tree, nullifier).0)
        .collect()
}

pub fn tree_close_before_index<R: Rpc>(rpc: &R, tree: &Pubkey) -> Result<u64, ClientError> {
    let mut account = fetch_account(rpc, tree)?;
    let tree_account =
        TreeAccount::from_bytes(&mut account.data, tree.to_bytes()).expect("load tree");
    Ok(tree_account.close_before_index())
}

pub fn nullifier_queue_next_index<R: Rpc>(rpc: &R, tree: &Pubkey) -> Result<u64, ClientError> {
    let account = fetch_account(rpc, tree)?;
    Ok(nullifier_queue_next_index_from(&account, tree))
}

pub fn nullifier_queue_next_index_from(account: &Account, tree: &Pubkey) -> u64 {
    let mut data = account.data.clone();
    let mut tree_account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    tree_account.nullifer_tree().queue_batches.next_index
}

pub fn nullifier_zkp_batch_size_from(account: &Account, tree: &Pubkey) -> u64 {
    let mut data = account.data.clone();
    let mut tree_account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    tree_account.nullifer_tree().queue_batches.zkp_batch_size
}

pub fn forester_fee_for_inputs(tree_before: &Account, tree: &Pubkey, num_inputs: u64) -> u64 {
    let zkp_batch_size = nullifier_zkp_batch_size_from(tree_before, tree);
    let fee_per_element =
        forester_fee_per_queue_element(zkp_batch_size).expect("non-zero nullifier zkp batch size");
    fee_per_element * num_inputs
}

pub fn expected_tree_lamports_after_spend(
    tree_lamports_before: u64,
    forester_fee: u64,
    num_inputs: u64,
    marker_rent: u64,
) -> u64 {
    tree_lamports_before + forester_fee - num_inputs * marker_rent
}

#[track_caller]
pub fn assert_tree_lamports_after_spend<R: Rpc>(
    rpc: &R,
    tree: &Pubkey,
    tree_before: &Account,
    num_inputs: u64,
) -> Result<Account, ClientError> {
    let marker_rent = nullifier_marker_rent(rpc)?;
    let forester_fee = forester_fee_for_inputs(tree_before, tree, num_inputs);
    let tree_after = fetch_account(rpc, tree)?;
    assert_eq!(
        tree_after.lamports,
        expected_tree_lamports_after_spend(
            tree_before.lamports,
            forester_fee,
            num_inputs,
            marker_rent
        ),
        "tree collects the forester fee and funds one marker per input"
    );
    assert_eq!(tree_after.owner, tree_before.owner, "tree owner unchanged");
    assert_eq!(
        tree_after.data.len(),
        tree_before.data.len(),
        "tree size unchanged"
    );
    Ok(tree_after)
}

#[track_caller]
pub fn decode_nullifier_marker(
    tree: &Pubkey,
    nullifier: &[u8; 32],
    marker: &Pubkey,
    account: &Account,
    marker_rent: u64,
) -> NullifierMarker {
    let (expected_marker, bump) = pda::nullifier_marker(tree, nullifier);
    assert_eq!(*marker, expected_marker, "nullifier marker address");
    assert_eq!(
        account.owner,
        Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID),
        "nullifier marker {marker} owner"
    );
    assert_eq!(
        account.data.len(),
        NULLIFIER_MARKER_SIZE,
        "nullifier marker {marker} size"
    );
    assert_eq!(
        account.lamports, marker_rent,
        "nullifier marker {marker} holds exactly its rent"
    );
    assert!(!account.executable, "nullifier marker {marker} executable");
    let decoded = NullifierMarker::try_from_slice(&account.data)
        .unwrap_or_else(|error| panic!("decode nullifier marker {marker}: {error}"));
    assert_eq!(decoded.bump, bump, "nullifier marker {marker} bump");
    decoded
}

#[track_caller]
pub fn assert_nullifier_marker<R: Rpc>(
    rpc: &R,
    tree: &Pubkey,
    nullifier: &[u8; 32],
    expected_queue_index: u64,
) -> Result<Pubkey, ClientError> {
    let marker_rent = nullifier_marker_rent(rpc)?;
    let (marker, _) = pda::nullifier_marker(tree, nullifier);
    let account = fetch_account(rpc, &marker)?;
    let decoded = decode_nullifier_marker(tree, nullifier, &marker, &account, marker_rent);
    assert_eq!(
        decoded.queue_index, expected_queue_index,
        "nullifier marker {marker} queue index"
    );
    Ok(marker)
}

#[track_caller]
pub fn assert_nullifier_markers<R: Rpc>(
    rpc: &R,
    tree: &Pubkey,
    nullifiers: &[[u8; 32]],
) -> Result<Vec<NullifierMarker>, ClientError> {
    let marker_rent = nullifier_marker_rent(rpc)?;
    nullifiers
        .iter()
        .zip(marker_addresses(tree, nullifiers))
        .map(|(nullifier, marker)| {
            let account = fetch_account(rpc, &marker)?;
            Ok(decode_nullifier_marker(
                tree,
                nullifier,
                &marker,
                &account,
                marker_rent,
            ))
        })
        .collect()
}

#[track_caller]
pub fn assert_nullifier_markers_absent<R: Rpc>(
    rpc: &R,
    tree: &Pubkey,
    nullifiers: &[[u8; 32]],
) -> Result<(), ClientError> {
    for marker in marker_addresses(tree, nullifiers) {
        let account = fetch_optional_account(rpc, &marker)?;
        assert!(
            account.is_none_or(|account| account.lamports == 0),
            "nullifier marker {marker} must not exist"
        );
    }
    Ok(())
}
