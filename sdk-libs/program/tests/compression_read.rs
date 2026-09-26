#![cfg(feature = "compression")]

use pinocchio::{AccountView, Address};
use zolana_account_checks::account_info::test_account_info::get_account_view;
use zolana_hasher::primitives::right_align;
use zolana_interface::{
    instruction::instruction_data::transact::TreeContext, pda::nullifier_pda,
    state::discriminator::TREE_ACCOUNT_DISCRIMINATOR, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_program::compression::{
    load_tree_id, CompressedAccountError, DataUtxo, PdaOwner, ReadRoots, UtxoKey,
};
use zolana_tree::{NullifierTreeInitParams, TreeAccount, TreeFeeSchedule};

const TREE: [u8; 32] = [21u8; 32];
const TREE_ID: u16 = 5;
const LATEST: TreeContext = TreeContext {
    utxo_tree_root_index: 0,
    nullifier_tree_root_index: 0,
};

fn tree_bytes(discriminator: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; TreeAccount::account_size()];
    TreeAccount::init(
        &mut bytes,
        discriminator,
        32,
        TREE,
        TREE_ID,
        NullifierTreeInitParams::default(),
        TreeFeeSchedule::at_cost(250, 5_000, 46).unwrap(),
    )
    .unwrap();
    bytes
}

fn tree_view(owner: [u8; 32], discriminator: u8) -> AccountView {
    get_account_view(TREE, owner, false, false, false, tree_bytes(discriminator))
}

fn pool_tree() -> AccountView {
    tree_view(SHIELDED_POOL_PROGRAM_ID, TREE_ACCOUNT_DISCRIMINATOR)
}

fn roots_of_pool_tree() -> ReadRoots {
    ReadRoots::load(&mut pool_tree(), &LATEST).unwrap()
}

fn key(owner: &PdaOwner) -> UtxoKey {
    roots_of_pool_tree()
        .key(&DataUtxo {
            owner,
            data_hash: right_align(&[9u8]),
            blinding: right_align(&[5u8]),
        })
        .unwrap()
}

fn account(address: Address, owner: [u8; 32], data: Vec<u8>) -> AccountView {
    get_account_view(address.to_bytes(), owner, false, false, false, data)
}

#[test]
fn load_reads_the_roots_and_tree_of_a_pool_tree() {
    let mut bytes = tree_bytes(TREE_ACCOUNT_DISCRIMINATOR);
    let expected = {
        let tree = TreeAccount::from_bytes(&mut bytes, TREE).unwrap();
        (
            tree.get_utxo_tree_root(0).unwrap(),
            tree.get_nullifier_tree_root(0).unwrap(),
        )
    };
    let roots = roots_of_pool_tree();

    assert_eq!(
        (
            *roots.tree(),
            roots.tree_id(),
            *roots.utxo_root(),
            *roots.nullifier_root()
        ),
        (
            Address::new_from_array(TREE),
            TREE_ID,
            expected.0,
            expected.1
        )
    );
}

#[test]
fn load_rejects_a_tree_the_pool_does_not_own() {
    let mut tree = tree_view([3u8; 32], TREE_ACCOUNT_DISCRIMINATOR);

    assert_eq!(
        ReadRoots::load(&mut tree, &LATEST),
        Err(CompressedAccountError::InvalidTreeAccount)
    );
}

#[test]
fn load_rejects_another_pool_account_type() {
    let mut tree = tree_view(SHIELDED_POOL_PROGRAM_ID, TREE_ACCOUNT_DISCRIMINATOR + 1);

    assert_eq!(
        ReadRoots::load(&mut tree, &LATEST),
        Err(CompressedAccountError::InvalidTreeAccount)
    );
}

#[test]
fn load_rejects_a_borrowed_tree() {
    let mut tree = pool_tree();
    let other = tree;
    let _borrow = other.try_borrow().unwrap();

    assert_eq!(
        ReadRoots::load(&mut tree, &LATEST),
        Err(CompressedAccountError::AccountBorrowFailed)
    );
}

#[test]
fn load_rejects_root_indexes_outside_the_history() {
    for context in [
        TreeContext {
            utxo_tree_root_index: u16::MAX,
            ..LATEST
        },
        TreeContext {
            nullifier_tree_root_index: u16::MAX,
            ..LATEST
        },
    ] {
        assert_eq!(
            ReadRoots::load(&mut pool_tree(), &context),
            Err(CompressedAccountError::InvalidRootIndex)
        );
    }
}

#[test]
fn load_tree_id_reads_a_pool_tree_and_rejects_others() {
    assert_eq!(load_tree_id(&pool_tree()), Ok(TREE_ID));
    assert_eq!(
        load_tree_id(&tree_view([3u8; 32], TREE_ACCOUNT_DISCRIMINATOR)),
        Err(CompressedAccountError::InvalidTreeAccount)
    );
    assert_eq!(
        load_tree_id(&tree_view(
            SHIELDED_POOL_PROGRAM_ID,
            TREE_ACCOUNT_DISCRIMINATOR + 1
        )),
        Err(CompressedAccountError::InvalidTreeAccount)
    );
}

#[test]
fn load_tree_id_rejects_a_mutably_borrowed_tree() {
    let tree = pool_tree();
    let mut other = tree;
    let _borrow = other.try_borrow_mut().unwrap();

    assert_eq!(
        load_tree_id(&tree),
        Err(CompressedAccountError::AccountBorrowFailed)
    );
}

#[test]
fn assert_unspent_accepts_the_empty_canonical_nullifier_pda() {
    let owner = PdaOwner::new(&Address::new_from_array([4u8; 32])).unwrap();
    let key = key(&owner);
    let (pda, _) = nullifier_pda(&Address::new_from_array(TREE), key.nullifier());

    assert_eq!(
        roots_of_pool_tree().assert_unspent(&account(pda, [0u8; 32], Vec::new()), &key),
        Ok(())
    );
}

#[test]
fn assert_unspent_rejects_another_address() {
    let owner = PdaOwner::new(&Address::new_from_array([4u8; 32])).unwrap();
    let key = key(&owner);
    let (other_tree_pda, _) = nullifier_pda(&Address::new_from_array([22u8; 32]), key.nullifier());

    assert_eq!(
        roots_of_pool_tree().assert_unspent(&account(other_tree_pda, [0u8; 32], Vec::new()), &key),
        Err(CompressedAccountError::InvalidNullifierPda)
    );
}

#[test]
fn assert_unspent_rejects_an_existing_nullifier_pda() {
    let owner = PdaOwner::new(&Address::new_from_array([4u8; 32])).unwrap();
    let key = key(&owner);
    let (pda, _) = nullifier_pda(&Address::new_from_array(TREE), key.nullifier());

    for existing in [
        account(pda, SHIELDED_POOL_PROGRAM_ID, vec![1u8; 8]),
        account(pda, SHIELDED_POOL_PROGRAM_ID, Vec::new()),
        account(pda, [0u8; 32], vec![0u8; 1]),
    ] {
        assert_eq!(
            roots_of_pool_tree().assert_unspent(&existing, &key),
            Err(CompressedAccountError::StateSpent)
        );
    }
}
