use borsh::BorshSerialize;
use light_batched_merkle_tree::merkle_tree::BatchedMerkleTreeAccount;
use light_hasher::{Hasher, Poseidon};
use light_program_test::{PoolTestRig, RigError};
use light_sparse_merkle_tree::SparseMerkleTree;
use shielded_pool_program::instructions::create_pool_tree::init::{
    address_sub_tree_slice_mut, pool_tree_account_size, state_next_index_offset, state_root_offset,
    STATE_HEIGHT,
};
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::instruction::{
    encode_instruction, tag, BatchUpdateAddressTreeData, CreatePoolTreeData,
};

fn rig() -> Option<PoolTestRig> {
    match PoolTestRig::new() {
        Ok(r) => Some(r),
        Err(RigError::MissingProgram(_)) => {
            eprintln!("skipping shielded-pool litesvm test: shielded_pool_program.so missing");
            None
        }
        Err(e) => panic!("rig boot failed: {e}"),
    }
}

fn tree_account_size() -> u64 {
    pool_tree_account_size() as u64
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

fn read_state_root(data: &[u8]) -> [u8; 32] {
    let offset = state_root_offset();
    let mut root = [0u8; 32];
    root.copy_from_slice(&data[offset..offset + 32]);
    root
}

fn address_queue_next_index(mut data: Vec<u8>, tree_pubkey: Pubkey) -> u64 {
    let tree_address = pinocchio::Address::new_from_array(tree_pubkey.to_bytes());
    let address_slice = address_sub_tree_slice_mut(&mut data).expect("address sub-tree slice");
    let tree = BatchedMerkleTreeAccount::address_from_bytes(address_slice, &tree_address).unwrap();
    tree.get_metadata().queue_batches.next_index
}

fn err_string<T>(result: Result<T, RigError>) -> String {
    match result {
        Ok(_) => panic!("instruction must fail"),
        Err(err) => format!("{err}"),
    }
}

fn assert_err_contains<T>(result: Result<T, RigError>, needle: &str) {
    let msg = err_string(result);
    assert!(
        msg.contains(needle),
        "expected error containing {needle:?}, got: {msg}"
    );
}

fn shielded_pool_ix<T: BorshSerialize>(
    rig: &PoolTestRig,
    accounts: Vec<AccountMeta>,
    tag: u8,
    data: &T,
) -> Instruction {
    Instruction {
        program_id: rig.program_id,
        accounts,
        data: encode_instruction(tag, data),
    }
}

#[test]
fn create_pool_tree_initializes_exact_combined_layout() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");

    let data = rig.account_data(&tree.pubkey()).expect("account data");
    assert_eq!(data.len(), pool_tree_account_size());
    assert_eq!(read_u64(&data, 0), 1, "combined discriminator");
    assert_eq!(read_u64(&data, state_next_index_offset()), 0);
    assert_eq!(
        read_state_root(&data),
        <Poseidon as Hasher>::zero_bytes()[STATE_HEIGHT]
    );
    assert_eq!(address_queue_next_index(data, tree.pubkey()), 0);
}

#[test]
fn create_pool_tree_rejects_bad_account_shapes() {
    let Some(mut rig) = rig() else {
        return;
    };
    let payer_pubkey = rig.payer.pubkey();
    rig.airdrop(&payer_pubkey, 50_000_000_000)
        .expect("top up payer");

    assert_err_contains(
        rig.create_pool_tree_with_size(tree_account_size() - 1),
        "Custom(1)",
    );

    let readonly_tree = rig
        .create_program_owned_account(tree_account_size())
        .expect("create program account");
    let payer = rig.payer.insecure_clone();
    let readonly_ix = shielded_pool_ix(
        &rig,
        vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new_readonly(readonly_tree.pubkey(), false),
        ],
        tag::CREATE_POOL_TREE,
        &CreatePoolTreeData,
    );
    assert_err_contains(
        rig.send_instructions(&[readonly_ix], &[&payer]),
        "Custom(1)",
    );

    let wrong_owner = rig
        .create_account_with_owner(tree_account_size(), Pubkey::default())
        .expect("create system-owned account");
    let payer = rig.payer.insecure_clone();
    let wrong_owner_ix = shielded_pool_ix(
        &rig,
        vec![
            AccountMeta::new_readonly(payer.pubkey(), true),
            AccountMeta::new(wrong_owner.pubkey(), false),
        ],
        tag::CREATE_POOL_TREE,
        &CreatePoolTreeData,
    );
    assert_err_contains(
        rig.send_instructions(&[wrong_owner_ix], &[&payer]),
        "Custom(1)",
    );

    let missing_signer_tree = rig
        .create_program_owned_account(tree_account_size())
        .expect("create program account");
    let nonsigner = rig
        .create_account_with_owner(0, Pubkey::default())
        .expect("create nonsigner account");
    let payer = rig.payer.insecure_clone();
    let missing_signer_ix = shielded_pool_ix(
        &rig,
        vec![
            AccountMeta::new_readonly(nonsigner.pubkey(), false),
            AccountMeta::new(missing_signer_tree.pubkey(), false),
        ],
        tag::CREATE_POOL_TREE,
        &CreatePoolTreeData,
    );
    assert_err_contains(
        rig.send_instructions(&[missing_signer_ix], &[&payer]),
        "Custom(1)",
    );
}

#[test]
fn append_state_leaves_persists_sparse_tree_state() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let mut reference = SparseMerkleTree::<Poseidon, STATE_HEIGHT>::new_empty();

    let first_batch = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
    rig.append_state_leaves(&tree, first_batch.clone())
        .expect("append first batch");
    for leaf in first_batch {
        reference.append(leaf);
    }
    let data = rig.account_data(&tree.pubkey()).expect("account data");
    assert_eq!(read_u64(&data, state_next_index_offset()), 3);
    assert_eq!(read_state_root(&data), reference.root());

    let second_batch = vec![[4u8; 32], [5u8; 32]];
    rig.append_state_leaves(&tree, second_batch.clone())
        .expect("append second batch");
    for leaf in second_batch {
        reference.append(leaf);
    }
    let data = rig.account_data(&tree.pubkey()).expect("account data");
    assert_eq!(read_u64(&data, state_next_index_offset()), 5);
    assert_eq!(read_state_root(&data), reference.root());
}

#[test]
fn append_state_leaves_rejects_empty_and_uninitialized_accounts() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let before = rig.account_data(&tree.pubkey()).expect("account data");
    assert_err_contains(rig.append_state_leaves(&tree, vec![]), "Custom(3)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before,
        "failed empty append must not mutate the tree"
    );

    let uninitialized = rig
        .create_program_owned_account(tree_account_size())
        .expect("create uninitialized account");
    assert_err_contains(
        rig.append_state_leaves(&uninitialized, vec![[9u8; 32]]),
        "Custom(6)",
    );
}

#[test]
fn insert_addresses_persists_queue_and_rejects_bad_batches() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");

    let before = rig.account_data(&tree.pubkey()).expect("account data");
    assert_err_contains(rig.insert_addresses(&tree, vec![]), "Custom(2)");
    assert_eq!(
        rig.account_data(&tree.pubkey()).expect("account data"),
        before,
        "failed empty insert must not mutate the tree"
    );

    rig.insert_addresses(&tree, vec![[30u8; 32], [10u8; 32]])
        .expect("insert addresses");
    let data = rig.account_data(&tree.pubkey()).expect("account data");
    assert_eq!(address_queue_next_index(data, tree.pubkey()), 2);

    let err = rig
        .insert_addresses(&tree, vec![[30u8; 32]])
        .expect_err("duplicate address must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("Custom(7)") || msg.contains("AddressQueueInsertFailed"),
        "expected queue insert failure for duplicate address, got: {msg}"
    );
}

#[test]
fn batch_update_address_tree_rejects_zero_root_before_auth() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");

    let data = BatchUpdateAddressTreeData {
        new_root: [0u8; 32],
        compressed_proof_a: [0u8; 32],
        compressed_proof_b: [0u8; 64],
        compressed_proof_c: [0u8; 32],
    };
    assert_err_contains(rig.batch_update_address_tree(&tree, data), "Custom(4)");
}

#[test]
fn runtime_rejects_malformed_payloads_and_unknown_tags() {
    let Some(mut rig) = rig() else {
        return;
    };
    let tree = rig
        .create_pool_tree(tree_account_size())
        .expect("create_pool_tree");
    let payer = rig.payer.insecure_clone();
    let accounts = vec![
        AccountMeta::new_readonly(payer.pubkey(), true),
        AccountMeta::new(tree.pubkey(), false),
    ];

    let malformed = Instruction {
        program_id: rig.program_id,
        accounts: accounts.clone(),
        data: vec![tag::INSERT_ADDRESSES, 1, 2, 3],
    };
    assert_err_contains(rig.send_instructions(&[malformed], &[&payer]), "Custom(0)");

    let payer = rig.payer.insecure_clone();
    let unknown_tag = Instruction {
        program_id: rig.program_id,
        accounts,
        data: vec![255],
    };
    assert_err_contains(
        rig.send_instructions(&[unknown_tag], &[&payer]),
        "InvalidInstructionData",
    );
}
