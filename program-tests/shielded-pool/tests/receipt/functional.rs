//! Proof-backed receipt flow: a real `nullifier-receipt` proof is verified on
//! chain, then a real `merge-receipt` proof spends the receipt's slots.

use shielded_pool_tests::support::{
    merge::RealMergeProof,
    receipt::{prove_receipt_inputs, receipt_inputs},
    transact::{proof_env, tree_progress},
};
use solana_pubkey::Pubkey;
use zolana_client::ComputeBudgetConfig;
use zolana_interface::{
    instruction::instruction_data::merge_transact::MERGE_DEFAULT_INPUT_COUNT,
    state::receipt::ReceiptHeader,
};
use zolana_test_utils::{
    nullifier_pda::assert_nullifier_pdas,
    prover::spawn_workspace_prover,
    transact::{fe, nullifier_tree},
};

const COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// `verify_receipt`: one commitment-aware Groth16 verification plus the slot
/// hash chain.
const VERIFY_RECEIPT_8_CU_CEILING: u64 = 500_000;

/// Receipt-backed merge: the default merge's on-chain work plus a slice
/// comparison, so the default ceilings apply.
const MERGE_RECEIPT_8_CU_CEILING: u64 = 420_000;

/// Prover round trip without a chain: the SDK witness proves and the proof
/// verifies against the committed verifying key.
#[test]
fn receipt_proof_verifies_locally() {
    spawn_workspace_prover();
    let nullifiers: Vec<[u8; 32]> = (1u64..=5).map(|i| fe(i * 7919)).collect();
    let inputs = receipt_inputs(
        Pubkey::new_unique(),
        1,
        &nullifier_tree().expect("nullifier tree"),
        &nullifiers,
        8,
    );
    assert_eq!(inputs.count, 5);
    prove_receipt_inputs(&inputs);
}

fn receipt_backed_merge_at_input_count(input_count: usize, real_input_count: usize) {
    let mut pool = proof_env();
    let tree = pool.tree;

    let built = RealMergeProof {
        input_count,
        real_input_count,
    }
    .build_receipt_backed(&mut pool, 1);
    let verify_cu = built.receipt.publish(&mut pool);
    println!("verify_receipt {input_count} slots: {verify_cu} CU");
    assert!(
        verify_cu <= VERIFY_RECEIPT_8_CU_CEILING,
        "verify_receipt consumed {verify_cu} CU (ceiling {VERIFY_RECEIPT_8_CU_CEILING})"
    );

    let receipt_data = pool
        .rpc
        .account_data(&built.receipt.address)
        .expect("receipt account");
    let header: &ReceiptHeader = bytemuck::from_bytes(&receipt_data[..ReceiptHeader::SIZE]);
    assert_eq!(header.verified, 1, "receipt verified");
    assert_eq!(usize::from(header.count()), input_count, "receipt count");

    let (utxo_next_before, nullifier_next_before) = tree_progress(&pool.rpc, &tree);
    let ix = built.merge.instruction(&pool);
    pool.rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &[],
            ComputeBudgetConfig::new(COMPUTE_UNIT_LIMIT),
        )
        .expect("receipt-backed merge with a valid proof");
    let merge_cu = pool
        .rpc
        .last_transaction_trace()
        .expect("merge trace")
        .compute_units_consumed;
    println!("merge_transact (receipt) {input_count} inputs: {merge_cu} CU");
    assert!(
        merge_cu <= MERGE_RECEIPT_8_CU_CEILING,
        "receipt-backed merge consumed {merge_cu} CU (ceiling {MERGE_RECEIPT_8_CU_CEILING})"
    );

    let (utxo_next_after, nullifier_next_after) = tree_progress(&pool.rpc, &tree);
    assert_eq!(utxo_next_after, utxo_next_before + 1, "one output appended");
    assert_eq!(
        nullifier_next_after,
        nullifier_next_before + input_count as u64,
        "one nullifier queued per input slot"
    );
    assert_nullifier_pdas(&pool.rpc, &tree, &built.merge.nullifiers).expect("nullifier PDAs");

    // The receipt is spent: every nullifier is now pending, so a second merge
    // of the same slots fails on the pending table, not on the receipt.
    pool.rpc.svm.expire_blockhash();
    let ix = built.merge.instruction(&pool);
    pool.rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &[],
            ComputeBudgetConfig::new(COMPUTE_UNIT_LIMIT),
        )
        .expect_err("a receipt slice cannot be spent twice");
}

#[test]
fn receipt_backed_merge_verifies_one_real_input() {
    receipt_backed_merge_at_input_count(MERGE_DEFAULT_INPUT_COUNT, 1);
}

#[test]
fn receipt_backed_merge_verifies_several_real_inputs() {
    receipt_backed_merge_at_input_count(MERGE_DEFAULT_INPUT_COUNT, 3);
}
