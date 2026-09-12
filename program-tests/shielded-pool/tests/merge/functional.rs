use shielded_pool_tests::support::{
    merge::RealMergeProof,
    transact::{proof_env, tree_progress},
};

use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::ComputeBudgetConfig;
use zolana_interface::{
    instruction::instruction_data::merge_transact::{MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT},
    state::{default_tree_fees, NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE},
    NULLIFIER_PDA_SIZE, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_test_utils::nullifier_pda::{
    assert_nullifier_pdas, nullifier_pda_addresses, nullifier_pda_rent, tree_fees,
};

const MERGE_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

const MERGE_8_CU_CEILING: u64 = 420_000;

const MERGE_36_CU_CEILING: u64 = 1_000_000;

fn merge_cu_ceiling(input_count: usize) -> u64 {
    match input_count {
        8 => MERGE_8_CU_CEILING,
        36 => MERGE_36_CU_CEILING,
        other => panic!("no pinned compute-unit ceiling for a {other}-input merge"),
    }
}

fn merge_at_input_count(input_count: usize, real_input_count: usize) {
    let mut pool = proof_env();
    let payer_pk = pool.rpc.payer.pubkey();
    let tree = pool.tree;

    let merge = RealMergeProof {
        input_count,
        real_input_count,
    }
    .build(&mut pool);
    let ix = merge.instruction(&pool);

    let (utxo_next_before, nullifier_next_before) = tree_progress(&pool.rpc, &tree);
    let (_, fee_balance_before) = tree_fees(&pool.rpc, &tree).expect("tree fees");
    pool.rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &[],
            ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
        )
        .expect("merge with a valid proof");

    let (utxo_next_after, nullifier_next_after) = tree_progress(&pool.rpc, &tree);
    assert_eq!(utxo_next_after, utxo_next_before + 1, "one output appended");
    assert_eq!(
        nullifier_next_after,
        nullifier_next_before + input_count as u64,
        "one nullifier queued per input slot"
    );

    const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
    // The protocol sponsors nullifier-tree maintenance, so the sponsored
    // default charges nothing per nullifier and the fee balance stays put.
    const FEE_PER_NULLIFIER: u64 = 0;
    let (fees, fee_balance_after) = tree_fees(&pool.rpc, &tree).expect("tree fees");
    assert_eq!(
        fees,
        default_tree_fees(NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE).expect("default tree fees"),
        "merge leaves the fee schedule untouched"
    );
    assert_eq!(
        fees.fee_per_nullifier, FEE_PER_NULLIFIER,
        "merge forester fee per nullifier"
    );
    let forester_fee = fees.fee_per_nullifier * input_count as u64;
    assert_eq!(
        fee_balance_after,
        fee_balance_before + forester_fee,
        "merge credits the fee balance"
    );
    assert_eq!(
        merge.nullifiers.len(),
        input_count,
        "merge queues one nullifier per input slot"
    );
    let nullifier_pda_rent = nullifier_pda_rent(&pool.rpc).expect("nullifier PDA rent");
    let nullifier_pdas = nullifier_pda_addresses(&tree, &merge.nullifiers);
    let nullifier_pda_rent_total = nullifier_pda_rent * input_count as u64;
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let trace = pool
        .rpc
        .last_transaction_trace()
        .expect("successful merge trace");
    println!(
        "merge_transact {input_count} inputs: {} CU",
        trace.compute_units_consumed
    );
    let cu_ceiling = merge_cu_ceiling(input_count);
    assert!(
        trace.compute_units_consumed > 0,
        "merge reported zero compute units"
    );
    assert!(
        trace.compute_units_consumed <= cu_ceiling,
        "merge at {input_count} inputs consumed {} CU (ceiling {cu_ceiling})",
        trace.compute_units_consumed
    );
    let traced: Vec<Pubkey> = trace
        .accounts
        .iter()
        .map(|transition| transition.address)
        .collect();
    assert!(
        traced.contains(&payer_pk)
            && traced.contains(&tree)
            && nullifier_pdas
                .iter()
                .all(|nullifier_pda| traced.contains(nullifier_pda)),
        "trace must journal the payer, the tree and the nullifier PDAs, got {traced:?}"
    );
    for transition in &trace.accounts {
        if nullifier_pdas.contains(&transition.address) {
            assert_eq!(
                transition.before, None,
                "nullifier PDA {} must not exist before the merge",
                transition.address
            );
            let after = transition
                .after
                .as_ref()
                .expect("nullifier PDA after merge");
            assert_eq!(
                after.lamports, nullifier_pda_rent,
                "nullifier PDA holds exactly its rent"
            );
            assert_eq!(after.owner, program_id, "nullifier PDA is program-owned");
            assert_eq!(after.data_len, NULLIFIER_PDA_SIZE, "nullifier PDA size");
            continue;
        }
        let before = transition.before.as_ref().expect("account before merge");
        let after = transition.after.as_ref().expect("account after merge");
        if transition.address == tree {
            assert_eq!(
                before.lamports + forester_fee,
                after.lamports + nullifier_pda_rent_total,
                "tree collects exactly the merge forester fee and funds one nullifier PDA per input"
            );
            assert_eq!(before.owner, after.owner, "tree owner unchanged");
            assert_eq!(before.data_len, after.data_len, "tree size unchanged");
            assert_ne!(before.data_sha256, after.data_sha256, "tree data advanced");
        } else if transition.address == payer_pk {
            assert_eq!(
                before.lamports,
                after.lamports + LAMPORTS_PER_SIGNATURE + forester_fee,
                "payer pays exactly the transaction fee plus the merge forester fee"
            );
            assert_eq!(
                before.data_sha256, after.data_sha256,
                "payer data unchanged"
            );
            assert_eq!(before.owner, after.owner, "payer owner unchanged");
        } else {
            assert_eq!(
                before, after,
                "account {} must be untouched by the merge",
                transition.address
            );
        }
    }
    assert_nullifier_pdas(&pool.rpc, &tree, &merge.nullifiers).expect("nullifier PDAs");
}

#[test]
fn merge_collects_the_exact_forester_fee_from_the_payer() {
    merge_at_input_count(MERGE_DEFAULT_INPUT_COUNT, 1);
}

#[test]
fn merge_verifies_several_real_inputs_padded_to_the_default_shape() {
    merge_at_input_count(MERGE_DEFAULT_INPUT_COUNT, 3);
}

#[test]
fn merge_verifies_the_wide_shape_on_chain() {
    merge_at_input_count(MAX_MERGE_INPUTS, 1);
}

#[test]
fn merge_verifies_several_real_inputs_padded_to_the_wide_shape() {
    merge_at_input_count(MAX_MERGE_INPUTS, 9);
}
