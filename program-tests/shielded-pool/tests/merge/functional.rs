//! Proof-backed functional tests for the `merge_transact` instruction: boot a
//! protocol config and pool tree, deposit one real zero-value input owned by
//! the payer's shielded address, pad to a supported merge shape with dummy
//! slots, prove the merge with the workspace prover, and send it. The proof
//! construction itself lives in `support::merge` so other test binaries can
//! reuse it.
//!
//! Both supported shapes run here, because the on-chain binding is
//! shape-dependent: the public-input hash folds three chains whose length is
//! the declared input count, and the verifying key is selected from that same
//! count. A client-side pairing check cannot catch a program that folds a
//! different width than the circuit, so a real proof must be *accepted* at
//! every supported count.
//!
//! The assertion targets are:
//! * the merge side of the forester-fee contract (the transact side is pinned
//!   in `transact/functional.rs`): a successful merge collects exactly
//!   `input_count x fee_per_nullifier` lamports from the payer into the input
//!   tree, per the tree's stored fee schedule;
//! * the measured compute cost, pinned as an upper bound per shape, because
//!   neither shape fits the 200,000 CU default and callers must raise the
//!   limit.
//!
//! Requires `cargo build-sbf -p shielded-pool-program`.

use shielded_pool_tests::support::{
    merge::RealMergeProof,
    transact::{proof_env, tree_progress},
};

use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_interface::{
    instruction::instruction_data::merge_transact::{MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT},
    state::{default_tree_fees, NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE},
    NULLIFIER_PDA_SIZE, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_test_utils::nullifier_pda::{
    assert_nullifier_pdas, nullifier_pda_addresses, nullifier_pda_rent, tree_fees,
};

/// The per-shape compute limit the merge is sent with. Both shapes exceed the
/// 200,000 CU default; the wide one exceeds it by more than double.
const MERGE_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

/// Measured cost of a successful `merge_transact` at the default 8-input shape
/// (LiteSVM `compute_units_consumed`, 2026-09), pinned at roughly 2x so a
/// regression that materially raises it fails here. Both ceilings sit strictly
/// below `MERGE_COMPUTE_UNIT_LIMIT`, so a regression trips the assert instead
/// of aborting the transaction at the enforced budget (which would make the
/// ceiling unfalsifiable).
///
/// The cost is not a single number: the test payer is a fresh keypair, so the
/// nullifiers -- and therefore each nullifier PDA's canonical bump search --
/// change per run. The observed spread across runs is about 1_500 CU per
/// off-by-one bump attempt per input.
const MERGE_8_CU_CEILING: u64 = 420_000; // observed 193_991-211_991 over five runs

/// Measured cost of a successful `merge_transact` at the wide 36-input shape.
/// The extra 28 inputs each add a queue insertion, a nullifier PDA creation
/// (with its bump search), and two root reads; the Groth16 pairing itself is
/// shape-independent.
const MERGE_36_CU_CEILING: u64 = 900_000; // observed 406_747-445_747 over five runs

fn merge_cu_ceiling(input_count: usize) -> u64 {
    match input_count {
        8 => MERGE_8_CU_CEILING,
        36 => MERGE_36_CU_CEILING,
        other => panic!("no pinned compute-unit ceiling for a {other}-input merge"),
    }
}

/// Prove and send one real merge at `input_count` inputs, asserting the fee
/// contract, the tree progress, the nullifier PDAs, and the compute cost.
fn merge_at_input_count(input_count: usize) {
    let mut pool = proof_env();
    let payer_pk = pool.rpc.payer.pubkey();
    let tree = pool.tree;

    let merge = RealMergeProof { input_count }.build(&mut pool);
    let ix = merge.instruction(&pool);

    let (utxo_next_before, nullifier_next_before) = tree_progress(&pool.rpc, &tree);
    let (_, fee_balance_before) = tree_fees(&pool.rpc, &tree).expect("tree fees");
    // Proof verification and the per-input queue/PDA work need far more than
    // the 200k default budget.
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(MERGE_COMPUTE_UNIT_LIMIT);
    pool.rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect("merge with a valid proof");

    // Tree progress: one nullifier queued per input slot, one merged output
    // appended.
    let (utxo_next_after, nullifier_next_after) = tree_progress(&pool.rpc, &tree);
    assert_eq!(utxo_next_after, utxo_next_before + 1, "one output appended");
    assert_eq!(
        nullifier_next_after,
        nullifier_next_before + input_count as u64,
        "one nullifier queued per input slot"
    );

    // Exact forester fee: `input_count` queue insertions at the tree's stored
    // fee_per_nullifier, collected from the payer into the input tree and
    // credited to the tree's fee balance. The tree in turn funds one nullifier
    // PDA per queued nullifier.
    const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
    const FEE_PER_NULLIFIER: u64 = 190;
    let (fees, fee_balance_after) = tree_fees(&pool.rpc, &tree).expect("tree fees");
    assert_eq!(
        fees,
        default_tree_fees(NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE).expect("default tree fees"),
        "merge leaves the fee schedule untouched"
    );
    // Pinned once, so the fee below is a formula over a known constant rather
    // than a restatement of whatever the tree happens to store (8 inputs ->
    // 1_520 lamports, 36 inputs -> 6_840).
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
    // Reported so a shape's cost is visible in `--nocapture` runs, and pinned
    // below so a regression fails rather than merely printing a bigger number.
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
    merge_at_input_count(MERGE_DEFAULT_INPUT_COUNT);
}

/// The wide shape, end to end through the program. The 36-input merge is the
/// only shape whose on-chain acceptance is not implied by the 8-input run: the
/// public-input hash prefix folds `input_count`-long chains and the verifying
/// key is chosen from the same count, so a width mismatch between program and
/// circuit shows up here and nowhere else.
#[test]
fn merge_verifies_the_wide_shape_on_chain() {
    merge_at_input_count(MAX_MERGE_INPUTS);
}
