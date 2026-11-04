use shielded_pool_tests::support::{
    merge::{RealMerge, RealMergeProof},
    transact::{proof_env, tree_progress},
};
use spr_interface::instruction::instruction_data::MergeOutputEncryption;

use solana_pubkey::Pubkey;
use solana_signer::Signer;
use spr_client::ComputeBudgetConfig;
use spr_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::merge_transact::{MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT},
    state::{default_tree_fees, DEFAULT_FEE_PER_TREE_LAMPORTS},
    NULLIFIER_PDA_SIZE, SHIELDED_POOL_PROGRAM_ID,
};
use spr_program_test::Rejection;
use spr_test_utils::nullifier_pda::{
    assert_nullifier_pdas, assert_nullifier_pdas_absent, nullifier_pda_addresses,
    nullifier_pda_rent, tree_fees,
};

const MERGE_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

const MERGE_8_CU_CEILING: u64 = 225_000;

const MERGE_24_CU_CEILING: u64 = 300_000;

const MERGE_52_CU_CEILING: u64 = 450_000;

fn merge_cu_ceiling(input_count: usize) -> u64 {
    match input_count {
        8 => MERGE_8_CU_CEILING,
        24 => MERGE_24_CU_CEILING,
        52 => MERGE_52_CU_CEILING,
        other => panic!("no pinned compute-unit ceiling for a {other}-input merge"),
    }
}

/// Compact padding fills the merge circuit past the real inputs and is left out
/// of the instruction: SPP queues and creates nullifier PDAs only for the real
/// inputs, and the width follows from their count.
#[test]
fn merge_with_compact_padding_spends_only_the_real_inputs() {
    for (input_count, real_input_count) in [
        (8, 3),
        (MERGE_DEFAULT_INPUT_COUNT, 9),
        (MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT + 1),
    ] {
        let mut pool = proof_env();
        let tree = pool.tree;
        let merge = RealMergeProof {
            input_count,
            real_input_count,
        }
        .build_compact(&mut pool);
        assert_eq!(merge.data.nullifiers.len(), real_input_count);
        let ix = merge.instruction(&pool);
        let (utxo_next_before, nullifier_next_before) = tree_progress(&pool.rpc, &tree);
        pool.rpc
            .create_and_send_default_payer_transaction_with_budget(
                &[ix],
                &[],
                ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
            )
            .expect("compact merge with a valid proof");
        assert_eq!(
            tree_progress(&pool.rpc, &tree),
            (
                utxo_next_before + 1,
                nullifier_next_before + real_input_count as u64
            ),
            "one output appended and one nullifier queued per real input"
        );
        assert_nullifier_pdas(&pool.rpc, &tree, &merge.data.nullifiers)
            .expect("nullifier PDAs for the real inputs");
        assert_nullifier_pdas_absent(&pool.rpc, &tree, &[[0u8; 32]])
            .expect("no nullifier PDA for compact padding");
    }
}

/// The proof binds the salt and every ciphertext element as public inputs, so
/// a relayer cannot swap in a ciphertext the owner cannot decrypt.
#[test]
fn merge_rejects_a_tampered_output_ciphertext_or_salt() {
    let mut pool = proof_env();
    let tree = pool.tree;
    let merge = RealMergeProof {
        input_count: 8,
        real_input_count: 3,
    }
    .build_compact(&mut pool);
    let tree_before = pool.rpc.account_data(&tree).expect("tree data");
    let mut tampered = Vec::new();
    for element in 0..3 {
        let mut data = merge.data.clone();
        match &mut data.output_encryption {
            MergeOutputEncryption::PoseidonCtrV1 { ciphertext, .. } => {
                let byte = ciphertext
                    .get_mut(element)
                    .and_then(|element| element.last_mut())
                    .expect("ciphertext element byte");
                *byte ^= 1;
            }
        }
        tampered.push((format!("ciphertext element {element}"), data));
    }
    let mut data = merge.data.clone();
    match &mut data.output_encryption {
        MergeOutputEncryption::PoseidonCtrV1 { salt, .. } => {
            *salt.last_mut().expect("salt byte") ^= 1;
        }
    }
    tampered.push(("salt".to_string(), data));

    for (label, data) in tampered {
        let ix = RealMerge {
            output_tree: merge.output_tree,
            data,
            nullifiers: merge.nullifiers.clone(),
            user_record: merge.user_record,
            cache: merge.cache,
        }
        .instruction(&pool);
        let error = pool
            .rpc
            .create_and_send_default_payer_transaction_with_budget(
                &[ix],
                &[],
                ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
            )
            .err()
            .unwrap_or_else(|| panic!("a tampered {label} must not verify"));
        Rejection::pool(ShieldedPoolError::TransactProofVerificationFailed)
            .at(0)
            .assert_litesvm(error);
    }
    assert_eq!(
        pool.rpc.account_data(&tree).expect("tree data"),
        tree_before,
        "rejected merges leave the tree untouched"
    );
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
    let (fees, fee_balance_after) = tree_fees(&pool.rpc, &tree).expect("tree fees");
    assert_eq!(
        fees,
        default_tree_fees(),
        "merge leaves the fee schedule untouched"
    );
    assert_eq!(
        fees.fee_per_tree, DEFAULT_FEE_PER_TREE_LAMPORTS,
        "merge fee per tree"
    );
    // The merge writes one tree, so it pays that tree's fee once.
    let forester_fee = fees.fee_per_tree;
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
fn merge_verifies_several_real_inputs_padded_to_the_narrow_shape() {
    merge_at_input_count(8, 3);
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

/// A merge into a tree other than its input tree pays each tree its own
/// `fee_per_tree`. One lamport short of the output tree's fee fails the whole
/// merge and changes no account but the transaction fee payer.
#[test]
fn merge_pays_a_distinct_output_tree_its_own_fee() {
    const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
    const INPUT_TREE_FEE: u64 = 1_234;
    const OUTPUT_TREE_FEE: u64 = 4_321;
    let mut pool = proof_env();
    let payer = pool.rpc.payer.pubkey();
    let input_tree = pool.tree;
    let authority = pool.authority.insecure_clone();
    let output_tree = pool
        .rpc
        .create_tree(&authority)
        .expect("create the output tree");
    for (tree, fee_per_tree) in [(input_tree, INPUT_TREE_FEE), (output_tree, OUTPUT_TREE_FEE)] {
        pool.rpc
            .set_tree_fees(
                &authority,
                &tree,
                spr_tree::TreeFeeSchedule {
                    fee_per_tree,
                    ..default_tree_fees()
                },
            )
            .expect("set tree fee");
    }
    let output_tree_id = spr_interface::state::read_tree_id(
        &pool.rpc.account_data(&output_tree).expect("output tree"),
    )
    .expect("output tree id");
    let merge = RealMergeProof {
        input_count: 8,
        real_input_count: 3,
    }
    .build_compact_into(&mut pool, output_tree, output_tree_id);
    let ix = merge.instruction(&pool);
    let real_inputs = merge.data.nullifiers.len() as u64;

    let payer_floor = pool.rpc.svm.minimum_balance_for_rent_exemption(0);
    let exact = payer_floor + LAMPORTS_PER_SIGNATURE + INPUT_TREE_FEE + OUTPUT_TREE_FEE;
    let set_payer_lamports = |pool: &mut shielded_pool_tests::support::fixtures::Pool,
                              lamports: u64| {
        let mut account = pool.rpc.svm.get_account(&payer).expect("payer");
        account.lamports = lamports;
        pool.rpc.svm.set_account(payer, account).expect("set payer");
    };
    let send = |pool: &mut shielded_pool_tests::support::fixtures::Pool| {
        pool.rpc.svm.expire_blockhash();
        pool.rpc
            .create_and_send_default_payer_transaction_with_budget(
                std::slice::from_ref(&ix),
                &[],
                ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
            )
    };
    let writable: Vec<Pubkey> = ix
        .accounts
        .iter()
        .filter(|meta| meta.is_writable && meta.pubkey != payer)
        .map(|meta| meta.pubkey)
        .collect();
    let snapshot = |pool: &shielded_pool_tests::support::fixtures::Pool| {
        writable
            .iter()
            .map(|address| pool.rpc.svm.get_account(address))
            .collect::<Vec<_>>()
    };

    set_payer_lamports(&mut pool, exact - 1);
    let before = snapshot(&pool);
    send(&mut pool).expect_err("one lamport short of the output tree's fee");
    assert_eq!(snapshot(&pool), before, "a failed merge changes no account");

    set_payer_lamports(&mut pool, exact);
    let (_, input_balance_before) = tree_fees(&pool.rpc, &input_tree).expect("input tree fees");
    let (_, output_balance_before) = tree_fees(&pool.rpc, &output_tree).expect("output fees");
    let input_lamports_before = pool.rpc.svm.get_balance(&input_tree).expect("input tree");
    let output_lamports_before = pool.rpc.svm.get_balance(&output_tree).expect("output tree");
    send(&mut pool).expect("merge into a distinct output tree");

    let nullifier_pda_rent = nullifier_pda_rent(&pool.rpc).expect("nullifier PDA rent");
    assert_eq!(pool.rpc.svm.get_balance(&payer), Some(payer_floor));
    assert_eq!(
        pool.rpc.svm.get_balance(&input_tree),
        Some(input_lamports_before + INPUT_TREE_FEE - real_inputs * nullifier_pda_rent),
        "the input tree collects its fee and funds one nullifier PDA per real input"
    );
    assert_eq!(
        pool.rpc.svm.get_balance(&output_tree),
        Some(output_lamports_before + OUTPUT_TREE_FEE),
        "the output tree collects exactly its own fee"
    );
    assert_eq!(
        (
            tree_fees(&pool.rpc, &input_tree)
                .expect("input tree fees")
                .1,
            tree_fees(&pool.rpc, &output_tree)
                .expect("output tree fees")
                .1,
        ),
        (
            input_balance_before + INPUT_TREE_FEE,
            output_balance_before + OUTPUT_TREE_FEE,
        )
    );
}
