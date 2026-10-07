use borsh::BorshSerialize;
use shielded_pool_tests::support::{
    fixtures::Pool,
    merge::{RealMerge, RealMergeProof},
    transact::{proof_env, tree_progress},
};

use solana_instruction::Instruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::ComputeBudgetConfig;
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::instruction_data::merge_transact::{MAX_MERGE_INPUTS, MERGE_DEFAULT_INPUT_COUNT},
    state::{default_tree_fees, NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE},
    NULLIFIER_PDA_SIZE, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{P256Pubkey, ShieldedKeypair, ViewingKey};
use zolana_program_test::{IndexedTransaction, Rejection};
use zolana_test_utils::nullifier_pda::{
    assert_nullifier_pdas, assert_nullifier_pdas_absent, nullifier_pda_addresses,
    nullifier_pda_rent, tree_fees,
};
use zolana_transaction::{
    rebuild_merge, AssetRegistry, LocalShieldedKeys, MergeOutput, MergeRebuild, Mint,
};
use zolana_user_registry_interface::state::{UserRecord, P256_PUBKEY_LEN};

const MERGE_COMPUTE_UNIT_LIMIT: u32 = 1_400_000;

const MERGE_8_CU_CEILING: u64 = 225_000;

const MERGE_24_CU_CEILING: u64 = 300_000;

const MERGE_54_CU_CEILING: u64 = 450_000;

fn merge_cu_ceiling(input_count: usize) -> u64 {
    match input_count {
        8 => MERGE_8_CU_CEILING,
        24 => MERGE_24_CU_CEILING,
        54 => MERGE_54_CU_CEILING,
        other => panic!("no pinned compute-unit ceiling for a {other}-input merge"),
    }
}

fn send_merge(pool: &mut Pool, ix: Instruction) -> IndexedTransaction {
    pool.rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &[],
            ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
        )
        .expect("merge with a valid proof")
}

fn assert_merge_rejected_untouched(
    pool: &mut Pool,
    merge: &RealMerge,
    ix: Instruction,
    error: ShieldedPoolError,
    case: &str,
) {
    let tree_before = pool.rpc.account_data(&pool.tree).expect("tree data");
    let failure = pool
        .rpc
        .create_and_send_default_payer_transaction_with_budget(
            &[ix],
            &[],
            ComputeBudgetConfig::new(MERGE_COMPUTE_UNIT_LIMIT),
        )
        .err()
        .unwrap_or_else(|| panic!("{case}: the merge must be rejected"));
    Rejection::pool(error).at(0).assert_litesvm(failure);
    assert_eq!(
        pool.rpc.account_data(&pool.tree).expect("tree data"),
        tree_before,
        "{case}: a rejected merge leaves the tree untouched"
    );
    assert_nullifier_pdas_absent(&pool.rpc, &pool.tree, &merge.data.nullifiers)
        .unwrap_or_else(|error| panic!("{case}: {error:?}"));
}

fn set_registry_viewing_key(
    pool: &mut Pool,
    record: Pubkey,
    viewing_pubkey: [u8; P256_PUBKEY_LEN],
) {
    let mut account = pool.rpc.svm.get_account(&record).expect("user record");
    let mut user_record =
        UserRecord::try_from_account_data(&account.data).expect("decode user record");
    user_record.viewing_pubkey = viewing_pubkey;
    account.data = vec![UserRecord::DISCRIMINATOR];
    user_record
        .serialize(&mut account.data)
        .expect("encode user record");
    account.data.resize(UserRecord::SIZE, 0);
    pool.rpc
        .svm
        .set_account(record, account)
        .expect("replace registry viewing key");
}

fn default_merge(pool: &mut Pool, real_input_count: usize) -> RealMerge {
    RealMergeProof {
        input_count: MERGE_DEFAULT_INPUT_COUNT,
        real_input_count,
    }
    .build(pool)
}

#[test]
fn merge_rejects_a_tampered_envelope_byte() {
    let mut pool = proof_env();
    let merge = default_merge(&mut pool, 1);

    for case in [
        "first ciphertext byte",
        "last ciphertext byte",
        "ephemeral key x byte",
    ] {
        let mut data = merge.data.clone();
        let envelope = data.envelope.as_mut().expect("default merge envelope");
        let byte = match case {
            "first ciphertext byte" => envelope.ciphertext.first_mut(),
            "last ciphertext byte" => envelope.ciphertext.last_mut(),
            _ => envelope.ephemeral_pk.last_mut(),
        }
        .expect("envelope byte");
        *byte ^= 1;
        let tampered = RealMerge {
            data,
            nullifiers: merge.nullifiers.clone(),
            user_record: merge.user_record,
            cache: merge.cache,
        };
        let ix = tampered.instruction(&pool);
        assert_merge_rejected_untouched(
            &mut pool,
            &merge,
            ix,
            ShieldedPoolError::TransactProofVerificationFailed,
            case,
        );
    }

    let ix = merge.instruction(&pool);
    send_merge(&mut pool, ix);
    assert_nullifier_pdas(&pool.rpc, &pool.tree, &merge.data.nullifiers)
        .expect("the untampered merge spends its inputs");
}

#[test]
fn merge_rejects_a_proof_sealed_to_a_key_other_than_the_registered_one() {
    let mut pool = proof_env();
    let merge = default_merge(&mut pool, 1);
    let owner = ShieldedKeypair::from_keypair(&pool.rpc.payer).expect("shielded keypair");

    let registered = *ViewingKey::new().pubkey().as_bytes();
    set_registry_viewing_key(&mut pool, merge.user_record, registered);
    let ix = merge.instruction(&pool);
    assert_merge_rejected_untouched(
        &mut pool,
        &merge,
        ix.clone(),
        ShieldedPoolError::TransactProofVerificationFailed,
        "proof sealed to the owner's previous viewing key",
    );

    set_registry_viewing_key(
        &mut pool,
        merge.user_record,
        *owner.viewing_pubkey().as_bytes(),
    );
    send_merge(&mut pool, ix);
    assert_nullifier_pdas(&pool.rpc, &pool.tree, &merge.data.nullifiers)
        .expect("the merge sealed to the registered key spends its inputs");
}

#[test]
fn merged_output_rebuilds_from_the_envelope_alone() {
    let mut pool = proof_env();
    let owner = ShieldedKeypair::from_keypair(&pool.rpc.payer).expect("shielded keypair");
    let merge = default_merge(&mut pool, 3);
    let envelope = merge.data.envelope.expect("default merge envelope");
    let (utxo_next_before, _) = tree_progress(&pool.rpc, &pool.tree);

    let ix = merge.instruction(&pool);
    let sent = send_merge(&mut pool, ix);
    let published = pool
        .rpc
        .indexer()
        .fetch_transaction_by_signature(&sent.signature)
        .expect("indexed merge")
        .clone();
    assert_eq!(
        published.merge_output(),
        Some(MergeOutput::Envelope {
            ephemeral_pk: P256Pubkey::from_bytes(envelope.ephemeral_pk).expect("ephemeral key"),
            ciphertext: &envelope.ciphertext,
        }),
        "the event republishes the instruction envelope"
    );

    let assets = AssetRegistry::default();
    let rebuilt = match rebuild_merge(&owner, &published, &[], &assets).expect("rebuild merge") {
        MergeRebuild::Rebuilt(rebuilt) => rebuilt,
        other => panic!("the owner must rebuild the merged output, got {other:?}"),
    };
    let [output] = rebuilt.as_slice() else {
        panic!("a merge rebuilds exactly one output, got {}", rebuilt.len());
    };
    assert_eq!(
        (
            output.utxo_hash,
            output.leaf_index,
            output.tree_id,
            output.utxo.owner,
            output.utxo.asset,
            output.utxo.amount,
            output.nullifier,
        ),
        (
            merge.data.output_utxo_hash,
            utxo_next_before,
            pool.tree_id,
            owner.signing_pubkey(),
            Mint::SOL,
            0,
            owner
                .nullifier_key
                .nullifier(&output.utxo_hash, &output.utxo.blinding)
                .expect("output nullifier"),
        )
    );

    let wrong_viewing_key = ViewingKey::new();
    let mut address = owner.shielded_address().expect("shielded address");
    address.viewing_pubkey = wrong_viewing_key.pubkey();
    let wrong_keys = LocalShieldedKeys::new(
        address,
        vec![wrong_viewing_key],
        owner.nullifier_key.clone(),
    )
    .expect("keys under a wrong viewing key");
    assert_eq!(
        rebuild_merge(&wrong_keys, &published, &[], &assets).expect("rebuild merge"),
        MergeRebuild::NotOurs,
        "a wrong viewing key must not rebuild the merged output"
    );
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
