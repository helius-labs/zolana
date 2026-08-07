//! Proof-backed functional test for `merge_chain_transact`. Deposit fifteen
//! UTXOs, collapse them with two chained merge legs and one recursive proof,
//! and send it as one transaction.
//!
//! The gain shows in the assertions. Fifteen nullifiers queue, one
//! output appends, and the intermediate output of the bottom leg never reaches
//! the tree. A plain merge would take two rounds, and the second could not
//! start until the first output was in the tree under an advanced root.
//!
//! The chain proving key is unpublished and regenerated per machine by
//! scripts/generate_keys_aggregate.sh, so this binary is behind the same
//! feature gate as the aggregate ones.

use shielded_pool_tests::support::transact::{proof_env, tree_progress, tree_roots};

use borsh::BorshSerialize;
use num_bigint::BigUint;
use solana_account::Account;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    prover::merge_chain::{merge_chain_external_data_hash, MergeChain, MergeChainLegProof},
    MergeProver, MerkleContext, MerkleProof, NonInclusionProof, ProofCompressed, ProverClient,
    SpendProof, TransferSpendInput, STATE_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_interface::instruction::{
    instruction_data::merge_transact::MERGE_INPUT_COUNT, MergeChainTransact,
};
use zolana_keypair::{
    hash::owner_hash, merge::merge_output_blinding, ShieldedKeypair, ShieldedKeypairTrait,
};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{test_blinding, ZolanaProgramTest};
use zolana_test_utils::transact::nullifier_tree;
use zolana_transaction::{Data, SppProofOutputUtxo, Utxo, SOL_MINT};
use zolana_user_registry_interface::{
    state::{UserRecord, NULLIFIER_PUBKEY_LEN, P256_PUBKEY_LEN},
    user_record_pda, USER_REGISTRY_PROGRAM_ID,
};

/// Levels of the chain under test. One leg at level 0, one at level 1. The top
/// leg spends the bottom leg's output in its last slot.
const LEVELS: [u8; 2] = [1, 1];
/// Tree-backed inputs the shape collapses, 7 per leg plus one.
const TREE_INPUTS: usize = 15;
/// SIMD-0296 raises this to 4096 over QUIC. Until then a chain that exceeds it
/// cannot be sent.
const TRANSACTION_SIZE_LIMIT: usize = 1232;

/// Materialize a registry-owned `UserRecord` account directly in LiteSVM. The
/// chain instruction only reads the record, so fabricating it exercises the
/// same validation as a record created through the registry program.
fn write_user_record(rpc: &mut ZolanaProgramTest, owner: Pubkey) -> Pubkey {
    let mut viewing_pubkey = [7u8; P256_PUBKEY_LEN];
    if let Some(first) = viewing_pubkey.first_mut() {
        *first = 0x02;
    }
    let (address, bump) = user_record_pda(&owner);
    let record = UserRecord {
        owner: solana_address::Address::new_from_array(owner.to_bytes()),
        bump,
        owner_p256: None,
        nullifier_pubkey: [11u8; NULLIFIER_PUBKEY_LEN],
        viewing_pubkey,
        merging_enabled: true,
    };
    let mut data = vec![UserRecord::DISCRIMINATOR];
    record.serialize(&mut data).expect("serialize user record");
    data.resize(UserRecord::SIZE, 0);
    rpc.svm
        .set_account(
            address,
            Account {
                lamports: 1_000_000_000,
                data,
                owner: Pubkey::new_from_array(USER_REGISTRY_PROGRAM_ID),
                executable: false,
                rent_epoch: 0,
            },
        )
        .expect("write user record");
    address
}

#[test]
fn merge_chain_collapses_fifteen_utxos_in_one_transaction() {
    let mut env = proof_env();
    let payer = env.rpc.payer.insecure_clone();
    let payer_pk = payer.pubkey();
    let tree = env.tree.pubkey();
    let zero = [0u8; 32];

    let keypair = ShieldedKeypair::from_solana_keypair(&payer).expect("shielded keypair");
    let record = write_user_record(&mut env.rpc, payer_pk);
    let nullifier_key = keypair.nullifier_key();
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let owner_public_key = keypair.signing_pubkey();
    let owner_field = owner_hash(&owner_public_key, &nullifier_pk).expect("owner field");
    let signing_pk_field = owner_public_key
        .owner_proof_input_hash()
        .expect("signing pk field");

    // Fifteen real inputs, one per tree-backed slot of the chain. Amounts stay
    // zero so the merge balances without a funded deposit path.
    let utxos: Vec<Utxo> = (0..TREE_INPUTS)
        .map(|i| Utxo {
            owner: owner_public_key,
            asset: SOL_MINT,
            amount: 0,
            blinding: test_blinding(i as u8 + 1),
            ring_program_id: None,
            data: Data::default(),
        })
        .collect();
    for utxo in &utxos {
        env.rpc
            .deposit_sol(&tree, &payer, 0, owner_field, utxo.blinding)
            .expect("proofless zero deposit");
    }

    // Every input proves against the root the last deposit left, so one root
    // index covers the whole chain.
    let hashes: Vec<[u8; 32]> = utxos
        .iter()
        .map(|utxo| utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash"))
        .collect();
    let root_index = TREE_INPUTS as u16;
    let (utxo_root, nullifier_root) = tree_roots(&env.rpc, &tree, root_index);
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    for hash in &hashes {
        state_tree.append(hash).expect("append state leaf");
    }
    assert_eq!(state_tree.root(), utxo_root, "state root gate");

    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let merkle_context = MerkleContext {
        tree_type: 0,
        tree: solana_address::Address::new_from_array(tree.to_bytes()),
    };
    let non_inclusion = |nullifier: [u8; 32]| {
        let proof = nf_tree
            .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
            .expect("non-inclusion proof");
        NonInclusionProof {
            leaf: nullifier,
            merkle_context: merkle_context.clone(),
            path: proof.merkle_proof.to_vec(),
            low_element: proof.leaf_lower_range_value,
            low_element_index: proof.leaf_index as u64,
            high_element: proof.leaf_higher_range_value,
            high_element_index: 0,
            root: nullifier_root,
            root_seq: 0,
            root_index: 0,
        }
    };
    let tree_spend = |index: usize| TransferSpendInput {
        utxo: utxos[index].clone(),
        nullifier_key: nullifier_key.clone(),
        data_hash: None,
        ring_data_hash: None,
        proof: Some(SpendProof {
            state: MerkleProof {
                leaf: hashes[index],
                merkle_context: merkle_context.clone(),
                path: state_tree
                    .get_proof_of_leaf(index, true)
                    .expect("state proof")
                    .to_vec(),
                leaf_index: index as u64,
                root: utxo_root,
                root_seq: 0,
                root_index,
            },
            nullifier: non_inclusion(
                nullifier_key
                    .nullifier(&hashes[index], &utxos[index].blinding)
                    .expect("nullifier"),
            ),
        }),
        nullifier_proof: None,
    };

    let merged_output = |first_nullifier: &[u8; 32]| {
        let mut output = SppProofOutputUtxo::new(
            SOL_MINT,
            0,
            keypair.shielded_address().expect("shielded address"),
        )
        .expect("merge output");
        output.blinding =
            merge_output_blinding(&nullifier_key, first_nullifier).expect("output blinding");
        output
    };

    // Every leg folds the same external data hash, and it names the output the
    // pool inserts. That output is known before any leg is proved. Its blinding
    // derives from the top leg's first nullifier, which is a tree UTXO.
    let top_first_nullifier = nullifier_key
        .nullifier(
            &hashes[MERGE_INPUT_COUNT],
            &utxos[MERGE_INPUT_COUNT].blinding,
        )
        .expect("nullifier");
    let external_data_hash = merge_chain_external_data_hash(
        u64::MAX,
        &merged_output(&top_first_nullifier)
            .hash()
            .expect("top output hash"),
    )
    .expect("chain external data hash");

    let bottom_spends: Vec<TransferSpendInput> = (0..MERGE_INPUT_COUNT).map(tree_spend).collect();
    let bottom_first_nullifier = nullifier_key
        .nullifier(&hashes[0], &utxos[0].blinding)
        .expect("nullifier");
    let bottom = MergeProver {
        inputs: bottom_spends,
        output: merged_output(&bottom_first_nullifier),
        expiry_unix_ts: u64::MAX,
        signing_pubkey: owner_public_key,
        nullifier_key: nullifier_key.clone(),
    }
    .build_chain_leg(external_data_hash)
    .expect("build bottom merge");

    // The bottom leg's output, as the top leg spends it. It is in no tree, so
    // its inclusion witness is a scratch tree. The merge circuit checks the
    // path against a root the prover supplies, and for a chained slot that root
    // never leaves the outer proof.
    let intermediate = Utxo {
        owner: owner_public_key,
        asset: SOL_MINT,
        amount: 0,
        blinding: merge_output_blinding(&nullifier_key, &bottom_first_nullifier)
            .expect("output blinding"),
        ring_program_id: None,
        data: Data::default(),
    };
    let intermediate_hash = intermediate
        .hash(&nullifier_pk, &zero, &zero)
        .expect("intermediate hash");
    assert_eq!(
        intermediate_hash, bottom.output_hash,
        "the top leg must spend exactly the output the bottom leg produced"
    );
    let mut scratch = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    scratch.append(&intermediate_hash).expect("append scratch");
    let intermediate_nullifier = nullifier_key
        .nullifier(&intermediate_hash, &intermediate.blinding)
        .expect("intermediate nullifier");

    // The top leg takes the remaining seven tree UTXOs, then the chained slot last.
    let mut top_spends: Vec<TransferSpendInput> =
        (MERGE_INPUT_COUNT..TREE_INPUTS).map(tree_spend).collect();
    top_spends.push(TransferSpendInput {
        utxo: intermediate.clone(),
        nullifier_key: nullifier_key.clone(),
        data_hash: None,
        ring_data_hash: None,
        proof: Some(SpendProof {
            state: MerkleProof {
                leaf: intermediate_hash,
                merkle_context: merkle_context.clone(),
                path: scratch
                    .get_proof_of_leaf(0, true)
                    .expect("scratch proof")
                    .to_vec(),
                leaf_index: 0,
                root: scratch.root(),
                root_seq: 0,
                root_index: 0,
            },
            nullifier: non_inclusion(intermediate_nullifier),
        }),
        nullifier_proof: None,
    });
    let top = MergeProver {
        inputs: top_spends,
        output: merged_output(&top_first_nullifier),
        expiry_unix_ts: u64::MAX,
        signing_pubkey: owner_public_key,
        nullifier_key: nullifier_key.clone(),
    }
    .build_chain_leg(external_data_hash)
    .expect("build top merge");

    let prover = ProverClient::local();
    let chain = MergeChain {
        levels: LEVELS.to_vec(),
        legs: vec![
            MergeChainLegProof {
                proof: prover.prove_merge(&bottom.inputs).expect("prove bottom"),
                result: bottom,
            },
            MergeChainLegProof {
                proof: prover.prove_merge(&top.inputs).expect("prove top"),
                result: top,
            },
        ],
        signing_pk_field,
    };
    let chain_proof = prover
        .prove_merge_chain(&chain.proof_inputs().expect("chain request"))
        .expect("prove merge chain");
    let (proof, commitment) = ProofCompressed::try_from(chain_proof)
        .expect("compress chain proof")
        .into_merge_chain_parts()
        .expect("chain proof carries its commitment");
    let ix_data = chain
        .instruction_data(proof, commitment)
        .expect("chain instruction data");
    assert_eq!(
        ix_data.nullifiers.len(),
        TREE_INPUTS,
        "every tree-backed input publishes its nullifier"
    );

    let (utxo_next_before, nullifier_next_before) = tree_progress(&env.rpc, &tree);
    let ix = MergeChainTransact {
        input_tree: tree,
        output_tree: tree,
        payer: payer_pk,
        user_record: record,
        data: ix_data,
    }
    .instruction();
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);

    // One signature plus its compact-u16 count precede the serialized message
    // in a legacy packet.
    let message = Message::new(&[budget.clone(), ix.clone()], Some(&payer_pk));
    let packet = 1 + 64 + message.serialize().len();
    assert!(
        packet <= TRANSACTION_SIZE_LIMIT,
        "fifteen inputs must fit a legacy packet, got {packet}"
    );

    env.rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect("merge chain with a valid proof");

    let (utxo_next_after, nullifier_next_after) = tree_progress(&env.rpc, &tree);
    assert_eq!(
        utxo_next_after,
        utxo_next_before + 1,
        "only the top output is appended, the intermediate one never reaches the tree"
    );
    assert_eq!(
        nullifier_next_after,
        nullifier_next_before + TREE_INPUTS as u64,
        "fifteen nullifiers queued from one transaction"
    );
}
