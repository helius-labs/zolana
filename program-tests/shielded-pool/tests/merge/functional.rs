//! Proof-backed functional test for the `merge_transact` instruction: boot a
//! protocol config and pool tree, deposit one real zero-value input owned by
//! the payer's shielded address, pad to the fixed 8-in/1-out merge shape with
//! dummy slots, prove the merge with the workspace prover, and send it.
//!
//! The assertion target is the merge side of the forester-fee contract (the
//! transact side is pinned in `transact/functional.rs`): a successful merge
//! collects exactly `MERGE_INPUT_COUNT (8) x fee_per_nullifier` lamports from
//! the payer into the input tree, per the tree's stored fee schedule.
//!
//! Requires `cargo build-sbf -p shielded-pool-program`.

use shielded_pool_tests::support::transact::{proof_env, tree_progress, tree_roots};

use borsh::BorshSerialize;
use groth16_solana::groth16::Groth16Verifier;
use num_bigint::BigUint;
use solana_account::Account;
use solana_compute_budget_interface::ComputeBudgetInstruction;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::{
    MergeProver, MerkleContext, MerkleProof, NonInclusionProof, ProofCompressed, ProverClient,
    SpendProof, TransferSpendInput, STATE_TREE_HEIGHT,
};
use zolana_hasher::Poseidon;
use zolana_interface::{
    instruction::{instruction_data::merge_transact::MERGE_INPUT_COUNT, MergeTransact},
    state::{default_tree_fees, NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE},
    verifying_keys::merge_8_1,
    NULLIFIER_PDA_SIZE, SHIELDED_POOL_PROGRAM_ID,
};
use zolana_keypair::{hash::owner_hash, PublicKey, ShieldedKeypair, ShieldedKeypairTrait};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{test_blinding, ZolanaProgramTest};
use zolana_test_utils::nullifier_pda::{
    assert_nullifier_pdas, nullifier_pda_addresses, nullifier_pda_rent, tree_fees,
};
use zolana_test_utils::transact::nullifier_tree;
use zolana_transaction::{
    instructions::merge::{merge_dummy_nullifier, merge_output_blinding},
    Data, SppProofOutputUtxo, Utxo, SOL_MINT,
};
use zolana_user_registry_interface::{
    state::{UserRecord, NULLIFIER_PUBKEY_LEN, P256_PUBKEY_LEN},
    user_record_pda, USER_REGISTRY_PROGRAM_ID,
};

/// Materialize a registry-owned `UserRecord` account directly in LiteSVM. The
/// merge instruction only reads the record, so fabricating it exercises the
/// same validation as a record created through the registry program. (Local
/// copy of the `merge/contract.rs` helper; test binaries cannot share code.)
fn write_user_record(
    rpc: &mut ZolanaProgramTest,
    owner: Pubkey,
    owner_p256: Option<[u8; P256_PUBKEY_LEN]>,
    merging_enabled: bool,
) -> Pubkey {
    // Compressed-point prefix 0x02 keeps `pk_field(viewing_pubkey)` computable.
    let mut viewing_pubkey = [7u8; P256_PUBKEY_LEN];
    if let Some(first) = viewing_pubkey.first_mut() {
        *first = 0x02;
    }
    // The program pins the record to its canonical registry PDA and bump.
    let (address, bump) = user_record_pda(&owner);
    let record = UserRecord {
        owner: solana_address::Address::new_from_array(owner.to_bytes()),
        bump,
        owner_p256,
        nullifier_pubkey: [11u8; NULLIFIER_PUBKEY_LEN],
        viewing_pubkey,
        merging_enabled,
    };
    let mut data = vec![UserRecord::DISCRIMINATOR];
    record
        .serialize(&mut data)
        .expect("serialize fabricated user record");
    // The registry requires the exact fixed record size; a `None` p256 key
    // serializes short, so zero-pad like the program's own writes do.
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
        .expect("write fabricated user record");
    address
}

#[test]
fn merge_collects_the_exact_forester_fee_from_the_payer() {
    let mut env = proof_env();
    let payer = env.rpc.payer.insecure_clone();
    let payer_pk = payer.pubkey();
    let tree = env.tree;
    let zero = [0u8; 32];

    // The merge owner IS the payer: the shielded keypair derives from the
    // payer's ed25519 secret, so the registry record binds the same key the
    // proof recomputes `signing_pk_field` from.
    let keypair = ShieldedKeypair::from_keypair(&payer).expect("shielded keypair");
    let record = write_user_record(&mut env.rpc, payer_pk, None, true);

    // The real input: a zero-value SOL deposit owned by the payer's shielded
    // address. A fixed nullifier secret keeps the run deterministic.
    let nullifier_key = keypair.nullifier_key();
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let owner_public_key = keypair.signing_pubkey();
    let owner_field = owner_hash(&owner_public_key, &nullifier_pk).expect("owner field");
    let event = env
        .rpc
        .deposit_sol(&tree, &payer, 0, owner_field)
        .expect("proofless zero deposit");
    let utxo = env
        .rpc
        .indexed_deposit_utxo(&event, owner_public_key)
        .expect("indexed deposit UTXO");
    let blinding = utxo.blinding;
    assert_eq!((utxo.asset, utxo.amount), (SOL_MINT, 0));

    // Merkle witnesses against the on-chain roots, gated on the local trees.
    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
    let (utxo_root, nullifier_root) = tree_roots(&env.rpc, &tree, 1);
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&utxo_hash).expect("append state leaf");
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("state proof")
        .to_vec();
    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let merkle_context = MerkleContext {
        tree_type: 0,
        tree: solana_address::Address::new_from_array(tree.to_bytes()),
    };

    let first_nullifier = nullifier_key
        .nullifier(&utxo_hash, &blinding)
        .expect("nullifier");
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&first_nullifier))
        .expect("non-inclusion proof");
    let to_non_inclusion =
        |leaf: [u8; 32], proof: &zolana_merkle_tree::indexed::NonInclusionProof| {
            NonInclusionProof {
                leaf,
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

    // One real input at slot 0; slots 1..8 are dummies whose deterministic
    // merge nullifiers still need non-inclusion witnesses.
    let mut spends = Vec::with_capacity(MERGE_INPUT_COUNT);
    spends.push(TransferSpendInput {
        utxo: utxo.clone(),
        nullifier_key: nullifier_key.clone(),
        data_hash: None,
        ring_data_hash: None,
        proof: Some(SpendProof {
            state: MerkleProof {
                leaf: utxo_hash,
                merkle_context: merkle_context.clone(),
                path: state_path,
                leaf_index: 0,
                root: utxo_root,
                root_seq: 0,
                // The deposit consumed root-history slot 1.
                root_index: 1,
            },
            nullifier: to_non_inclusion(first_nullifier, &non_inclusion),
        }),
        nullifier_proof: None,
    });
    for slot in 1..MERGE_INPUT_COUNT {
        let dummy_nullifier = merge_dummy_nullifier(&nullifier_key, &first_nullifier, slot as u8)
            .expect("dummy nullifier");
        let proof = nf_tree
            .get_non_inclusion_proof(&BigUint::from_bytes_be(&dummy_nullifier))
            .expect("dummy non-inclusion proof");
        spends.push(TransferSpendInput {
            utxo: Utxo {
                owner: PublicKey::zeroed(),
                asset: SOL_MINT,
                amount: 0,
                blinding: test_blinding(slot as u8 + 10),
                ring_program_id: None,
                data: Data::default(),
            },
            nullifier_key: nullifier_key.clone(),
            data_hash: None,
            ring_data_hash: None,
            proof: None,
            nullifier_proof: Some(to_non_inclusion(dummy_nullifier, &proof)),
        });
    }

    // The merged output's blinding is derived, not random: the circuit (and
    // the owner's wallet) reconstruct it from the nullifier secret and the
    // first input's nullifier.
    let mut output = SppProofOutputUtxo::new(
        SOL_MINT,
        0,
        keypair.shielded_address().expect("shielded address"),
    )
    .expect("merge output");
    output.blinding =
        merge_output_blinding(&nullifier_key, &first_nullifier).expect("output blinding");

    let result = MergeProver {
        inputs: spends,
        output,
        expiry_unix_ts: u64::MAX,
        signing_pubkey: owner_public_key,
        nullifier_key,
    }
    .build()
    .expect("build merge witness");

    let prover = ProverClient::local();
    let proof = prover.prove_merge(&result.inputs).expect("prove merge");
    // Local pairing gate against the committed merge verifying key: the proof
    // itself is valid, so an on-chain 7008 can only come from a binding
    // mismatch, not a bad proof.
    {
        let public_inputs = [result.public_input_hash];
        let mut verifier = Groth16Verifier::new(
            &proof.a,
            &proof.b,
            &proof.c,
            &public_inputs,
            &merge_8_1::VERIFYINGKEY,
        )
        .expect("construct merge verifier");
        verifier.verify().expect("merge proof verifies locally");
    }
    let merge_proof = ProofCompressed::try_from(proof)
        .expect("compress merge proof")
        .to_merge_proof()
        .expect("merge rail proof");

    let (utxo_next_before, nullifier_next_before) = tree_progress(&env.rpc, &tree);
    let (_, fee_balance_before) = tree_fees(&env.rpc, &tree).expect("tree fees");
    let ix = MergeTransact {
        input_tree: tree,
        output_tree: tree,
        payer: payer_pk,
        user_record: record,
        data: result.instruction_data(merge_proof),
    }
    .instruction();
    // Proof verification needs more than the 200k default budget.
    let budget = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    env.rpc
        .create_and_send_default_payer_transaction(&[budget, ix], &[])
        .expect("merge with a valid proof");

    // Tree progress: eight nullifiers queued, one merged output appended.
    let (utxo_next_after, nullifier_next_after) = tree_progress(&env.rpc, &tree);
    assert_eq!(utxo_next_after, utxo_next_before + 1, "one output appended");
    assert_eq!(
        nullifier_next_after,
        nullifier_next_before + MERGE_INPUT_COUNT as u64,
        "eight nullifiers queued"
    );

    // Exact forester fee: MERGE_INPUT_COUNT (8) queue insertions at the tree's
    // stored fee_per_nullifier, collected from the payer into the input tree
    // and credited to the tree's fee balance. The tree in turn funds one
    // nullifier PDA per queued nullifier.
    const LAMPORTS_PER_SIGNATURE: u64 = 5_000;
    let (fees, fee_balance_after) = tree_fees(&env.rpc, &tree).expect("tree fees");
    assert_eq!(
        fees,
        default_tree_fees(NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE).expect("default tree fees"),
        "merge leaves the fee schedule untouched"
    );
    let forester_fee = fees.fee_per_nullifier * MERGE_INPUT_COUNT as u64;
    assert_eq!(forester_fee, 1_520, "merge forester fee formula");
    assert_eq!(
        fee_balance_after,
        fee_balance_before + forester_fee,
        "merge credits the fee balance"
    );
    assert_eq!(
        result.nullifiers.len(),
        MERGE_INPUT_COUNT,
        "merge queues one nullifier per input slot"
    );
    let nullifier_pda_rent = nullifier_pda_rent(&env.rpc).expect("nullifier PDA rent");
    let nullifier_pdas = nullifier_pda_addresses(&tree, &result.nullifiers);
    let nullifier_pda_rent_total = nullifier_pda_rent * MERGE_INPUT_COUNT as u64;
    let program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID);
    let trace = env
        .rpc
        .last_transaction_trace()
        .expect("successful merge trace");
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
                "tree collects exactly the merge forester fee and funds eight nullifier PDAs"
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
    assert_nullifier_pdas(&env.rpc, &tree, &result.nullifiers).expect("nullifier PDAs");
}
