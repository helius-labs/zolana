//! Litesvm program-test for the `transact` instruction: boot a protocol config
//! and pool tree, build a valid (2,3) Groth16 proof on the Solana-only eddsa
//! rail, assemble the `transact` instruction data, and send it to the program.
//!
//! The first input spends a proofless-deposit UTXO owned by the payer and the
//! second is circuit padding. The first output preserves the deposited value
//! while the other two are padding. This gives the dummy owner-tag gate a real
//! transaction signer and binds the proof to exactly what the program
//! reconstructs on-chain: the `external_data` hash, payer pubkey hash,
//! per-input owner hashes, tree roots, and nullifier/output hash chains.
//!
//! Requires `cargo build-sbf -p shielded-pool-program` to have produced the
//! `.so` binary; the test skips (does not fail) when it is missing.

#[path = "../common/setup.rs"]
mod common;
#[path = "../common/transact.rs"]
mod transact_common;

use num_bigint::BigUint;
use solana_keypair::Keypair;
use solana_message::Message;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use solana_transaction::Transaction;
use zolana_client::{TransferOutput, STATE_TREE_HEIGHT};
use zolana_hasher::primitives::hash_bytes;
use zolana_hasher::{sha256::Sha256BE, Hasher, Poseidon};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{CircuitId, OwnerTag, TransactIxData},
        Transact,
    },
    N_PUBLIC_SLOTS,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey};
use zolana_merkle_tree::MerkleTree;
use zolana_program_test::{test_blinding, ZolanaProgramTest};
use zolana_transaction::{instructions::transact::PrivateTxHash, Data, Utxo, SOL_MINT};
use zolana_tree::TreeAccount;

use crate::transact_common::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo,
    external_data_hash, inline_outputs, new_transact_ix_data, nullifier_tree,
    output_owner_pk_hashes, prove_and_verify_transfer, public_input_hash, real_output,
    set_output_owner_tags, sol_public_slots, spend_input, start_prover, transfer_output,
    SpendInputArgs, TransferProverInputsArgs,
};

const TRANSFER_AMOUNT: u64 = 1_000_000;

/// The (utxo, nullifier) tree roots at the requested history indices, exactly
/// as the program reads them during `apply_tree`.
fn tree_roots(rpc: &ZolanaProgramTest, tree: &Pubkey, utxo_index: u16) -> ([u8; 32], [u8; 32]) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.get_utxo_tree_root(utxo_index).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
}

fn tree_lamports(rpc: &ZolanaProgramTest, tree: &Pubkey) -> u64 {
    rpc.svm.get_account(tree).expect("tree account").lamports
}

fn tree_indices(rpc: &ZolanaProgramTest, tree: &Pubkey) -> (u64, u64) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let mut account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    let output_index = account.utxo_tree().next_index();
    let nullifier_index = account.nullifer_tree().queue_batches.next_index;
    (output_index, nullifier_index)
}

/// Boot a program-test environment with a protocol config and one pool tree,
/// the shared precondition for every `transact` scenario.
struct TransactEnv {
    rpc: ZolanaProgramTest,
    authority: Keypair,
    tree: Keypair,
}

impl TransactEnv {
    /// Returns `None` when the program `.so` is missing so callers can skip.
    fn boot() -> Option<Self> {
        let mut rpc = common::program_test()?;
        start_prover().expect("start prover");
        let authority = Keypair::new();
        rpc.create_protocol_config(&authority)
            .expect("create protocol config");
        let tree = rpc
            .create_tree(common::tree_account_size(), &authority)
            .expect("create tree");
        Some(Self {
            rpc,
            authority,
            tree,
        })
    }

    /// Move only the nullifier queue cursor so it has one fewer free leaf than
    /// the state tree. Roots remain unchanged, allowing a proof generated with
    /// the normal client-side `allow_dummy_inputs = true` assumption to reach
    /// the program's public-input verification.
    fn force_dummy_inputs_disabled(&mut self) {
        let tree_pubkey = self.tree.pubkey();
        let mut account = self
            .rpc
            .svm
            .get_account(&tree_pubkey)
            .expect("tree account");
        {
            let mut tree = TreeAccount::from_bytes(&mut account.data, tree_pubkey.to_bytes())
                .expect("load mutable tree");
            let state_remaining = {
                let utxo = tree.utxo_tree();
                utxo.capacity() - utxo.next_index()
            };
            {
                let mut nullifier = tree.nullifer_tree();
                let next_leaf = nullifier
                    .capacity
                    .checked_sub(state_remaining)
                    .expect("nullifier capacity exceeds state capacity")
                    + 1;
                nullifier
                    .queue_batches
                    .get_current_batch_mut()
                    .expect("current nullifier batch")
                    .start_index = next_leaf;
            }
            assert!(
                !tree
                    .allow_dummy_inputs()
                    .expect("derive dummy-input policy"),
                "fixture must cross the dummy-input threshold"
            );
        }
        self.rpc
            .svm
            .set_account(tree_pubkey, account)
            .expect("write threshold tree account");
    }
}

/// Build a valid (2,3) eddsa-rail `transact` instruction data with a real proof:
/// one real input/output plus padded slots, bound to the on-chain roots and
/// payer. Shared by the positive and negative scenarios.
fn build_valid_transact_ix(env: &mut TransactEnv) -> TransactIxData {
    let payer = env.rpc.payer.insecure_clone();
    let payer_bytes = payer.pubkey().to_bytes();
    let zero = [0u8; 32];

    // Shield one real UTXO so the transaction has a signer participant. The
    // circuit's dummy-tag hardening deliberately rejects an all-padding proof.
    let blinding = test_blinding(7);
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pubkey");
    let owner = PublicKey::from_ed25519(&payer_bytes);
    let utxo = Utxo {
        owner,
        asset: SOL_MINT,
        amount: TRANSFER_AMOUNT,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let owner_hash = owner_hash(&owner, &nullifier_pk).expect("owner field");
    let event = env
        .rpc
        .deposit_sol(
            &env.tree.pubkey(),
            &payer,
            TRANSFER_AMOUNT,
            owner_hash,
            blinding,
        )
        .expect("proofless deposit");
    let utxo_hash = utxo.hash(&nullifier_pk, &zero, &zero).expect("utxo hash");
    assert_eq!(event.utxo_hash, utxo_hash, "deposited UTXO hash");

    // The deposit appended leaf 0 and stored its state root at history index 1.
    let roots = tree_roots(&env.rpc, &env.tree.pubkey(), 1);
    let (utxo_root, nullifier_root) = roots;
    let mut state_tree = MerkleTree::<Poseidon>::new(STATE_TREE_HEIGHT, 0);
    state_tree.append(&utxo_hash).expect("append state leaf");
    assert_eq!(state_tree.root(), utxo_root, "state root gate");
    let state_path: Vec<[u8; 32]> = state_tree
        .get_proof_of_leaf(0, true)
        .expect("state proof")
        .to_vec();

    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    assert_eq!(nf_tree.root(), nullifier_root, "nullifier root gate");
    let nullifier = nullifier_key
        .nullifier(&utxo_hash, &blinding)
        .expect("nullifier");
    let non_inclusion = nf_tree
        .get_non_inclusion_proof(&BigUint::from_bytes_be(&nullifier))
        .expect("non-inclusion proof");
    let owner_pk_hash = hash_bytes(&payer_bytes).expect("owner pk hash");
    let real_input = spend_input(SpendInputArgs {
        utxo: &utxo,
        owner_field: &owner_hash,
        state_path: &state_path,
        state_path_index: 0,
        non_inclusion: &non_inclusion,
        roots,
        nullifier: &nullifier,
        owner_pk_hash: &owner_pk_hash,
        nullifier_key: &nullifier_key,
    })
    .expect("real input");
    let (dummy_input, dummy_nullifier) =
        dummy_input(&[31u8; 31], &nf_tree, roots, &owner_pk_hash).expect("dummy input");
    let nullifiers = [nullifier, dummy_nullifier];

    // Preserve the real input's value in output 0; outputs 1 and 2 are padding.
    let output_nullifier_pk = NullifierKey::from_secret([10u8; 31])
        .pubkey()
        .expect("output nullifier pubkey");
    let real_output = real_output(
        owner,
        output_nullifier_pk,
        SOL_MINT,
        TRANSFER_AMOUNT,
        [4u8; 31],
    );
    let real_output_hash = real_output.hash().expect("real output hash");
    let dummy_outputs: Vec<(TransferOutput, [u8; 32])> = [[1u8; 31], [2u8; 31]]
        .iter()
        .map(|blinding| dummy_transfer_output(blinding).expect("dummy output"))
        .collect();
    let output_hashes = [real_output_hash, dummy_outputs[0].1, dummy_outputs[1].1];
    let mut outputs = vec![
        transfer_output(&real_output).expect("real transfer output"),
        dummy_outputs[0].0.clone(),
        dummy_outputs[1].0.clone(),
    ];

    // Instruction data; `proof` and `private_tx_hash` are filled in once the
    // external-data hash (which excludes both) is known. Each output carries its
    // own `Inline` owner tag.
    let view_tags = [payer_bytes; 3];
    let mut transact_ix_data = new_transact_ix_data(
        vec![
            eddsa_input_utxo(nullifier, 1),
            eddsa_input_utxo(dummy_nullifier, 1),
        ],
        Vec::new(),
        inline_outputs(&output_hashes, &view_tags),
    );

    // Output 0 binds to the payer and the dummy outputs reuse the payer's
    // participant tag.
    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.outputs).expect("output owner pk hashes");
    set_output_owner_tags(
        &mut outputs,
        &owner_pk_hashes,
        &[output_nullifier_pk, zero, zero],
    );

    // external_data_hash via the shared interface struct: the program computes
    // the identical value on-chain. No settlement, so the account fields are 0.
    let external_data_hash =
        external_data_hash(&transact_ix_data, &[]).expect("external data hash");

    let private_tx = PrivateTxHash::new(
        &[utxo_hash, zero],
        &[real_output_hash, zero, zero],
        &external_data_hash,
    )
    .hash()
    .expect("private tx hash");

    // Values the program reconstructs from accounts[0] (the payer).
    let payer_pubkey_hash = Sha256BE::hash(&payer_bytes).expect("payer hash");

    let (public_slot_assets, public_slot_amounts) = sol_public_slots(zero);
    let public_input_hash = public_input_hash(
        &nullifiers,
        &output_hashes,
        &[utxo_root, utxo_root],
        &[nullifier_root, nullifier_root],
        &private_tx,
        &external_data_hash,
        &public_slot_assets,
        &public_slot_amounts,
        &payer_pubkey_hash,
        &[owner_pk_hash, owner_pk_hash],
        &owner_pk_hashes,
    );

    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![real_input, dummy_input],
        outputs,
        external_data_hash,
        private_tx_hash: private_tx,
        public_slot_assets,
        public_slot_amounts,
        payer_pubkey_hash,
        public_input_hash,
    });
    transact_ix_data.proof =
        prove_and_verify_transfer(&prover_inputs, public_input_hash, "transact")
            .expect("prove transact");
    transact_ix_data.private_tx_hash = private_tx;
    transact_ix_data
}

#[test]
fn transact_sends_valid_proof() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };

    let payer = env.rpc.payer.pubkey();
    let transact_ix_data = build_valid_transact_ix(&mut env);
    let tree_balance_before = tree_lamports(&env.rpc, &env.tree.pubkey());

    // Index 0 is the fee payer and the eddsa signer the inputs reference
    // (`eddsa_signer_index = 0`); the builder also supplies the System Program
    // for the single forester-fee CPI.
    let ix = Transact {
        payer,
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();

    let result = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[]);
    assert!(result.is_ok(), "transact failed: {result:?}");
    let tree_balance_after = tree_lamports(&env.rpc, &env.tree.pubkey());
    assert_eq!(
        tree_balance_after - tree_balance_before,
        40,
        "two inserted nullifiers must fund two 20-lamport forester shares"
    );
}

#[test]
fn transact_spends_from_input_tree_and_appends_to_output_tree() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };

    let output_tree = env
        .rpc
        .create_tree(common::tree_account_size(), &env.authority)
        .expect("create output tree");
    let payer = env.rpc.payer.pubkey();
    let transact_ix_data = build_valid_transact_ix(&mut env);
    let input_before = tree_indices(&env.rpc, &env.tree.pubkey());
    let output_before = tree_indices(&env.rpc, &output_tree.pubkey());
    let input_balance_before = tree_lamports(&env.rpc, &env.tree.pubkey());
    let output_balance_before = tree_lamports(&env.rpc, &output_tree.pubkey());

    let ix = Transact {
        payer,
        input_tree: env.tree.pubkey(),
        output_tree: output_tree.pubkey(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();
    // The test indexer intentionally models one output tree. This scenario
    // exercises two on-chain trees, so submit directly and assert their state.
    let payer_signer = env.rpc.payer.insecure_clone();
    let message = Message::new(&[ix], Some(&payer));
    let transaction = Transaction::new(&[&payer_signer], message, env.rpc.svm.latest_blockhash());
    env.rpc
        .svm
        .send_transaction(transaction)
        .expect("cross-tree transact");

    let input_after = tree_indices(&env.rpc, &env.tree.pubkey());
    let output_after = tree_indices(&env.rpc, &output_tree.pubkey());
    assert_eq!(
        input_after.0, input_before.0,
        "input UTXO tree is unchanged"
    );
    assert_eq!(
        input_after.1,
        input_before.1 + 2,
        "input nullifier queue receives both inputs"
    );
    assert_eq!(
        output_after.0,
        output_before.0 + 3,
        "output UTXO tree receives all outputs"
    );
    assert_eq!(
        output_after.1, output_before.1,
        "output nullifier queue is unchanged"
    );
    assert_eq!(
        tree_lamports(&env.rpc, &env.tree.pubkey()) - input_balance_before,
        40,
        "forester fees accrue to the input tree"
    );
    assert_eq!(
        tree_lamports(&env.rpc, &output_tree.pubkey()),
        output_balance_before,
        "output tree receives no nullifier forester fee"
    );
}

#[test]
fn transact_rejects_dummy_inputs_after_capacity_threshold() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };

    let payer = env.rpc.payer.pubkey();
    let transact_ix_data = build_valid_transact_ix(&mut env);
    env.force_dummy_inputs_disabled();
    let ix = Transact {
        payer,
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();

    let err = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[])
        .expect_err("dummy inputs must be rejected after the capacity threshold");
    let needle = format!(
        "Custom({})",
        ShieldedPoolError::TransactProofVerificationFailed as u32
    );
    assert!(
        format!("{err}").contains(&needle),
        "expected {needle}, got: {err}"
    );
}

/// The declared circuit selector is checked before proof verification: a
/// selector whose type belongs to another instruction or whose shape is not
/// supported is rejected even with an otherwise valid proof.
#[test]
fn transact_rejects_mismatched_circuit_selector() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };

    let payer = env.rpc.payer.pubkey();
    let valid = build_valid_transact_ix(&mut env);

    for (circuit, error) in [
        // A zone selector on the default-zone `transact` instruction.
        (
            CircuitId::ZoneEddsa(2, 3, N_PUBLIC_SLOTS as u8),
            ShieldedPoolError::MismatchedCircuitType,
        ),
        // A confidential selector for which no key exists.
        (
            CircuitId::ConfidentialEddsa(6, 6, N_PUBLIC_SLOTS as u8),
            ShieldedPoolError::InvalidTransactShape,
        ),
    ] {
        let mut data = valid.clone();
        data.circuit = circuit;
        let ix = Transact {
            payer,
            input_tree: env.tree.pubkey(),
            output_tree: env.tree.pubkey(),
            interface_transfer_accounts: Vec::new(),
            data,
        }
        .instruction();
        let err = env
            .rpc
            .create_and_send_default_payer_transaction(&[ix], &[])
            .expect_err("mismatched circuit selector must be rejected");
        let needle = format!("Custom({})", error as u32);
        let msg = format!("{err}");
        assert!(msg.contains(&needle), "expected {needle}, got: {msg}");
    }
}

/// A tampered output owner tag (changed after proving, so
/// `hash_bytes(resolved_owner_tag)` no longer matches the proof's committed
/// output-owner chain) must be rejected: the program reconstructs the owner tags
/// from the instruction's outputs and the resulting public input no longer
/// matches the proof.
#[test]
fn transact_rejects_tampered_output_view_tag() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };

    let payer = env.rpc.payer.pubkey();
    let mut transact_ix_data = build_valid_transact_ix(&mut env);
    let tree_balance_before = tree_lamports(&env.rpc, &env.tree.pubkey());

    // Flip a recipient output's owner tag. The proof committed to the original
    // `hash_bytes(resolved_owner_tag)`, so the program's reconstruction now
    // disagrees.
    let tampered = transact_ix_data.outputs.get_mut(1).expect("second output");
    tampered.owner_tag = OwnerTag::Inline([0xAAu8; 32]);

    let ix = Transact {
        payer,
        input_tree: env.tree.pubkey(),
        output_tree: env.tree.pubkey(),
        interface_transfer_accounts: Vec::new(),
        data: transact_ix_data,
    }
    .instruction();

    let result = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[]);
    assert!(
        result.is_err(),
        "tampered output view_tag must be rejected, got: {result:?}"
    );
    let tree_balance_after = tree_lamports(&env.rpc, &env.tree.pubkey());
    assert_eq!(
        tree_balance_after, tree_balance_before,
        "a rejected transact must not collect a forester fee"
    );
}
