//! Litesvm program-test for the `transact` instruction: boot a protocol config
//! and pool tree, build a valid (2,3) Groth16 proof on the Solana-only eddsa
//! rail, assemble the `transact` instruction data, and send it to the program.
//!
//! The two inputs are circuit dummies (`is_dummy = 1`), so they need no real
//! UTXOs or merkle proofs, but they carry distinct non-zero nullifiers plus the
//! real on-chain tree roots and the payer's owner hash. The proof is therefore
//! bound to exactly what the program reconstructs on-chain: the `external_data`
//! hash (via the shared [`ExternalDataHash`] from the interface crate), the
//! payer pubkey hash, the per-input owner hashes, the tree roots, and the
//! nullifier/output hash chains.
//!
//! Requires `cargo build-sbf -p shielded-pool-program` to have produced the
//! `.so` binary; the test skips (does not fail) when it is missing.

#[path = "../common/setup.rs"]
mod common;
#[path = "../common/transact.rs"]
mod transact_common;

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::TransferOutput;
use zolana_hasher::{sha256::Sha256BE, Hasher};
use zolana_interface::{
    error::ShieldedPoolError,
    instruction::{
        instruction_data::transact::{CircuitId, OwnerTag, TransactIxData},
        Transact,
    },
    N_PUBLIC_SLOTS,
};
use zolana_keypair::hash::hash_field;
use zolana_program_test::ZolanaProgramTest;
use zolana_transaction::instructions::transact::PrivateTxHash;
use zolana_tree::TreeAccount;

use crate::transact_common::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo,
    external_data_hash, inline_outputs, new_transact_ix_data, nullifier_tree,
    output_owner_pk_hashes, prove_and_verify_transfer, public_input_hash, set_output_owner_tags,
    sol_public_slots, start_prover, TransferProverInputsArgs,
};

/// The (utxo, nullifier) tree roots at history index 0, exactly as the program
/// reads them during `apply_tree`.
fn tree_roots(rpc: &ZolanaProgramTest, tree: &Pubkey) -> ([u8; 32], [u8; 32]) {
    let mut data = rpc.account_data(tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");
    (
        account.get_utxo_tree_root(0).expect("utxo root"),
        account.get_nullifier_tree_root(0).expect("nullifier root"),
    )
}

fn tree_lamports(rpc: &ZolanaProgramTest, tree: &Pubkey) -> u64 {
    rpc.svm.get_account(tree).expect("tree account").lamports
}

/// Boot a program-test environment with a protocol config and one pool tree,
/// the shared precondition for every `transact` scenario.
struct TransactEnv {
    rpc: ZolanaProgramTest,
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
        Some(Self { rpc, tree })
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
/// two circuit-dummy inputs and three dummy outputs, bound to the on-chain roots
/// and the payer. Shared by the positive and negative scenarios.
fn build_valid_transact_ix(env: &TransactEnv) -> TransactIxData {
    let payer = env.rpc.payer.pubkey();
    let payer_bytes = payer.to_bytes();
    let roots = tree_roots(&env.rpc, &env.tree.pubkey());
    let (utxo_root, nullifier_root) = roots;
    let zero = [0u8; 32];

    // Two circuit-dummy inputs over distinct blindings. Each derives its
    // nullifier over the dummified utxo hash and carries a real non-inclusion
    // witness (the program inserts both nullifiers into the nullifier tree;
    // zeros or duplicates are rejected).
    let nf_tree = nullifier_tree().expect("indexed nullifier tree");
    let owner_hash = hash_field(&payer_bytes).expect("owner hash");
    let (dummy_input_0, nullifier_0) =
        dummy_input(&[31u8; 31], &nf_tree, roots, &owner_hash).expect("dummy input 0");
    let (dummy_input_1, nullifier_1) =
        dummy_input(&[32u8; 31], &nf_tree, roots, &owner_hash).expect("dummy input 1");
    let nullifiers = [nullifier_0, nullifier_1];

    // Three dummy outputs with distinct blindings. Each has a real `utxo_hash` that
    // the program appends to the tree and the proof commits via the public output
    // chain; all three contribute `0` to `private_tx_hash`.
    let dummy_outputs: Vec<(TransferOutput, [u8; 32])> = [[1u8; 31], [2u8; 31], [3u8; 31]]
        .iter()
        .map(|blinding| dummy_transfer_output(blinding).expect("dummy output"))
        .collect();
    let output_hashes: Vec<[u8; 32]> = dummy_outputs.iter().map(|(_, hash)| *hash).collect();
    let mut outputs: Vec<TransferOutput> = dummy_outputs.into_iter().map(|(out, _)| out).collect();

    // Instruction data; `proof` and `private_tx_hash` are filled in once the
    // external-data hash (which excludes both) is known. The eddsa rail carries no
    // P256 owner, so `p256_signing_pk_x` is `None`. Each output carries its own
    // `Inline` owner tag.
    let view_tags = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let mut transact_ix_data = new_transact_ix_data(
        nullifiers
            .iter()
            .map(|nullifier| eddsa_input_utxo(*nullifier, 0))
            .collect(),
        Vec::new(),
        inline_outputs(&output_hashes, &view_tags),
        None,
    );

    // Confidential owner tags: the program reconstructs each output's owner
    // `pk_field` as `hash_field(resolved_owner_tag)` per position. All three
    // outputs are dummies, so their owner is unconstrained (nullifier_pk 0).
    let owner_pk_hashes =
        output_owner_pk_hashes(&transact_ix_data.outputs, None).expect("output owner pk hashes");
    set_output_owner_tags(&mut outputs, &owner_pk_hashes, &[zero, zero, zero]);

    // external_data_hash via the shared interface struct: the program computes
    // the identical value on-chain. No settlement, so the account fields are 0.
    let external_data_hash =
        external_data_hash(&transact_ix_data, &[]).expect("external data hash");

    // Dummy inputs and outputs contribute zero hashes to private_tx_hash.
    let private_tx = PrivateTxHash::new(&[zero, zero], &[zero, zero, zero], &external_data_hash)
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
        &[owner_hash, owner_hash],
        &owner_pk_hashes,
        &zero,
    );

    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![dummy_input_0, dummy_input_1],
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
    let transact_ix_data = build_valid_transact_ix(&env);
    let tree_balance_before = tree_lamports(&env.rpc, &env.tree.pubkey());

    // Index 0 is the fee payer and the eddsa signer the inputs reference
    // (`eddsa_signer_index = 0`); the builder also supplies the System Program
    // for the single forester-fee CPI.
    let ix = Transact {
        payer,
        tree: env.tree.pubkey(),
        legs: Vec::new(),
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
fn transact_rejects_dummy_inputs_after_capacity_threshold() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };

    env.force_dummy_inputs_disabled();
    let payer = env.rpc.payer.pubkey();
    let transact_ix_data = build_valid_transact_ix(&env);
    let ix = Transact {
        payer,
        tree: env.tree.pubkey(),
        legs: Vec::new(),
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
    let valid = build_valid_transact_ix(&env);

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
            tree: env.tree.pubkey(),
            legs: Vec::new(),
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
/// `hash_field(resolved_owner_tag)` no longer matches the proof's committed
/// output-owner chain) must be rejected: the program reconstructs the owner tags
/// from the instruction's outputs and the resulting public input no longer
/// matches the proof.
#[test]
fn transact_rejects_tampered_output_view_tag() {
    let Some(mut env) = TransactEnv::boot() else {
        return;
    };

    let payer = env.rpc.payer.pubkey();
    let mut transact_ix_data = build_valid_transact_ix(&env);
    let tree_balance_before = tree_lamports(&env.rpc, &env.tree.pubkey());

    // Flip a recipient output's owner tag. The proof committed to the original
    // `hash_field(resolved_owner_tag)`, so the program's reconstruction now
    // disagrees.
    let tampered = transact_ix_data.outputs.get_mut(1).expect("second output");
    tampered.owner_tag = OwnerTag::Inline([0xAAu8; 32]);

    let ix = Transact {
        payer,
        tree: env.tree.pubkey(),
        legs: Vec::new(),
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
