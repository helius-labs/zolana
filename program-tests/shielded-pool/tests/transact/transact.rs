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
#[path = "../common/transact_core.rs"]
mod transact_common;

use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signer::Signer;
use zolana_client::TransferOutput;
use zolana_hasher::{sha256::Sha256BE, Hasher};
use zolana_interface::instruction::{
    instruction_data::transact::{OwnerTag, TransactIxData},
    Transact,
};
use zolana_keypair::hash::hash_field;
use zolana_program_test::ZolanaProgramTest;
use zolana_transaction::instructions::transact::{no_address_hashes, private_tx_hash};
use zolana_tree::TreeAccount;

use crate::transact_common::{
    build_transfer_prover_inputs, dummy_input, dummy_transfer_output, eddsa_input_utxo,
    external_data_hash, fe, inline_outputs, new_transact_ix_data, output_owner_pk_hashes,
    prove_and_verify_transfer, public_input_hash, set_output_owner_tags, start_prover,
    TransferProverInputsArgs,
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

    // Two circuit-dummy inputs with distinct non-zero nullifiers (the program
    // inserts both into the nullifier tree; zeros or duplicates are rejected).
    let nullifiers = [fe(1), fe(2)];

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
        None,
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
        external_data_hash(&transact_ix_data, &zero).expect("external data hash");

    // Dummy inputs and outputs contribute zero hashes to private_tx_hash.
    let private_tx = private_tx_hash(
        &[zero, zero],
        &[zero, zero, zero],
        &no_address_hashes(2),
        &external_data_hash,
    )
    .expect("private tx hash");

    // Values the program reconstructs from accounts[0] (the payer).
    let owner_hash = hash_field(&payer_bytes).expect("owner hash");
    let payer_pubkey_hash = Sha256BE::hash(&payer_bytes).expect("payer hash");

    let public_input_hash = public_input_hash(
        &nullifiers,
        &output_hashes,
        &[utxo_root, utxo_root],
        &[nullifier_root, nullifier_root],
        &private_tx,
        &external_data_hash,
        &zero,
        &payer_pubkey_hash,
        &[owner_hash, owner_hash],
        &owner_pk_hashes,
        &zero,
    );

    let prover_inputs = build_transfer_prover_inputs(TransferProverInputsArgs {
        inputs: vec![
            dummy_input(&nullifiers[0], roots, &owner_hash),
            dummy_input(&nullifiers[1], roots, &owner_hash),
        ],
        outputs,
        external_data_hash,
        private_tx_hash: private_tx,
        public_sol_amount: zero,
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

    // Accounts: `[payer (signer), tree (writable)]`. Index 0 is the fee payer
    // and the eddsa signer the inputs reference (`eddsa_signer_index = 0`).
    let ix = Transact {
        payer,
        tree: env.tree.pubkey(),
        withdrawal: None,
        data: transact_ix_data,
    }
    .instruction();

    let result = env
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[]);
    assert!(result.is_ok(), "transact failed: {result:?}");
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

    // Flip a recipient output's owner tag. The proof committed to the original
    // `hash_field(resolved_owner_tag)`, so the program's reconstruction now
    // disagrees.
    let tampered = transact_ix_data.outputs.get_mut(1).expect("second output");
    tampered.owner_tag = OwnerTag::Inline([0xAAu8; 32]);

    let ix = Transact {
        payer,
        tree: env.tree.pubkey(),
        withdrawal: None,
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
}
