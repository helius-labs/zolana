//! The harness as a `SprClient`'s RPC and indexer: the proofs it serves are
//! bound to the roots the chain holds, a transaction it sent is confirmed and
//! indexed, and it fails and dates a blockhash as a validator's RPC does.

use solana_keypair::Keypair;
use solana_signer::Signer;
use spr_client::{compile_message, sign_transaction, ComputeBudgetConfig, Rpc};
use spr_interface::{error::ShieldedPoolError, instruction::UpdateProtocolConfigData};
use spr_keypair::{hash::owner_hash, ShieldedKeypair};
use spr_program_test::{Rejection, SprProgramTest};
use spr_protocol_instructions::UpdateProtocolConfig;
use spr_tree::TreeAccount;

#[test]
#[ignore = "needs the SBF build in target/deploy; run by `just test-program-fast`"]
fn the_handle_serves_the_proofs_the_chain_verifies() {
    let mut harness = SprProgramTest::new().expect("harness");
    let payer = harness.payer.insecure_clone();
    let authority = Keypair::new();
    harness
        .airdrop(&authority.pubkey(), 10_000_000_000)
        .expect("fund the authority");
    harness
        .create_protocol_config(&authority)
        .expect("protocol config");
    let tree = harness.create_tree(&authority).expect("tree");
    let owner = ShieldedKeypair::from_keypair(&Keypair::new()).expect("owner");
    let deposit = harness
        .deposit_sol(
            &tree,
            &payer,
            1_000_000,
            owner_hash(
                &owner.signing_pubkey(),
                &owner.nullifier_key.pubkey().expect("nullifier pubkey"),
            )
            .expect("owner hash"),
        )
        .expect("deposit");
    let signature = harness
        .last_transaction_trace()
        .expect("the deposit's trace")
        .signature;

    let handle = harness.into_handle();
    let proofs = handle
        .get_merkle_proofs(tree, vec![deposit.utxo_hash], None)
        .expect("merkle proofs");
    let nullifier_proofs = handle
        .get_non_inclusion_proofs(tree, vec![[7u8; 32]], None)
        .expect("non-inclusion proofs");
    let mut data = handle.lock().account_data(&tree).expect("tree account");
    let account = TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree");

    let [proof] = proofs.proofs.as_slice() else {
        panic!("one proof per leaf");
    };
    assert_eq!(proof.leaf_index, deposit.leaf_index);
    assert_eq!(
        proof.root,
        account
            .get_utxo_tree_root(proof.root_index)
            .expect("utxo root")
    );
    let [nullifier_proof] = nullifier_proofs.proofs.as_slice() else {
        panic!("one proof per nullifier");
    };
    assert_eq!(
        nullifier_proof.root,
        account
            .get_nullifier_tree_root(nullifier_proof.root_index)
            .expect("nullifier root")
    );
    assert!(handle.confirm_transaction(signature).expect("confirm"));
    assert_eq!(
        handle
            .get_shielded_transactions_by_signature(signature, None)
            .expect("indexed transaction")
            .transactions
            .len(),
        1
    );
    assert!(handle
        .get_merkle_proofs(tree, vec![[9u8; 32]], None)
        .is_err());
}

/// A rejection reaches the client as `SolanaRpc` reports one, so a
/// `Rejection` matches it; the blockhash comes with the block height at which
/// a validator stops accepting it.
#[test]
#[ignore = "needs the SBF build in target/deploy; run by `just test-program-fast`"]
fn the_handle_reports_rejections_and_blockhash_heights_as_the_rpc_does() {
    let mut harness = SprProgramTest::new().expect("harness");
    let payer = harness.payer.insecure_clone();
    let authority = Keypair::new();
    harness
        .create_protocol_config(&authority)
        .expect("protocol config");
    harness.svm.warp_to_slot(40);
    let last_valid = 40 + solana_clock::MAX_PROCESSING_AGE as u64;
    assert_eq!(Rpc::get_block_height(&harness).expect("block height"), 40);
    let (_, harness_last_valid) = Rpc::get_latest_blockhash(&harness).expect("latest blockhash");
    assert_eq!(harness_last_valid, last_valid);
    let handle = harness.into_handle();

    let (blockhash, last_valid_block_height) =
        handle.get_latest_blockhash().expect("latest blockhash");
    assert_eq!(handle.get_block_height().expect("block height"), 40);
    assert_eq!(last_valid_block_height, last_valid);

    // UpdateProtocolConfigData has no variant 8.
    let mut unknown_variant = UpdateProtocolConfig {
        authority: authority.pubkey(),
        update: UpdateProtocolConfigData::TreeCreationPermissionless(true),
    }
    .instruction();
    unknown_variant.data.truncate(1);
    unknown_variant.data.push(8);
    let message = compile_message(
        &payer.pubkey(),
        &[unknown_variant],
        blockhash,
        ComputeBudgetConfig::for_instruction_count(1),
    )
    .expect("message");
    let transaction = sign_transaction(message, &[&payer, &authority]).expect("signed");
    let error = handle
        .process_transaction(transaction)
        .expect_err("an unknown update variant is rejected");
    Rejection::pool(ShieldedPoolError::InvalidInstructionData).assert_client(&error);
}
