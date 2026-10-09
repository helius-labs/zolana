//! A `ZolanaClient` whose RPC and indexer are the litesvm harness proves and
//! sends a private transfer with nothing beside it but the prover server: the
//! client fetches the proof data from the harness, the prover proves it, and
//! the harness runs and indexes the transaction.
//!
//! Requires `cargo build-sbf -p shielded-pool-program` and the workspace prover.

use solana_keypair::Keypair;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_client::{
    sign_transaction, IndexerRequirement, ProofDataSource, ProverClient, Rpc,
    SignedPrivateTransaction, Submission,
};
use zolana_interface::state::read_tree_id;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::ZolanaProgramTest;
use zolana_test_utils::prover::spawn_workspace_prover;
use zolana_transaction::{instructions::transact::ConfidentialTransaction, WalletUtxo};

#[test]
fn a_client_over_the_harness_proves_and_sends_a_transfer() {
    spawn_workspace_prover(IndexerRequirement::Optional);
    let mut harness = ZolanaProgramTest::new().expect("harness");
    let payer = harness.payer.insecure_clone();
    let authority = Keypair::new();
    harness
        .airdrop(&authority.pubkey(), 10_000_000_000)
        .expect("fund the authority");
    harness
        .create_protocol_config(&authority)
        .expect("protocol config");
    let tree = harness.create_tree(&authority).expect("tree");

    // The payer shields SOL to itself and spends it: the one input owner is
    // the fee payer, so one signature covers both.
    let sender = ShieldedKeypair::from_keypair(&payer).expect("sender");
    let shield = ZolanaProgramTest::wallet_sol_shield_data(
        1_000_000,
        &sender.shielded_address().expect("shielded address"),
    )
    .expect("shield data");
    let deposit = harness.deposit(&tree, &payer, &shield).expect("deposit");
    let utxo = harness
        .indexed_deposit_utxo(&deposit, sender.signing_pubkey())
        .expect("the deposited UTXO");
    let tree_id =
        read_tree_id(&harness.account_data(&tree).expect("tree account")).expect("tree id");
    let nullifier_pubkey = sender.nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0u8; 32], &[0u8; 32], tree_id)
        .expect("utxo hash");
    assert_eq!(utxo_hash, deposit.utxo_hash);
    let nullifier = utxo
        .nullifier(&utxo_hash, &sender.nullifier_key)
        .expect("nullifier");
    let input = WalletUtxo {
        utxo,
        nullifier_pubkey,
        utxo_hash,
        nullifier,
        data_hash: None,
        ring_data_hash: None,
        tree_id,
        leaf_index: deposit.leaf_index,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    };

    let client = harness
        .into_client(ProverClient::local())
        .with_proof_data_source(ProofDataSource::Client);
    let signed = SignedPrivateTransaction {
        transaction: ConfidentialTransaction::new(vec![input], payer.pubkey())
            .expect("transaction")
            .encrypt(&sender)
            .expect("encrypt"),
        settlement_transfers: Vec::new(),
    };
    let message = Submission::new(&signed, payer.pubkey(), &sender)
        .finish_unsigned_sync(&client)
        .expect("prove and build");
    let transaction = sign_transaction(message, &[&payer]).expect("sign");
    let signature = client.process_transaction(transaction).expect("send");
    client
        .confirm_private_transaction_sync(signature)
        .expect("confirmed and indexed");
    assert!(client
        .indexer()
        .lock()
        .indexer()
        .is_nullifier_spent(&nullifier));
}
