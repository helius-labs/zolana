//! A `ZolanaClient` whose RPC and indexer are the litesvm harness proves and
//! sends a private transfer, and a merge, with nothing beside it but the
//! prover server: the client fetches the proof data from the harness, the
//! prover proves it, and the harness runs and indexes the transaction.
//!
//! Requires `cargo build-sbf -p shielded-pool-program` and the workspace prover.

use borsh::BorshSerialize;
use solana_account::Account;
use solana_keypair::Keypair;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use spr_client::{
    IndexerRequirement, MergeSubmission, ProofDataSource, ProverClient, Rpc,
    SignedPrivateTransaction, Submission,
};
use spr_interface::{instruction::instruction_data::transact::OwnerTag, state::read_tree_id};
use spr_keypair::ShieldedKeypair;
use spr_program_test::ZolanaProgramTest;
use spr_test_utils::prover::spawn_workspace_prover;
use spr_transaction::{
    instructions::{
        merge::MergeTransaction,
        transact::{ConfidentialTransaction, Shape},
    },
    WalletUtxo,
};
use spr_user_registry_interface::{user_record_pda, UserRecord, USER_REGISTRY_PROGRAM_ID};

/// A harness with a tree, and the tree's address and id.
fn harness_with_tree() -> (ZolanaProgramTest, Pubkey, u16) {
    let mut harness = ZolanaProgramTest::new().expect("harness");
    let authority = Keypair::new();
    harness
        .airdrop(&authority.pubkey(), 10_000_000_000)
        .expect("fund the authority");
    harness
        .create_protocol_config(&authority)
        .expect("protocol config");
    let tree = harness.create_tree(&authority).expect("tree");
    let tree_id =
        read_tree_id(&harness.account_data(&tree).expect("tree account")).expect("tree id");
    (harness, tree, tree_id)
}

/// The payer shields `amount` lamports to `owner`; the UTXO as the wallet
/// holds it.
fn shield(
    harness: &mut ZolanaProgramTest,
    tree: &Pubkey,
    tree_id: u16,
    owner: &ShieldedKeypair,
    amount: u64,
) -> WalletUtxo {
    let payer = harness.payer.insecure_clone();
    let shield = ZolanaProgramTest::wallet_sol_shield_data(
        amount,
        &owner.shielded_address().expect("shielded address"),
    )
    .expect("shield data");
    let deposit = harness.deposit(tree, &payer, &shield).expect("deposit");
    let utxo = harness
        .indexed_deposit_utxo(&deposit, owner.signing_pubkey())
        .expect("the deposited UTXO");
    let nullifier_pubkey = owner.nullifier_key.pubkey().expect("nullifier pubkey");
    let utxo_hash = utxo
        .hash(&nullifier_pubkey, &[0u8; 32], &[0u8; 32], tree_id)
        .expect("utxo hash");
    assert_eq!(utxo_hash, deposit.utxo_hash);
    let nullifier = utxo
        .nullifier(&utxo_hash, &owner.nullifier_key)
        .expect("nullifier");
    WalletUtxo {
        utxo,
        nullifier_pubkey,
        utxo_hash,
        nullifier,
        tx_viewing_key: None,
        data_hash: None,
        ring_data_hash: None,
        tree_id,
        leaf_index: deposit.leaf_index,
        latest_tree_id: None,
        slot: 0,
        tx_signature: Signature::default(),
        slot_index: 0,
    }
}

#[test]
fn a_client_over_the_harness_sends_a_transfer_with_account_tagged_padding() {
    spawn_workspace_prover(IndexerRequirement::Optional);
    let (mut harness, tree, tree_id) = harness_with_tree();
    let payer = harness.payer.insecure_clone();
    // The payer shields SOL to itself and spends it: the one input owner is
    // the fee payer, so one signature covers both.
    let sender = ShieldedKeypair::from_keypair(&payer).expect("sender");
    let input = shield(&mut harness, &tree, tree_id, &sender, 1_000_000);
    let nullifier = input.nullifier;
    let recipient = ShieldedKeypair::new_ed25519().expect("recipient");
    let sender_address = sender.shielded_address().expect("sender address");
    let mut transaction =
        ConfidentialTransaction::new(vec![input], payer.pubkey()).expect("transaction");
    transaction
        .transfer_sol(
            &recipient.shielded_address().expect("recipient address"),
            400_000,
        )
        .expect("transfer");
    transaction
        .pad_utxos(Shape::IN1_OUT4, &sender_address)
        .expect("pad transaction");
    let transaction = transaction.encrypt(&sender).expect("encrypt");
    assert_eq!(transaction.output_utxos.len(), 4);
    assert_eq!(transaction.external_data.outputs.len(), 4);
    assert_eq!(
        transaction
            .output_utxos
            .iter()
            .filter(|output| output.is_dummy())
            .count(),
        2
    );
    let expected_tags = vec![
        OwnerTag::Inline(
            recipient
                .signing_pubkey()
                .confidential_view_tag()
                .expect("recipient tag"),
        ),
        OwnerTag::Account(0), // Change.
        OwnerTag::Account(0), // Padding.
        OwnerTag::Account(0), // Padding.
    ];
    assert_eq!(
        transaction
            .external_data
            .outputs
            .iter()
            .map(|output| output.owner_tag)
            .collect::<Vec<_>>(),
        expected_tags
    );

    let client = harness
        .into_client(ProverClient::local())
        .with_proof_data_source(ProofDataSource::Client);
    let signed = SignedPrivateTransaction {
        transaction,
        settlement_transfers: Vec::new(),
    };
    let signature = Submission::new(&signed, payer.pubkey(), &sender)
        .send_sync(&client, &[&payer])
        .expect("proved, sent, confirmed and indexed");
    assert!(client.confirm_transaction(signature).expect("confirmed"));
    assert!(client
        .indexer()
        .lock()
        .indexer()
        .is_nullifier_spent(&nullifier));
}

/// The high-level builder selects the EdDSA shape before encryption; Submission
/// proves that rail and sends a message signed only by the relayer.
#[test]
fn a_client_submission_proves_the_owner_authorization_for_a_relayer() {
    spawn_workspace_prover(IndexerRequirement::Optional);
    let (mut harness, tree, tree_id) = harness_with_tree();
    let payer = harness.payer.insecure_clone();
    let sender = ShieldedKeypair::new_ed25519().expect("sender");
    let input = shield(&mut harness, &tree, tree_id, &sender, 1_000_000);
    let nullifier = input.nullifier;
    let recipient = ShieldedKeypair::new_ed25519().expect("recipient");
    let mut transaction = ConfidentialTransaction::new(vec![input], payer.pubkey())
        .expect("transaction")
        .with_transaction_signers(&[payer.pubkey()]);
    transaction
        .transfer_sol(
            &recipient.shielded_address().expect("recipient address"),
            400_000,
        )
        .expect("transfer");
    let transaction = transaction
        .encrypt(&sender)
        .expect("encrypt on EdDSA shape");
    assert_eq!(
        (
            transaction.input_utxos.len(),
            transaction.output_utxos.len()
        ),
        (2, 8)
    );
    let signed = SignedPrivateTransaction {
        transaction,
        settlement_transfers: Vec::new(),
    };
    let client = harness
        .into_client(ProverClient::local())
        .with_proof_data_source(ProofDataSource::Client);
    // A missing EdDSA capability keeps the default rail's owner signature
    // requirement. Having only the payer must never authorize the sender.
    let default = Submission::new(&signed, payer.pubkey(), &sender)
        .finish_unsigned_sync(&client)
        .expect("prove signer transfer");
    assert!(spr_client::sign_transaction(default.message, &[&payer]).is_err());
    let submission = Submission::new(&signed, payer.pubkey(), &sender)
        .with_confidential_eddsa_owner(&sender.signing_key);
    let unsigned = submission
        .finish_unsigned_sync(&client)
        .expect("prove relayed transfer");
    assert_eq!(unsigned.message.header().num_required_signatures, 1);
    assert!(!unsigned.message.static_account_keys().contains(
        &solana_pubkey::Pubkey::new_from_array(
            sender
                .signing_pubkey()
                .confidential_view_tag()
                .expect("owner tag"),
        )
    ));
    let transaction =
        spr_client::sign_transaction(unsigned.message, &[&payer]).expect("only relayer signs");
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

/// A merge needs no owner signature: the payer pays, the record enables it,
/// and the owner's nullifier secret proves it.
#[test]
fn a_client_over_the_harness_merges_a_wallets_utxos() {
    spawn_workspace_prover(IndexerRequirement::Optional);
    let (mut harness, tree, tree_id) = harness_with_tree();
    let payer = harness.payer.insecure_clone();
    let owner = Keypair::new();
    let wallet = ShieldedKeypair::from_keypair(&owner).expect("wallet");
    let address = wallet.shielded_address().expect("shielded address");
    // The first deposit opens the SOL vault, so it must cover its rent.
    let inputs: Vec<_> = [1_000_000, 200_000, 100_000]
        .into_iter()
        .map(|amount| shield(&mut harness, &tree, tree_id, &wallet, amount))
        .collect();
    let nullifiers: Vec<_> = inputs.iter().map(|input| input.nullifier).collect();
    write_merging_record(&mut harness, owner.pubkey(), &wallet);

    let client = harness
        .into_client(ProverClient::local())
        .with_proof_data_source(ProofDataSource::Client);
    let merge = MergeTransaction::new(inputs)
        .expect("merge")
        .with_output_tree_id(tree_id)
        .encrypt(&wallet)
        .expect("encrypt");
    assert_eq!(merge.output_utxo.amount, 1_300_000);
    let submission = MergeSubmission::new(&merge, owner.pubkey(), &address, &wallet.nullifier_key);
    // The proof binds no payer: any account can send the instruction.
    let proved = submission.prove_sync(&client).expect("proved");
    assert_eq!(
        proved.output_hash,
        merge.output_hash().expect("output hash")
    );
    let relayer = Keypair::new();
    let instruction = proved.instruction(relayer.pubkey());
    assert!(instruction
        .accounts
        .iter()
        .any(|account| account.pubkey == relayer.pubkey() && account.is_signer));
    let signature = submission
        .send_sync(&client, &payer)
        .expect("proved, sent, confirmed and indexed");
    assert!(client.confirm_transaction(signature).expect("confirmed"));
    let indexer = client.indexer().lock();
    for nullifier in &nullifiers {
        assert!(indexer.indexer().is_nullifier_spent(nullifier));
    }
}

/// `owner`'s user record with `wallet`'s keys and merging enabled.
fn write_merging_record(harness: &mut ZolanaProgramTest, owner: Pubkey, wallet: &ShieldedKeypair) {
    let (address, bump) = user_record_pda(&owner);
    let record = UserRecord {
        owner,
        bump,
        nullifier_pubkey: wallet.nullifier_key.pubkey().expect("nullifier pubkey"),
        viewing_pubkey: *wallet.viewing_pubkey().as_bytes(),
        merge_encryption: spr_user_registry_interface::MergeEncryptionScheme::PoseidonCtrV1,
    };
    let mut data = vec![UserRecord::DISCRIMINATOR];
    record.serialize(&mut data).expect("serialize the record");
    data.resize(UserRecord::SIZE, 0);
    harness
        .svm
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
        .expect("write the record");
}
