//! The harness as a `ZolanaClient`'s indexer: the proofs it serves are bound
//! to the roots the chain holds, and a transaction it sent is confirmed and
//! indexed.

use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_client::Rpc;
use zolana_keypair::{hash::owner_hash, ShieldedKeypair};
use zolana_program_test::ZolanaProgramTest;
use zolana_tree::TreeAccount;

#[test]
#[ignore = "needs the SBF build in target/deploy; run by `just test-program-fast`"]
fn the_handle_serves_the_proofs_the_chain_verifies() {
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
