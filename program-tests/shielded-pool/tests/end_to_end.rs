//! End-to-end happy-path coverage of the shielded-pool program against a
//! real .so loaded by litesvm. Tree appends happen through value-moving
//! instructions, which carry their own tests.
//!
//! Requires `cargo build-sbf -p shielded-pool-program` to have produced
//! `target/deploy/shielded_pool_program.so`. The ZolanaProgramTest returns
//! `ProgramTestError::MissingProgram` if not.
//!
mod common;

use common::program_test_with_tree;
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::proofless_event_for_wallet;
use zolana_transaction::Wallet;

#[test]
fn proofless_shield_sol_deposits_into_pool() {
    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    let depositor = Keypair::new();
    program_test
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("airdrop");

    let vault = program_test.cpi_authority();
    let vault_before_lamports = program_test
        .svm
        .get_account(&vault)
        .map(|a| a.lamports)
        .unwrap_or(0);
    let tree_before = program_test
        .account_data(&tree.pubkey())
        .expect("tree data");
    let recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");

    let amount = 1_000_000_000u64;
    let seed = [42u8; BLINDING_LEN];
    let data = zolana_program_test::ZolanaProgramTest::wallet_sol_shield_data(
        amount, &recipient, &seed, 0,
    )
    .expect("wallet deposit data");
    program_test
        .proofless_shield(&tree, &depositor, &data)
        .expect("proofless_shield");

    // The deposit landed in the pool's SOL vault (the CPI authority PDA).
    let vault_lamports = program_test
        .svm
        .get_account(&vault)
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert!(
        vault_lamports >= vault_before_lamports + amount,
        "vault must grow by the deposit"
    );

    // The UTXO was appended: the state sub-tree root / next_index changed.
    let tree_after = program_test
        .account_data(&tree.pubkey())
        .expect("tree data");
    assert_ne!(tree_before, tree_after, "tree must record the new leaf");
}

#[test]
fn indexer_matches_onchain_root_and_locates_deposits() {
    use zolana_program_test::ZolanaProgramTest;

    let Some((mut program_test, _authority, tree)) = program_test_with_tree() else {
        return;
    };
    assert_eq!(
        program_test.indexer().root(),
        program_test.state_root(&tree.pubkey()).expect("state root"),
        "empty trees must agree"
    );

    let depositor = Keypair::new();
    program_test
        .airdrop(&depositor.pubkey(), 10_000_000_000)
        .expect("airdrop");
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");

    let mut owner_utxo_hashes = Vec::new();
    let mut view_tags = Vec::new();
    for (i, amount) in [1_000_000_000u64, 250_000_000, 1_000_000]
        .into_iter()
        .enumerate()
    {
        let mut seed = [0xA0; BLINDING_LEN];
        seed[30] = i as u8;
        let data = ZolanaProgramTest::wallet_sol_shield_data(amount, &recipient, &seed, i as u8)
            .expect("wallet deposit data");
        let event = program_test
            .proofless_shield(&tree, &depositor, &data)
            .expect("deposit");
        assert_eq!(event.amount, amount, "event must carry the settled amount");
        assert_eq!(event.asset, [0u8; 32], "SOL asset is the zero address");
        assert_eq!(event.salt, data.salt);
        assert!(
            recipient
                .sync_proofless_deposit(&proofless_event_for_wallet(&event))
                .expect("wallet discovery"),
            "wallet must discover deposit {i}"
        );
        owner_utxo_hashes.push(data.owner_utxo_hash);
        view_tags.push(data.view_tag);

        assert_eq!(
            program_test.indexer().root(),
            program_test.state_root(&tree.pubkey()).expect("state root"),
            "indexed tree must track the on-chain root after deposit {i}"
        );
    }

    // The depositor locates each UTXO by its opaque owner commitment; the
    // recipient by scanning their view tag.
    let indexer = program_test.indexer();
    for (i, amount) in [1_000_000_000u64, 250_000_000, 1_000_000]
        .into_iter()
        .enumerate()
    {
        let record = indexer
            .fetch_by_owner_utxo_hash(&owner_utxo_hashes[i])
            .expect("fetch by owner commitment");
        assert_eq!(record.amount, amount);
        assert_eq!(record.leaf_index, i as u64);

        let by_tag: Vec<_> = indexer.fetch_by_view_tag(&view_tags[i]).collect();
        assert_eq!(
            by_tag.len(),
            3,
            "bootstrap view tag locates recipient deposits"
        );
        assert!(by_tag.iter().any(|record| record.leaf_index == i as u64));
    }
    assert_eq!(recipient.utxos.len(), 3);
}
