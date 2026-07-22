use mollusk_svm::result::Check;
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_interface::pda;
use zolana_keypair::{constants::BLINDING_LEN, ShieldedKeypair};
use zolana_program_test::{ZolanaProgramTest, ZONE_TEST_PROGRAM_ID};
use zolana_test_utils::litesvm_asserts::{
    litesvm_assert_deposit, litesvm_assert_zone_deposit, DepositAssertArgs, SolDepositOracle,
    ZoneDepositAssertArgs,
};
use zolana_transaction::{
    owner_utxo_hash, AssetRegistry, LocalWalletAuthority, Wallet, DEFAULT_TAG_WINDOW,
};

use crate::{
    mollusk::deposit_fixture,
    support::{register_mint, spl_depositor, Pool},
};

#[test]
fn sol_deposit_moves_lamports_emits_the_exact_output_and_updates_the_indexer() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let recipient_key = ShieldedKeypair::new().expect("recipient keypair");
    let mut recipient = Wallet::new(
        recipient_key.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("recipient wallet");
    let mut data = ZolanaProgramTest::wallet_sol_shield_data(
        750_000_000,
        &recipient.identity,
        &[3u8; BLINDING_LEN],
        0,
    )
    .expect("deposit data");
    data.memo = Some(b"manual program test".to_vec());

    let tree = pool.tree.pubkey();
    let mut oracle = SolDepositOracle::capture(&pool.rpc, &tree, &depositor.pubkey());
    let root_before = pool.rpc.state_root(&tree).expect("state root");
    assert_eq!(
        pool.rpc.indexer().root(),
        root_before,
        "empty reference indexer and on-chain tree must start at the same root"
    );
    let event = pool
        .rpc
        .deposit(&tree, &depositor, &data)
        .expect("SOL deposit");
    oracle.record_accepted(&data, &event);
    oracle.assert_matches(&pool.rpc, &tree, &depositor.pubkey());
    litesvm_assert_deposit(
        &mut pool.rpc,
        &mut recipient,
        DepositAssertArgs {
            tree: &tree,
            event: &event,
            data: &data,
            expected_amount: 750_000_000,
            expected_asset: [0u8; 32],
            root_before,
            authority: &LocalWalletAuthority::new(Pubkey::default(), &recipient_key),
        },
    );
    assert_eq!(recipient.utxos.len(), 1);
}

#[test]
fn deposit_fixture_executes_successfully_before_mutation() {
    let (mollusk, instruction, accounts) = deposit_fixture();
    mollusk.process_and_validate_instruction(&instruction, &accounts, &[Check::success()]);
}

#[test]
fn bootstrap_deposits_keep_indexer_wallet_and_tree_in_sync() {
    const AMOUNTS: [u64; 3] = [1_000_000_000, 250_000_000, 1_000_000];

    let mut pool = Pool::initialized();
    let tree = pool.tree.pubkey();
    assert_eq!(
        pool.rpc.indexer().root(),
        pool.rpc.state_root(&tree).expect("state root"),
        "empty trees must agree"
    );

    let depositor = pool.funded_signer(10_000_000_000);
    let mut oracle = SolDepositOracle::capture(&pool.rpc, &tree, &depositor.pubkey());
    let recipient_keypair = ShieldedKeypair::new().expect("recipient keypair");
    let mut recipient = Wallet::new(
        recipient_keypair
            .shielded_address()
            .expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("wallet");
    let authority = LocalWalletAuthority::new(Address::default(), &recipient_keypair);

    let mut owner_utxo_hashes = Vec::new();
    let mut view_tags = Vec::new();
    for (i, amount) in AMOUNTS.into_iter().enumerate() {
        let mut seed = [0xA0; BLINDING_LEN];
        *seed.get_mut(30).expect("seed has message byte") = i as u8;
        let data =
            ZolanaProgramTest::wallet_sol_shield_data(amount, &recipient.identity, &seed, i as u8)
                .expect("wallet deposit data");
        let event = pool.rpc.deposit(&tree, &depositor, &data).expect("deposit");
        oracle.record_accepted(&data, &event);
        let before = recipient.utxos.len();
        recipient
            .sync(
                &authority,
                &[event.to_shielded_transaction(Signature::default())],
                0,
                DEFAULT_TAG_WINDOW,
            )
            .expect("wallet discovery");
        assert_eq!(
            recipient.utxos.len(),
            before + 1,
            "wallet must discover deposit {i}"
        );
        owner_utxo_hashes
            .push(owner_utxo_hash(&data.owner, &data.blinding).expect("owner utxo hash"));
        view_tags.push(data.view_tag);

        assert_eq!(
            pool.rpc.indexer().root(),
            pool.rpc.state_root(&tree).expect("state root"),
            "indexed tree must track the on-chain root after deposit {i}"
        );
        oracle.assert_matches(&pool.rpc, &tree, &depositor.pubkey());
    }

    let indexer = pool.rpc.indexer();
    for (i, amount) in AMOUNTS.into_iter().enumerate() {
        let owner_utxo_hash = owner_utxo_hashes.get(i).expect("owner UTXO hash");
        let record = indexer
            .fetch_by_owner_utxo_hash(owner_utxo_hash)
            .expect("fetch by owner commitment");
        assert_eq!(
            record.proofless().expect("proofless deposit").amount,
            amount
        );
        assert_eq!(record.leaf_index, i as u64);

        let view_tag = view_tags.get(i).expect("view tag");
        let by_tag: Vec<_> = indexer.fetch_by_view_tag(view_tag).collect();
        assert_eq!(
            by_tag.len(),
            3,
            "bootstrap view tag locates recipient deposits"
        );
        assert!(by_tag.iter().any(|record| record.leaf_index == i as u64));
    }
    assert_eq!(recipient.utxos.len(), 3);
}

#[test]
fn zone_sol_deposit_settles_and_indexes_the_exact_output() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_zone_test_program()
        .expect("load zone test program");
    let zone_authority = pool.authority.insecure_clone();
    pool.rpc
        .create_zone_config(&zone_authority, &zone_authority.pubkey(), true)
        .expect("create zone config");

    let tree = pool.tree.pubkey();
    let depositor = pool.funded_signer(5_000_000_000);
    let recipient_key = ShieldedKeypair::new().expect("recipient keypair");
    let mut recipient = Wallet::new(
        recipient_key.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("recipient wallet");
    let mut data = ZolanaProgramTest::wallet_zone_sol_shield_data(
        600_000_000,
        &recipient.identity,
        &[5u8; BLINDING_LEN],
        0,
    )
    .expect("zone SOL deposit data");
    data.zone_data_hash = [5u8; 32];
    let root_before = pool.rpc.state_root(&tree).expect("root");
    let depositor_before = pool
        .rpc
        .svm
        .get_account(&depositor.pubkey())
        .expect("depositor")
        .lamports;
    let vault_before = pool
        .rpc
        .svm
        .get_account(&pda::sol_interface())
        .map_or(0, |account| account.lamports);

    let event = pool
        .rpc
        .zone_deposit(&tree, &depositor, &data)
        .expect("zone SOL deposit");
    assert_eq!(
        pool.rpc
            .svm
            .get_account(&depositor.pubkey())
            .expect("depositor")
            .lamports,
        depositor_before - 600_000_000
    );
    assert_eq!(
        pool.rpc
            .svm
            .get_account(&pda::sol_interface())
            .expect("SOL vault")
            .lamports,
        vault_before + 600_000_000
    );
    litesvm_assert_zone_deposit(
        &mut pool.rpc,
        &mut recipient,
        ZoneDepositAssertArgs {
            tree: &tree,
            event: &event,
            data: &data,
            expected_amount: 600_000_000,
            expected_asset: [0u8; 32],
            expected_zone_program_id: ZONE_TEST_PROGRAM_ID,
            root_before,
            authority: &LocalWalletAuthority::new(Address::default(), &recipient_key),
        },
    );
    assert_eq!(recipient.utxos.len(), 1);
}

#[test]
fn zone_spl_deposit_settles_and_indexes_the_exact_output() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_zone_test_program()
        .expect("load zone test program");
    let zone_authority = pool.authority.insecure_clone();
    pool.rpc
        .create_zone_config(&zone_authority, &zone_authority.pubkey(), true)
        .expect("create zone config");
    let (mint, _, vault) = register_mint(&mut pool);
    let (depositor, user_token) = spl_depositor(&mut pool, mint, 1_000_000);
    let recipient_key = ShieldedKeypair::new().expect("recipient keypair");
    let mut recipient = Wallet::new(
        recipient_key.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("recipient wallet");
    let mut data = ZolanaProgramTest::wallet_zone_spl_shield_data(
        350_000,
        &recipient.identity,
        &[9u8; BLINDING_LEN],
        0,
    )
    .expect("zone SPL deposit data");
    data.zone_data_hash = [9u8; 32];
    let tree = pool.tree.pubkey();
    let root_before = pool.rpc.state_root(&tree).expect("root");
    let vault_before = pool.rpc.token_balance(&vault).expect("vault balance");
    let user_before = pool
        .rpc
        .token_balance(&user_token)
        .expect("user token balance");

    let event = pool
        .rpc
        .zone_deposit_spl(&tree, &depositor, &user_token, &mint, &data)
        .expect("zone SPL deposit");
    assert_eq!(pool.rpc.token_balance(&vault), Some(vault_before + 350_000));
    assert_eq!(
        pool.rpc.token_balance(&user_token),
        Some(user_before - 350_000)
    );
    litesvm_assert_zone_deposit(
        &mut pool.rpc,
        &mut recipient,
        ZoneDepositAssertArgs {
            tree: &tree,
            event: &event,
            data: &data,
            expected_amount: 350_000,
            expected_asset: mint.to_bytes(),
            expected_zone_program_id: ZONE_TEST_PROGRAM_ID,
            root_before,
            authority: &LocalWalletAuthority::new(Address::default(), &recipient_key),
        },
    );
    assert_eq!(recipient.utxos.len(), 1);
}
