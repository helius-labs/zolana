use mollusk_svm::result::Check;
use solana_address::Address;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_event::{general_event_from_indexed, Movement};
use zolana_interface::{
    instruction::{Deposit, UtxoData},
    pda,
};
use zolana_keypair::{hash::owner_hash, pubkey::PublicKey, NullifierKey, ShieldedKeypair};
use zolana_program_test::{ZolanaProgramTest, ZONE_TEST_PROGRAM_ID};
use zolana_test_utils::litesvm_asserts::{
    litesvm_assert_deposit, litesvm_assert_zone_deposit, DepositAssertArgs, SolDepositOracle,
    ZoneDepositAssertArgs,
};
use zolana_transaction::{
    owner_utxo_hash, AssetRegistry, Data, LocalWalletAuthority, Utxo, Wallet, DEFAULT_TAG_WINDOW,
    SOL_MINT,
};

use shielded_pool_tests::support::{
    fixtures::{register_mint, spl_depositor, Pool},
    mollusk::deposit_fixture,
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
        &[3u8; 32],
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
fn sol_deposit_emits_one_general_event_with_the_exact_deposit_withdraw() {
    const AMOUNT: u64 = 1_000_000;
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree.pubkey();
    let data = ZolanaProgramTest::sol_shield_data(AMOUNT, [9u8; 32], [9u8; 32]);
    let ix = Deposit {
        tree,
        depositor: depositor.pubkey(),
        deposits: vec![data],
    }
    .instruction()
    .expect("deposit instruction");

    let outcome = pool
        .rpc
        .create_and_send_default_payer_transaction(&[ix], &[&depositor])
        .expect("SOL deposit");
    assert_eq!(
        outcome.events.len(),
        1,
        "exactly one EmitEvent self-CPI must be recorded"
    );
    let event = general_event_from_indexed(outcome.events.first().expect("deposit event"))
        .expect("decoded GeneralEvent");
    assert_eq!(
        event.movements,
        vec![Movement {
            is_deposit: true,
            amount: AMOUNT,
            asset: None,
        }],
        "SOL deposit emits exactly one deposit movement with no asset"
    );
    assert!(event.inputs.is_empty(), "deposit spends no inputs");
    assert_eq!(event.outputs.len(), 1, "deposit appends exactly one output");
}

/// INV-DEPOSIT-17 frame: a successful SOL deposit changes only the tree and
/// the settlement pair (depositor, sol_interface); every other account keeps
/// its exact data and lamports.
#[test]
fn sol_deposit_modifies_only_the_tree_and_the_settlement_pair() {
    const AMOUNT: u64 = 1_000_000;
    let (mollusk, instruction, accounts) = deposit_fixture();
    let tree = instruction.accounts.first().expect("tree meta").pubkey;
    let depositor = instruction.accounts.get(1).expect("depositor meta").pubkey;
    let sol_interface = instruction
        .accounts
        .get(3)
        .expect("sol_interface meta")
        .pubkey;

    let result = mollusk.process_instruction(&instruction, &accounts);
    assert!(
        result.raw_result.is_ok(),
        "fixture deposit must succeed: {:?}",
        result.raw_result
    );
    for (key, before) in &accounts {
        let after = result
            .resulting_accounts
            .iter()
            .find(|(result_key, _)| result_key == key)
            .map(|(_, account)| account)
            .expect("input account present in result");
        if *key == tree {
            assert_ne!(after.data, before.data, "tree data must change");
            assert_eq!(after.lamports, before.lamports, "tree lamports unchanged");
        } else if *key == depositor {
            assert_eq!(
                after.lamports,
                before.lamports - AMOUNT,
                "depositor pays exactly the amount"
            );
            assert_eq!(after.data, before.data, "depositor data unchanged");
        } else if *key == sol_interface {
            assert_eq!(
                after.lamports,
                before.lamports + AMOUNT,
                "sol_interface receives exactly the amount"
            );
            assert_eq!(after.data, before.data, "sol_interface data unchanged");
        } else {
            assert_eq!(after, before, "account outside the frame must be untouched");
        }
    }
}

/// The `Some(utxo_data)` deposit arm: the supplied `data_hash` must be
/// committed into the on-chain UTXO hash exactly as the canonical client
/// hash computes it, and must change the hash relative to the plain arm.
#[test]
fn sol_deposit_with_utxo_data_commits_the_data_hash() {
    const AMOUNT: u64 = 250_000_000;
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let blinding: [u8; 32] = [7u8; 32];
    // 0x07-padded stays below the BN254 modulus, so the Poseidon hash accepts it.
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pk");
    let owner_pk = PublicKey::from_ed25519(&depositor.pubkey().to_bytes());
    let owner_field = owner_hash(&owner_pk, &nullifier_pk).expect("owner field");
    let utxo = Utxo {
        owner: owner_pk,
        asset: SOL_MINT,
        amount: AMOUNT,
        blinding,
        zone_program_id: None,
        data: Data::default(),
    };

    let mut data_hash = [0u8; 32];
    if let Some(last) = data_hash.last_mut() {
        *last = 42;
    }
    let mut data = ZolanaProgramTest::sol_shield_data(AMOUNT, owner_field, blinding);
    data.utxo_data = Some(UtxoData {
        data_hash,
        data: vec![1, 2, 3],
    });

    let tree = pool.tree.pubkey();
    let event = pool
        .rpc
        .deposit(&tree, &depositor, &data)
        .expect("SOL deposit with utxo data");

    let zero = [0u8; 32];
    assert_eq!(
        event.utxo_hash,
        utxo.hash(&nullifier_pk, &data_hash, &zero)
            .expect("hash with data"),
        "on-chain utxo hash must commit the supplied data_hash"
    );
    assert_ne!(
        event.utxo_hash,
        utxo.hash(&nullifier_pk, &zero, &zero)
            .expect("hash without data"),
        "the data-carrying arm must produce a different commitment than the plain arm"
    );
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
        let mut seed = [0xA0; 32];
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
        &[5u8; 32],
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
fn zone_deposit_event_carries_the_zone_data_preimage_verbatim() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_zone_test_program()
        .expect("load zone test program");
    let zone_authority = pool.authority.insecure_clone();
    pool.rpc
        .create_zone_config(&zone_authority, &zone_authority.pubkey(), true)
        .expect("create zone config");
    let tree = pool.tree.pubkey();
    let depositor = pool.funded_signer(2_000_000_000);
    let mut data = pool
        .rpc
        .zone_sol_shield_data(1_000_000, [4u8; 32], [4u8; 32]);
    data.zone_data_hash = [6u8; 32];
    data.zone_data = vec![11, 22, 33, 44, 55];

    let event = pool
        .rpc
        .zone_deposit(&tree, &depositor, &data)
        .expect("zone SOL deposit");
    assert_eq!(
        event.output.zone_data,
        Some(data.zone_data.clone()),
        "emitted ProoflessOutput carries the zone_data preimage verbatim"
    );
    assert_eq!(
        event.output.zone_data_hash,
        Some(data.zone_data_hash),
        "emitted ProoflessOutput carries the instruction's zone_data_hash"
    );
    assert_eq!(
        event.output.zone_program_id,
        Some(ZONE_TEST_PROGRAM_ID),
        "emitted ProoflessOutput carries the signing zone's program id"
    );
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
        mint,
        user_token,
        &recipient.identity,
        &[9u8; 32],
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
        .zone_deposit(&tree, &depositor, &data)
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

