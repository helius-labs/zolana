use solana_address::Address;
use solana_clock::Clock;
use solana_pubkey::Pubkey;
use solana_signature::Signature;
use solana_signer::Signer;
use zolana_event::{general_event_from_indexed, SplTransfer};
use zolana_interface::{
    instruction::{deposit_blinding, AssetDeposit, Deposit, UtxoData},
    pda,
    state::STATE_ROOT_HISTORY_CAPACITY,
};
use zolana_keypair::{
    hash::owner_hash, pubkey::PublicKey, NullifierKey, ShieldedKeypair, ViewingKey,
};
use zolana_program_test::{
    DepositOutput, RingDepositOutput, ZolanaProgramTest, RING_TEST_PROGRAM_ID,
};
use zolana_test_utils::litesvm_asserts::{
    litesvm_assert_deposit, litesvm_assert_ring_deposit, DepositAssertArgs, RingDepositAssertArgs,
    SolDepositOracle,
};
use zolana_transaction::{
    derive_blinding, owner_utxo_hash, serialization::RingDepositPlaintext, AssetRegistry, Data,
    KeypairWalletAuthority, Utxo, Wallet, DEFAULT_TAG_WINDOW, SOL_MINT,
};
use zolana_tree::TreeAccount;

use shielded_pool_tests::support::{
    fixtures::{register_mint, spl_depositor, Pool},
    mollusk::deposit_fixture,
    transact::tree_progress,
};

#[test]
fn sol_deposit_moves_lamports_emits_the_exact_output_and_updates_the_indexer() {
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let recipient_key = ShieldedKeypair::new_p256().expect("recipient keypair");
    let mut recipient = Wallet::new(
        recipient_key.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("recipient wallet");
    let mut data = ZolanaProgramTest::wallet_sol_shield_data(750_000_000, &recipient.identity)
        .expect("deposit data");
    data.memo = Some(b"manual program test".to_vec());

    let tree = pool.tree;
    let mut oracle = SolDepositOracle::capture(&pool.rpc, &tree, &depositor.pubkey());
    let root_before = pool.rpc.state_root(&tree).expect("state root");
    let indexed_outputs_before = pool.rpc.indexer().utxos().len();
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
            indexed_outputs_before,
            authority: &KeypairWalletAuthority::new(Pubkey::default(), &recipient_key),
        },
    );
    assert_eq!(recipient.utxos.len(), 1);
}

#[test]
fn deposits_advance_history_once_per_updated_slot_without_gap_entries() {
    let mut pool = Pool::initialized();
    let tree = pool.tree;
    let (initial_index, initial_history_len) = {
        let mut data = pool.rpc.account_data(&tree).expect("tree account");
        let mut account =
            TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree account");
        (
            account.utxo_tree().current_root_index(),
            account.utxo_tree().root_history_len,
        )
    };
    assert_eq!(initial_index, 0);
    assert_eq!(initial_history_len, 1);

    let current_slot = pool.rpc.svm.get_sysvar::<Clock>().slot;
    let target_slot = current_slot + 1;
    pool.rpc
        .warp_to_slot(target_slot)
        .expect("warp to first updated slot");
    let expected_index = (initial_index + 1) % STATE_ROOT_HISTORY_CAPACITY as u16;

    let depositor = pool.funded_signer(2_000_000_000);
    pool.rpc
        .deposit(
            &tree,
            &depositor,
            &ZolanaProgramTest::sol_shield_data(1_000_000, [1; 32]),
        )
        .expect("first deposit");
    assert_eq!(pool.rpc.svm.get_sysvar::<Clock>().slot, target_slot);

    let (first_root, first_history_len) = {
        let mut data = pool.rpc.account_data(&tree).expect("tree account");
        let mut account =
            TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree account");
        assert_eq!(account.utxo_tree().current_root_index(), expected_index);
        let root = account.utxo_tree().root();
        assert_eq!(
            account
                .get_utxo_tree_root(expected_index)
                .expect("first slot root"),
            root
        );
        assert_eq!(account.utxo_tree().last_update_slot, target_slot);
        let history_len = account.utxo_tree().root_history_len;
        assert_eq!(history_len, 2, "the first updated slot adds one entry");
        (root, history_len)
    };

    pool.rpc
        .deposit(
            &tree,
            &depositor,
            &ZolanaProgramTest::sol_shield_data(1_000_000, [3; 32]),
        )
        .expect("second deposit");
    assert_eq!(pool.rpc.svm.get_sysvar::<Clock>().slot, target_slot);

    let same_slot_final_root = {
        let mut data = pool.rpc.account_data(&tree).expect("tree account");
        let mut account =
            TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree account");
        let final_root = account.utxo_tree().root();
        assert_ne!(
            final_root, first_root,
            "the second deposit changes the root"
        );
        assert_eq!(account.utxo_tree().current_root_index(), expected_index);
        assert_eq!(
            account
                .get_utxo_tree_root(expected_index)
                .expect("slot-final root"),
            final_root,
            "the second root overwrites the first root at the current index"
        );
        assert_eq!(account.utxo_tree().last_update_slot, target_slot);
        assert_eq!(
            account.utxo_tree().root_history_len,
            first_history_len,
            "a second update in the same slot must not consume another history entry"
        );
        final_root
    };

    let expected_gap_index = (expected_index + 1) % STATE_ROOT_HISTORY_CAPACITY as u16;
    let mut gap_slot = target_slot + STATE_ROOT_HISTORY_CAPACITY as u64;
    if gap_slot % STATE_ROOT_HISTORY_CAPACITY as u64 == u64::from(expected_gap_index) {
        gap_slot += 1;
    }
    assert_ne!(
        gap_slot % STATE_ROOT_HISTORY_CAPACITY as u64,
        u64::from(expected_gap_index),
        "the regression must distinguish the dense index from slot modulo capacity"
    );
    pool.rpc
        .warp_to_slot(gap_slot)
        .expect("warp across slots without tree updates");
    pool.rpc
        .deposit(
            &tree,
            &depositor,
            &ZolanaProgramTest::sol_shield_data(1_000_000, [5; 32]),
        )
        .expect("deposit after slot gap");

    let mut data = pool.rpc.account_data(&tree).expect("tree account");
    let mut account =
        TreeAccount::from_bytes(&mut data, tree.to_bytes()).expect("load tree account");
    assert_eq!(account.utxo_tree().current_root_index(), expected_gap_index);
    assert_eq!(account.utxo_tree().last_update_slot, gap_slot);
    assert_eq!(
        account.utxo_tree().root_history_len,
        first_history_len + 1,
        "the entire slot gap consumes only the one entry written after it"
    );
    assert_eq!(
        account
            .get_utxo_tree_root(expected_index)
            .expect("previous updated-slot root"),
        same_slot_final_root,
        "skipped slots do not create holes or evict the prior root"
    );
}

#[test]
fn sol_deposit_emits_one_general_event_with_the_exact_deposit_withdraw() {
    const AMOUNT: u64 = 1_000_000;
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(2_000_000_000);
    let tree = pool.tree;
    let data = ZolanaProgramTest::sol_shield_data(AMOUNT, [9u8; 32]);
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
        event.spl_transfers,
        vec![SplTransfer {
            is_deposit: true,
            amount: AMOUNT,
            asset: None,
        }],
        "SOL deposit emits exactly one deposit transfer with no asset"
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
    // Deposit accounts: [tree, depositor, program, system_program, sol_interface].
    let sol_interface = instruction
        .accounts
        .get(4)
        .expect("sol_interface meta")
        .pubkey;
    assert_eq!(sol_interface, pda::sol_interface());

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
    let nullifier_key = NullifierKey::from_secret([9u8; 31]);
    let nullifier_pk = nullifier_key.pubkey().expect("nullifier pk");
    let owner_pk = PublicKey::from_ed25519(&depositor.pubkey().to_bytes());
    let owner_field = owner_hash(&owner_pk, &nullifier_pk).expect("owner field");

    let mut data_hash = [0u8; 32];
    if let Some(last) = data_hash.last_mut() {
        *last = 42;
    }
    let mut data = ZolanaProgramTest::sol_shield_data(AMOUNT, owner_field);
    data.utxo_data = Some(UtxoData {
        data_hash,
        data: vec![1, 2, 3],
    });

    let tree = pool.tree;
    let event = pool
        .rpc
        .deposit(&tree, &depositor, &data)
        .expect("SOL deposit with utxo data");
    let blinding = deposit_blinding(&tree.to_bytes(), event.leaf_index).expect("deposit blinding");
    let utxo = Utxo {
        owner: owner_pk,
        asset: SOL_MINT,
        amount: AMOUNT,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    };

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
    let tree = pool.tree;
    assert_eq!(
        pool.rpc.indexer().root(),
        pool.rpc.state_root(&tree).expect("state root"),
        "empty trees must agree"
    );

    let depositor = pool.funded_signer(10_000_000_000);
    let mut oracle = SolDepositOracle::capture(&pool.rpc, &tree, &depositor.pubkey());
    let recipient_keypair = ShieldedKeypair::new_p256().expect("recipient keypair");
    let mut recipient = Wallet::new(
        recipient_keypair
            .shielded_address()
            .expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("wallet");
    let authority = KeypairWalletAuthority::new(Address::default(), &recipient_keypair);

    let mut owner_utxo_hashes = Vec::new();
    let mut view_tags = Vec::new();
    for (i, amount) in AMOUNTS.into_iter().enumerate() {
        let data = ZolanaProgramTest::wallet_sol_shield_data(amount, &recipient.identity)
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
        let blinding = recipient
            .utxos
            .last()
            .expect("discovered UTXO")
            .utxo
            .blinding;
        owner_utxo_hashes.push(owner_utxo_hash(&data.owner, &blinding).expect("owner utxo hash"));
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
fn ring_sol_deposit_settles_and_indexes_the_exact_output() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_ring_test_program()
        .expect("load ring test program");
    let ring_authority = pool.authority.insecure_clone();
    pool.rpc
        .create_activated_ring_config(
            &ring_authority,
            &ring_authority.pubkey(),
            &ring_authority,
            true,
        )
        .expect("create ring config");

    let tree = pool.tree;
    let depositor = pool.funded_signer(5_000_000_000);
    let recipient_key = ShieldedKeypair::new_p256().expect("recipient keypair");
    let mut recipient = Wallet::new(
        recipient_key.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("recipient wallet");
    let mut data = ZolanaProgramTest::wallet_ring_sol_shield_data(
        600_000_000,
        &recipient.identity,
        &[5u8; 32],
        0,
    )
    .expect("ring SOL deposit data");
    data.ring_data_hash = [5u8; 32];
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
        .ring_deposit(&tree, &depositor, &data)
        .expect("ring SOL deposit");
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
    litesvm_assert_ring_deposit(
        &mut pool.rpc,
        &mut recipient,
        RingDepositAssertArgs {
            tree: &tree,
            event: &event,
            data: &data,
            expected_amount: 600_000_000,
            expected_asset: [0u8; 32],
            expected_ring_program_id: RING_TEST_PROGRAM_ID,
            root_before,
            authority: &KeypairWalletAuthority::new(Address::default(), &recipient_key),
        },
    );
    assert_eq!(recipient.utxos.len(), 1);
}

#[test]
fn ring_deposit_event_carries_the_ring_data_preimage_verbatim() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_ring_test_program()
        .expect("load ring test program");
    let ring_authority = pool.authority.insecure_clone();
    pool.rpc
        .create_activated_ring_config(
            &ring_authority,
            &ring_authority.pubkey(),
            &ring_authority,
            true,
        )
        .expect("create ring config");
    let tree = pool.tree;
    let depositor = pool.funded_signer(2_000_000_000);
    let mut data = pool
        .rpc
        .ring_sol_shield_data(1_000_000, [4u8; 32], [4u8; 32]);
    data.ring_data_hash = [6u8; 32];
    // The ring_data preimage travels inside the owner-hidden encrypted
    // envelope, so the event must carry the ciphertext verbatim and the
    // plaintext must round-trip back to the exact ring_data bytes.
    let viewing_key = ViewingKey::new();
    let ring_data = vec![11, 22, 33, 44, 55];
    data.encrypted = RingDepositPlaintext {
        blinding: [4u8; 32],
        utxo_data: None,
        memo: None,
        ring_data: ring_data.clone(),
    }
    .encrypt(&viewing_key.pubkey())
    .expect("encrypt ring deposit plaintext");

    let event = pool
        .rpc
        .ring_deposit(&tree, &depositor, &data)
        .expect("ring SOL deposit");
    assert_eq!(
        event.output.encrypted.ciphertext, data.encrypted.ciphertext,
        "emitted output carries the encrypted envelope verbatim"
    );
    let plaintext = RingDepositPlaintext::decrypt(&event.output.encrypted, &viewing_key)
        .expect("decrypt ring deposit plaintext");
    assert_eq!(
        plaintext.ring_data, ring_data,
        "ring_data preimage round-trips verbatim"
    );
    assert_eq!(
        event.output.ring_data_hash, data.ring_data_hash,
        "emitted output carries the instruction's ring_data_hash"
    );
    assert_eq!(
        event.output.ring_program_id, RING_TEST_PROGRAM_ID,
        "emitted output carries the signing ring's program id"
    );
}

#[test]
fn ring_deposit_batch_binds_distinct_ring_data_per_entry() {
    const AMOUNTS: [u64; 3] = [1_000_000, 2_000_000, 3_000_000];
    const BLINDING_SEED: [u8; 32] = [8u8; 32];

    let mut pool = Pool::initialized();
    pool.rpc
        .load_ring_test_program()
        .expect("load ring test program");
    let ring_authority = pool.authority.insecure_clone();
    pool.rpc
        .create_activated_ring_config(
            &ring_authority,
            &ring_authority.pubkey(),
            &ring_authority,
            true,
        )
        .expect("create ring config");

    let tree = pool.tree;
    let depositor = pool.funded_signer(2_000_000_000);
    let recipient_key = ShieldedKeypair::new_p256().expect("recipient keypair");
    let recipient = recipient_key
        .shielded_address()
        .expect("recipient shielded address");
    let first_leaf_index = tree_progress(&pool.rpc, &tree).0;
    let ring_program_id = Address::new_from_array(RING_TEST_PROGRAM_ID);
    let interface_before = sol_interface_lamports(&pool.rpc);
    let total_amount = AMOUNTS.into_iter().sum::<u64>();

    let mut deposits = Vec::with_capacity(AMOUNTS.len());
    let mut expected_outputs = Vec::with_capacity(AMOUNTS.len());
    for (offset, amount) in AMOUNTS.into_iter().enumerate() {
        let position = u8::try_from(offset).expect("small ring deposit batch");
        let blinding = derive_blinding(&BLINDING_SEED, position);
        let ring_data_hash = [position.checked_add(1).expect("ring-data seed"); 32];
        let ring_data = vec![position, position.checked_add(10).expect("ring-data byte")];
        let mut data = ZolanaProgramTest::wallet_ring_sol_shield_data(
            amount,
            &recipient,
            &BLINDING_SEED,
            position,
        )
        .expect("ring deposit data");
        data.ring_data_hash = ring_data_hash;
        data.encrypted = RingDepositPlaintext {
            blinding,
            utxo_data: None,
            memo: None,
            ring_data,
        }
        .encrypt(&recipient.viewing_pubkey)
        .expect("encrypt ring deposit data");

        let expected_utxo = Utxo {
            owner: recipient.signing_pubkey,
            asset: SOL_MINT,
            amount,
            blinding,
            ring_program_id: Some(ring_program_id),
            data: Data::default(),
        };
        let utxo_hash = expected_utxo
            .hash(&recipient.nullifier_pubkey, &[0u8; 32], &ring_data_hash)
            .expect("ring-bound UTXO hash");
        expected_outputs.push(RingDepositOutput {
            view_tag: data.view_tag,
            utxo_hash,
            output_tree: tree.to_bytes(),
            leaf_index: first_leaf_index
                .checked_add(u64::try_from(offset).expect("small ring deposit batch"))
                .expect("ring deposit leaf index"),
            output: zolana_event::EncryptedRingDepositOutput {
                owner_utxo_hash: data.owner_utxo_hash,
                asset: [0u8; 32],
                amount,
                data_hash: data.data_hash,
                ring_program_id: RING_TEST_PROGRAM_ID,
                ring_data_hash,
                encrypted: zolana_event::EncryptedRingDepositData {
                    tx_viewing_pk: data.encrypted.tx_viewing_pk,
                    salt: data.encrypted.salt,
                    ciphertext: data.encrypted.ciphertext.clone(),
                },
            },
        });
        deposits.push(data);
    }

    let batch = pool
        .rpc
        .ring_deposit_batch(&tree, &depositor, deposits)
        .expect("ring deposit batch");
    assert_eq!(
        batch.outputs, expected_outputs,
        "ring deposit batch event must bind every entry to its ring program and ring-data hash"
    );
    assert_eq!(
        batch.spl_transfers,
        vec![SplTransfer {
            is_deposit: true,
            amount: total_amount,
            asset: None,
        }],
        "ring deposit batch settles SOL once"
    );
    assert_eq!(
        sol_interface_lamports(&pool.rpc) - interface_before,
        total_amount,
        "ring deposit batch settles the summed amount"
    );
    assert_batch_root_matches_reference(&pool.rpc, &tree);
}

#[test]
fn ring_spl_deposit_settles_and_indexes_the_exact_output() {
    let mut pool = Pool::initialized();
    pool.rpc
        .load_ring_test_program()
        .expect("load ring test program");
    let ring_authority = pool.authority.insecure_clone();
    pool.rpc
        .create_activated_ring_config(
            &ring_authority,
            &ring_authority.pubkey(),
            &ring_authority,
            true,
        )
        .expect("create ring config");
    let (mint, _, vault) = register_mint(&mut pool);
    let (depositor, user_token) = spl_depositor(&mut pool, mint, 1_000_000);
    let recipient_key = ShieldedKeypair::new_p256().expect("recipient keypair");
    let mut recipient = Wallet::new(
        recipient_key.shielded_address().expect("shielded address"),
        AssetRegistry::default(),
    )
    .expect("recipient wallet");
    let mut data = ZolanaProgramTest::wallet_ring_spl_shield_data(
        350_000,
        mint,
        user_token,
        &recipient.identity,
        &[9u8; 32],
        0,
    )
    .expect("ring SPL deposit data");
    data.ring_data_hash = [9u8; 32];
    let tree = pool.tree;
    let root_before = pool.rpc.state_root(&tree).expect("root");
    let vault_before = pool.rpc.token_balance(&vault).expect("vault balance");
    let user_before = pool
        .rpc
        .token_balance(&user_token)
        .expect("user token balance");

    let event = pool
        .rpc
        .ring_deposit(&tree, &depositor, &data)
        .expect("ring SPL deposit");
    assert_eq!(pool.rpc.token_balance(&vault), Some(vault_before + 350_000));
    assert_eq!(
        pool.rpc.token_balance(&user_token),
        Some(user_before - 350_000)
    );
    litesvm_assert_ring_deposit(
        &mut pool.rpc,
        &mut recipient,
        RingDepositAssertArgs {
            tree: &tree,
            event: &event,
            data: &data,
            expected_amount: 350_000,
            expected_asset: mint.to_bytes(),
            expected_ring_program_id: RING_TEST_PROGRAM_ID,
            root_before,
            authority: &KeypairWalletAuthority::new(Address::default(), &recipient_key),
        },
    );
    assert_eq!(recipient.utxos.len(), 1);
}

/// The batch append writes one root for the whole batch; the indexer replays
/// the same leaves one at a time into its reference tree. Equal roots prove
/// the batch append and the leaf-by-leaf append agree.
#[track_caller]
fn assert_batch_root_matches_reference(rpc: &ZolanaProgramTest, tree: &Pubkey) {
    let onchain = rpc.state_root(tree).expect("state root");
    assert_eq!(
        rpc.indexer().root(),
        onchain,
        "batch append root must match the leaf-by-leaf reference tree"
    );
}

/// Every batch entry must append its own leaf at its own index, and the leaf
/// hashes must be distinct.
#[track_caller]
fn assert_distinct_leaves(outputs: &[DepositOutput], count: usize) {
    assert_eq!(outputs.len(), count);
    let mut leaf_indices: Vec<u64> = outputs.iter().map(|output| output.leaf_index).collect();
    leaf_indices.sort_unstable();
    leaf_indices.dedup();
    assert_eq!(
        leaf_indices.len(),
        count,
        "each batch entry must append its own leaf"
    );
    let mut hashes: Vec<[u8; 32]> = outputs.iter().map(|output| output.utxo_hash).collect();
    hashes.sort_unstable();
    hashes.dedup();
    assert_eq!(hashes.len(), count, "batch leaves must be distinct");
}

fn sol_interface_lamports(rpc: &ZolanaProgramTest) -> u64 {
    rpc.svm
        .get_account(&pda::sol_interface())
        .map_or(0, |account| account.lamports)
}

/// Byte-identical entries must still append distinct leaves: each blinding
/// comes from the leaf index, so two outputs cannot collide into one UTXO.
#[test]
fn sol_deposit_batch_settles_once_and_appends_three_distinct_leaves() {
    const AMOUNT: u64 = 1_000_000;
    const COUNT: u64 = 3;
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree;
    let interface_before = sol_interface_lamports(&pool.rpc);
    let deposits: Vec<AssetDeposit> =
        vec![ZolanaProgramTest::sol_shield_data(AMOUNT, [7u8; 32]); COUNT as usize];

    let batch = pool
        .rpc
        .deposit_batch(&tree, &depositor, deposits)
        .expect("batch deposit");
    let outputs = batch.outputs;

    assert_distinct_leaves(&outputs, COUNT as usize);
    for output in &outputs {
        assert_eq!(
            output.output.blinding,
            deposit_blinding(&tree.to_bytes(), output.leaf_index).expect("expected blinding"),
            "each entry carries the blinding derived for its own leaf index"
        );
    }
    assert_eq!(
        batch.spl_transfers,
        vec![SplTransfer {
            is_deposit: true,
            amount: AMOUNT * COUNT,
            asset: None,
        }],
        "one settlement record carrying the summed SOL amount"
    );
    for output in &outputs {
        assert_eq!(output.output.amount, AMOUNT, "per-entry amount");
        assert_eq!(output.output.asset, [0u8; 32], "SOL asset");
    }
    assert_eq!(
        sol_interface_lamports(&pool.rpc) - interface_before,
        AMOUNT * COUNT,
        "the batch must settle the summed amount"
    );
    assert_batch_root_matches_reference(&pool.rpc, &tree);
}

/// Repeating the same entry in a later transaction must not reproduce the
/// earlier leaf, whose nullifier is already spendable from the public blinding.
#[test]
fn repeating_an_identical_deposit_in_a_later_transaction_appends_a_distinct_leaf() {
    const AMOUNT: u64 = 1_000_000;
    let mut pool = Pool::initialized();
    let depositor = pool.funded_signer(5_000_000_000);
    let tree = pool.tree;
    let data = ZolanaProgramTest::sol_shield_data(AMOUNT, [9u8; 32]);

    let first = pool
        .rpc
        .deposit(&tree, &depositor, &data)
        .expect("first deposit");
    let second = pool
        .rpc
        .deposit(&tree, &depositor, &data)
        .expect("second deposit");

    assert_ne!(first.leaf_index, second.leaf_index, "distinct leaf indices");
    assert_ne!(
        first.output.blinding, second.output.blinding,
        "identical instruction data must not reproduce a blinding"
    );
    assert_ne!(
        first.utxo_hash, second.utxo_hash,
        "identical instruction data must not reproduce a leaf"
    );
    for output in [&first, &second] {
        assert_eq!(
            output.output.blinding,
            deposit_blinding(&tree.to_bytes(), output.leaf_index).expect("expected blinding"),
            "blinding is derived from the tree and the leaf index"
        );
    }
    assert_batch_root_matches_reference(&pool.rpc, &tree);
}

#[test]
fn multi_asset_deposit_batch_settles_each_asset_once_and_appends_three_distinct_leaves() {
    const LAMPORTS: u64 = 1_000_000;
    const TOKENS: u64 = 1_000;
    let mut pool = Pool::initialized();
    let (mint, _, vault) = register_mint(&mut pool);
    let (depositor, user_token) = spl_depositor(&mut pool, mint, 1_000_000);
    let tree = pool.tree;
    let interface_before = sol_interface_lamports(&pool.rpc);
    let vault_before = pool.rpc.token_balance(&vault).expect("vault balance");

    let deposits = vec![
        ZolanaProgramTest::sol_shield_data(LAMPORTS, [1u8; 32]),
        ZolanaProgramTest::spl_shield_data(TOKENS, [2u8; 32], &mint, &user_token),
        ZolanaProgramTest::sol_shield_data(LAMPORTS, [3u8; 32]),
    ];
    let batch = pool
        .rpc
        .deposit_batch(&tree, &depositor, deposits)
        .expect("batch deposit");
    let outputs = batch.outputs;

    assert_distinct_leaves(&outputs, 3);
    assert_eq!(
        batch.spl_transfers,
        vec![
            SplTransfer {
                is_deposit: true,
                amount: LAMPORTS * 2,
                asset: None,
            },
            SplTransfer {
                is_deposit: true,
                amount: TOKENS,
                asset: Some(mint.to_bytes()),
            },
        ],
        "one settlement record per asset, each carrying that asset's total"
    );
    let assets: Vec<[u8; 32]> = outputs.iter().map(|output| output.output.asset).collect();
    assert_eq!(
        assets,
        vec![[0u8; 32], mint.to_bytes(), [0u8; 32]],
        "each output records its own asset"
    );
    assert_eq!(
        sol_interface_lamports(&pool.rpc) - interface_before,
        LAMPORTS * 2,
        "both SOL entries settle in one transfer"
    );
    assert_eq!(
        pool.rpc.token_balance(&vault).expect("vault balance") - vault_before,
        TOKENS,
        "the SPL entry settles into the vault"
    );
    assert_batch_root_matches_reference(&pool.rpc, &tree);
}
