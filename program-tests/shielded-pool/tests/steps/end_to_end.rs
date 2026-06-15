//! End-to-end happy-path steps.

use cucumber::{then, when};
use solana_keypair::Keypair;
use solana_signer::Signer;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::ShieldedKeypair;
use zolana_program_test::{proofless_event_for_wallet, ZolanaProgramTest};
use zolana_transaction::{AssetRegistry, Wallet, DEFAULT_TAG_WINDOW};

use crate::ShieldedPoolWorld;

const E2E_AMOUNTS: [u64; 3] = [1_000_000_000, 250_000_000, 1_000_000];

#[when(expr = "the depositor shields {int} lamports into the pool")]
fn shield_into_pool(world: &mut ShieldedPoolWorld, amount: u64) {
    let tree = world.tree().pubkey();
    let depositor = Keypair::new();
    world
        .rpc()
        .airdrop(&depositor.pubkey(), 5_000_000_000)
        .expect("airdrop");

    let vault = world.rpc().cpi_authority();
    let vault_before_lamports = world
        .rpc()
        .svm
        .get_account(&vault)
        .map(|a| a.lamports)
        .unwrap_or(0);
    let tree_before = world.rpc().account_data(&tree).expect("tree data");
    let recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");

    let seed = [42u8; BLINDING_LEN];
    let data = ZolanaProgramTest::wallet_sol_shield_data(amount, &recipient, &seed, 0)
        .expect("wallet deposit data");
    world
        .rpc()
        .proofless_shield(&tree, &depositor, &data)
        .expect("proofless_shield");

    // The deposit landed in the pool's SOL vault (the CPI authority PDA).
    let vault_lamports = world
        .rpc()
        .svm
        .get_account(&vault)
        .map(|a| a.lamports)
        .unwrap_or(0);
    assert!(
        vault_lamports >= vault_before_lamports + amount,
        "vault must grow by the deposit"
    );

    // The UTXO was appended: the state sub-tree root / next_index changed.
    let tree_after = world.rpc().account_data(&tree).expect("tree data");
    assert_ne!(tree_before, tree_after, "tree must record the new leaf");
}

#[then(expr = "the deposit lands in the pool vault and grows the tree")]
fn deposit_landed(_world: &mut ShieldedPoolWorld) {
    // Assertions are performed in the `When` step where before/after state is local.
}

#[when(expr = "the depositor makes the bootstrap deposit run")]
fn bootstrap_deposits(world: &mut ShieldedPoolWorld) {
    let tree = world.tree().pubkey();
    // Empty trees must agree before any deposits.
    assert_eq!(
        world.rpc().indexer().root(),
        world.rpc().state_root(&tree).expect("state root"),
        "empty trees must agree"
    );

    let depositor = Keypair::new();
    world
        .rpc()
        .airdrop(&depositor.pubkey(), 10_000_000_000)
        .expect("airdrop");
    let mut recipient =
        Wallet::new(ShieldedKeypair::new().expect("recipient keypair")).expect("wallet");

    let mut owner_utxo_hashes = Vec::new();
    let mut view_tags = Vec::new();
    for (i, amount) in E2E_AMOUNTS.into_iter().enumerate() {
        let mut seed = [0xA0; BLINDING_LEN];
        seed[30] = i as u8;
        let data = ZolanaProgramTest::wallet_sol_shield_data(amount, &recipient, &seed, i as u8)
            .expect("wallet deposit data");
        let event = world
            .rpc()
            .proofless_shield(&tree, &depositor, &data)
            .expect("deposit");
        assert_eq!(event.amount, amount, "event must carry the settled amount");
        assert_eq!(event.asset, [0u8; 32], "SOL asset is the zero address");
        assert_eq!(event.salt, data.salt);
        let before = recipient.utxos.len();
        recipient
            .sync(
                &[],
                &[proofless_event_for_wallet(&event)],
                &AssetRegistry::default(),
                0,
                DEFAULT_TAG_WINDOW,
            )
            .expect("wallet discovery");
        assert_eq!(
            recipient.utxos.len(),
            before + 1,
            "wallet must discover deposit {i}"
        );
        owner_utxo_hashes.push(data.owner_utxo_hash);
        view_tags.push(data.view_tag);

        assert_eq!(
            world.rpc().indexer().root(),
            world.rpc().state_root(&tree).expect("state root"),
            "indexed tree must track the on-chain root after deposit {i}"
        );
    }

    // The depositor locates each UTXO by its opaque owner commitment; the
    // recipient by scanning their view tag.
    let indexer = world.rpc().indexer();
    for (i, amount) in E2E_AMOUNTS.into_iter().enumerate() {
        let record = indexer
            .fetch_by_owner_utxo_hash(&owner_utxo_hashes[i])
            .expect("fetch by owner commitment");
        assert_eq!(
            record.proofless().expect("proofless deposit").amount,
            amount
        );
        assert_eq!(record.leaf_index, i as u64);

        let by_tag: Vec<_> = indexer.fetch_by_view_tag(&view_tags[i]).collect();
        assert_eq!(
            by_tag.len(),
            3,
            "bootstrap view tag locates recipient deposits"
        );
        assert!(by_tag.iter().any(|record| record.leaf_index == i as u64));
    }
    world.recipient = Some(recipient);
}

#[then(expr = "the indexer matches the on-chain root and the recipient owns {int} UTXOs")]
fn indexer_matches(world: &mut ShieldedPoolWorld, count: usize) {
    assert_eq!(world.recipient().utxos.len(), count);
}
