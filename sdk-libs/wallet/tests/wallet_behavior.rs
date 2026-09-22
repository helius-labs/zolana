//! Wallet sync over a batch of anonymous transfers and a split.
//!
//! These cases build the published transactions by hand, keep the notes each
//! participant should end up with in a small world, and then assert that a
//! fresh wallet syncing the same batch reaches exactly that state: balances,
//! spends, counterparty counters and history rows. They live here rather than
//! in `zolana-transaction` because they drive `Wallet`, and a wallet-using test
//! in that crate makes it depend on this one.

mod common;

use std::collections::HashMap;

use common::{build_transfer, local_authority, wallet_for, TransferSpec, TEST_TREE_ID};
use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::{AssetRegistry, ShieldedTransaction, Utxo, SOL_ASSET_ID, SOL_MINT};
use zolana_wallet::{PrivateTransactionDirection, PrivateTransactionKind, Wallet};

/// The notes and counters a batch of published transactions should leave
/// behind, tracked independently of the wallet so the sync has something to be
/// checked against.
#[derive(Default)]
struct SyncWorld {
    keypairs: HashMap<String, ShieldedKeypair>,
    sync_transactions: Vec<ShieldedTransaction>,
    owned_utxos: HashMap<String, Vec<Utxo>>,
    spent_utxos: Vec<Utxo>,
    sent_counts: HashMap<String, u64>,
    wallet: Option<Wallet>,
    wallet_name: Option<String>,
}

impl SyncWorld {
    fn kp(&self, name: &str) -> &ShieldedKeypair {
        self.keypairs.get(name).expect("shielded keypair not set")
    }

    /// A keypair rebuilt from the stored secrets, so a case that mutates its
    /// copy cannot leak that state into the next one.
    fn fresh_keypair(&self, name: &str) -> ShieldedKeypair {
        let keypair = self.kp(name);
        let signing = SigningKey::from_p256_bytes(&keypair.signing_key.secret_bytes())
            .expect("signing key round-trip");
        let viewing = ViewingKey::from_bytes(&keypair.viewing_key.secret_bytes())
            .expect("viewing key round-trip");
        ShieldedKeypair::with_viewing_key(signing, viewing).expect("keypair rebuild")
    }
}

fn add_keypairs(world: &mut SyncWorld, names: &[&str]) {
    for name in names {
        world.keypairs.insert(
            (*name).to_string(),
            ShieldedKeypair::new_p256().expect("shielded keypair"),
        );
    }
}

enum TagKind {
    Bootstrap,
    Shared(u64),
    Request(u64),
}

fn record_transfer(
    world: &mut SyncWorld,
    sender: &str,
    recipient: &str,
    amount: u64,
    tag: TagKind,
    input_utxo: bool,
) {
    let assets = AssetRegistry::default();
    let tx_count = world.sent_counts.get(sender).copied().unwrap_or(0);
    let seq = (world.sync_transactions.len() + 1) as u8;
    let input = input_utxo.then(|| {
        world
            .owned_utxos
            .get(sender)
            .and_then(|utxos| utxos.last())
            .cloned()
            .expect("no utxo to input_utxo")
    });

    let sender_kp = world.fresh_keypair(sender);
    let recipient_kp = world.fresh_keypair(recipient);
    let first_nullifier = match &input {
        Some(utxo) => {
            let nullifier_pk = sender_kp.nullifier_key.pubkey().unwrap();
            let hash = utxo
                .hash(&nullifier_pk, &[0u8; 32], &[0u8; 32], TEST_TREE_ID)
                .unwrap();
            utxo.nullifier(&hash, &sender_kp.nullifier_key).unwrap()
        }
        None => [seq; 32],
    };
    let change_amount = input
        .as_ref()
        .map(|utxo| utxo.amount.checked_sub(amount).expect("insufficient input"))
        .unwrap_or(0);

    let view_tag = match tag {
        TagKind::Bootstrap => recipient_kp.recipient_bootstrap_view_tag(),
        TagKind::Shared(i) => sender_kp
            .get_send_shared_view_tag(&recipient_kp.viewing_pubkey(), i)
            .unwrap(),
        TagKind::Request(i) => recipient_kp.get_recipient_request_view_tag(i).unwrap(),
    };
    let sender_view_tag = sender_kp.get_sender_view_tag(tx_count).unwrap();
    // A BN254 field element: top byte zeroed (32-byte blindings must stay
    // below the modulus for the Poseidon UTXO hash).
    let mut blinding = [seq.wrapping_add(100); 32];
    blinding[0] = 0;

    let (transaction, recipient_utxo, change_utxos) = build_transfer(
        &assets,
        TransferSpec {
            sender: &sender_kp,
            recipient: &recipient_kp,
            amount,
            slot_tag: view_tag,
            sender_view_tag,
            first_nullifier,
            change_amount,
            blinding,
            blinding_seed: [seq; 32],
        },
    );

    world.sync_transactions.push(transaction);
    world.sent_counts.insert(sender.to_string(), tx_count + 1);
    world
        .owned_utxos
        .entry(recipient.to_string())
        .or_default()
        .push(recipient_utxo);
    world
        .owned_utxos
        .entry(sender.to_string())
        .or_default()
        .extend(change_utxos);
    if let Some(utxo) = input {
        world.spent_utxos.push(utxo);
    }
}

fn bootstrap_transfer(world: &mut SyncWorld, amount: u64, sender: String, recipient: String) {
    record_transfer(
        world,
        &sender,
        &recipient,
        amount,
        TagKind::Bootstrap,
        false,
    );
}

fn spending_transfer(world: &mut SyncWorld, amount: u64, sender: String, recipient: String) {
    record_transfer(world, &sender, &recipient, amount, TagKind::Bootstrap, true);
}

fn shared_transfer(world: &mut SyncWorld, amount: u64, sender: String, recipient: String, i: u64) {
    record_transfer(
        world,
        &sender,
        &recipient,
        amount,
        TagKind::Shared(i),
        false,
    );
}

fn request_transfer(world: &mut SyncWorld, amount: u64, sender: String, recipient: String, i: u64) {
    record_transfer(
        world,
        &sender,
        &recipient,
        amount,
        TagKind::Request(i),
        false,
    );
}

fn recorded_split(world: &mut SyncWorld, owner: String, parts: u8) {
    let tx_count = world.sent_counts.get(&owner).copied().unwrap_or(0);
    let seq = (world.sync_transactions.len() + 1) as u8;
    let input = world
        .owned_utxos
        .get(&owner)
        .and_then(|utxos| utxos.last())
        .cloned()
        .expect("no utxo to split");

    let owner_kp = world.fresh_keypair(&owner);
    let (transaction, outputs) = common::split_transaction(&owner_kp, &input, parts, [seq; 32]);
    world.sync_transactions.push(transaction);
    world.sent_counts.insert(owner.clone(), tx_count + 1);
    world.owned_utxos.entry(owner).or_default().extend(outputs);
    world.spent_utxos.push(input);
}

fn sync_fresh_wallet(world: &mut SyncWorld, name: String) {
    let keypair = world.fresh_keypair(&name);
    let mut wallet = wallet_for(&keypair, AssetRegistry::default());
    let authority = local_authority(&keypair);
    let report = wallet
        .sync(&authority, &world.sync_transactions, 1_700_000_000, 8)
        .unwrap();
    assert_eq!(report.unparsed_transactions, 0);
    assert_eq!(report.stored_utxos, wallet.utxos.len());
    assert_eq!(wallet.last_synced, 1_700_000_000);
    world.wallet = Some(wallet);
    world.wallet_name = Some(name);
}

/// Syncs a second fresh wallet over the same transactions through the parallel
/// scan and asserts it reaches the same history as [`sync_fresh_wallet`].
///
/// `parallel.rs` is a second implementation of the same scan, so every
/// classification rule exists there in a second copy. Comparing the two is what
/// keeps them from drifting apart -- a rule fixed in one and missed in the other
/// shows up here rather than in a user's history.
#[cfg(feature = "parallel")]
fn parallel_scan_agrees(world: &mut SyncWorld) {
    let name = world
        .wallet_name
        .clone()
        .expect("call after `sync_fresh_wallet`");
    let serial = world.wallet.as_ref().expect("wallet not synced");
    let keypair = world.kp(&name);
    let mut parallel = wallet_for(keypair, AssetRegistry::default());
    let authority = local_authority(keypair);
    parallel
        .sync_parallel(&authority, &world.sync_transactions, 1_700_000_000, 8)
        .unwrap();

    assert_eq!(
        parallel.private_transactions(),
        serial.private_transactions(),
        "parallel scan disagreed with the serial scan"
    );
}

fn wallet_holds(world: &mut SyncWorld, total: usize, spent: usize) {
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    assert_eq!(wallet.utxos.len(), total);
    assert_eq!(
        wallet.utxos.iter().filter(|u| wallet.is_spent(u)).count(),
        spent
    );
}

fn unspent_sol_balance(world: &mut SyncWorld, amount: u64) {
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    let owner = world.wallet_name.as_ref().expect("wallet not synced");
    let balances = wallet.balances(false).unwrap();
    assert_eq!(balances.len(), 1);
    let mut actual = balances.into_iter().next().unwrap();
    actual.utxos.sort_by_key(|entry| entry.utxo.blinding);
    let mut expected_utxos: Vec<Utxo> = world
        .owned_utxos
        .get(owner)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|utxo| !world.spent_utxos.contains(utxo))
        .collect();
    expected_utxos.sort_by_key(|a| a.blinding);
    // The balance carries WalletUtxos now, so the notes are compared as the
    // UTXOs the world tracks and the rest of the balance as a whole.
    let actual_utxos: Vec<Utxo> = actual
        .utxos
        .iter()
        .map(|entry| entry.utxo.clone())
        .collect();
    assert_eq!(
        (actual.asset_id, actual.mint, actual.amount, actual_utxos),
        (SOL_ASSET_ID, SOL_MINT, amount, expected_utxos)
    );
}

fn wallet_counts(world: &mut SyncWorld, tx_count: u64, request_count: u64) {
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    let entry = wallet
        .viewing_key_history
        .last()
        .expect("no viewing key entry");
    assert_eq!(
        (entry.tx_count, entry.request_count),
        (tx_count, request_count)
    );
}

fn knows_sender(world: &mut SyncWorld, name: String, index: u64) {
    let pubkey = world.kp(&name).viewing_pubkey();
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    let entry = wallet
        .viewing_key_history
        .last()
        .expect("no viewing key entry");
    assert_eq!(entry.known_senders.get(&pubkey), Some(&index));
}

fn knows_recipient(world: &mut SyncWorld, name: String, index: u64) {
    let pubkey = world.kp(&name).viewing_pubkey();
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    let entry = wallet
        .viewing_key_history
        .last()
        .expect("no viewing key entry");
    assert_eq!(entry.known_recipients.get(&pubkey), Some(&index));
}

fn private_tx_count(world: &mut SyncWorld, count: usize) {
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    assert_eq!(wallet.private_transactions().len(), count);
}

fn inbound_from(world: &mut SyncWorld, amount: u64, sender: String) {
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    let sender_pk = world.kp(&sender).viewing_pubkey();
    let found = wallet.private_transactions().iter().any(|tx| {
        tx.kind == PrivateTransactionKind::PrivateTransfer
            && tx.direction == PrivateTransactionDirection::Inbound
            && tx.amount == amount
            && tx.asset == SOL_MINT
            && tx.counterparty_viewing_pubkey == Some(sender_pk)
    });
    assert!(
        found,
        "missing inbound transfer of {amount} sol from {sender:?}; history={:?}",
        wallet.private_transactions()
    );
}

fn outbound_to(world: &mut SyncWorld, amount: u64, recipient: String) {
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    let recipient_pk = world.kp(&recipient).viewing_pubkey();
    let found = wallet.private_transactions().iter().any(|tx| {
        tx.kind == PrivateTransactionKind::PrivateTransfer
            && tx.direction == PrivateTransactionDirection::Outbound
            && tx.amount == amount
            && tx.asset == SOL_MINT
            && tx.counterparty_viewing_pubkey == Some(recipient_pk)
    });
    assert!(
        found,
        "missing outbound transfer of {amount} sol to {recipient:?}; history={:?}",
        wallet.private_transactions()
    );
}

/// The sender-side row of a transfer whose only recipient is the sender itself.
///
/// Recorded by the anonymous-sender bundle, whose recipient list the wallet
/// reads out of its own change slot -- the rail that used to hardcode
/// `Outbound` here while the matching receipt already said `SelfTransfer`.
fn self_transfer_recorded(world: &mut SyncWorld, amount: u64) {
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    let self_pk = wallet.identity.viewing_pubkey;
    let found = wallet.private_transactions().iter().any(|tx| {
        tx.kind == PrivateTransactionKind::PrivateTransfer
            && tx.direction == PrivateTransactionDirection::SelfTransfer
            && tx.amount == amount
            && tx.asset == SOL_MINT
            && tx.counterparty_viewing_pubkey == Some(self_pk)
    });
    assert!(
        found,
        "missing self transfer of {amount} sol; history={:?}",
        wallet.private_transactions()
    );
    // Scoped to this transfer: the helper must stay usable in a scenario that
    // also has a genuine outbound row.
    assert!(
        !wallet.private_transactions().iter().any(|tx| {
            tx.direction == PrivateTransactionDirection::Outbound
                && tx.amount == amount
                && tx.asset == SOL_MINT
        }),
        "a send to self must leave no outbound row for {amount} sol; history={:?}",
        wallet.private_transactions()
    );
}

fn split_recorded(world: &mut SyncWorld, amount: u64) {
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    let found = wallet.private_transactions().iter().any(|tx| {
        tx.kind == PrivateTransactionKind::PrivateTransfer
            && tx.direction == PrivateTransactionDirection::SelfTransfer
            && tx.amount == amount
            && tx.asset == SOL_MINT
    });
    assert!(
        found,
        "missing split of {amount} sol; history={:?}",
        wallet.private_transactions()
    );
}

#[test]
fn wallet_sync_restores_contacts_counters_spends_and_history() {
    let mut world = SyncWorld::default();
    add_keypairs(&mut world, &["alice", "bob", "carol"]);
    bootstrap_transfer(&mut world, 40, "bob".into(), "alice".into());
    spending_transfer(&mut world, 25, "alice".into(), "carol".into());
    shared_transfer(&mut world, 10, "bob".into(), "alice".into(), 0);
    sync_fresh_wallet(&mut world, "alice".into());
    wallet_holds(&mut world, 3, 1);
    unspent_sol_balance(&mut world, 25);
    wallet_counts(&mut world, 1, 0);
    knows_sender(&mut world, "bob".into(), 1);
    knows_recipient(&mut world, "carol".into(), 0);
    private_tx_count(&mut world, 3);
    inbound_from(&mut world, 40, "bob".into());
    outbound_to(&mut world, 25, "carol".into());
    inbound_from(&mut world, 10, "bob".into());
}

/// The anonymous rail classifies a send whose only recipient is the sender as a
/// self transfer, matching the confidential rail. Both the sender-bundle row and
/// the recipient receipt say `SelfTransfer`, so no row contradicts the other.
#[test]
fn wallet_sync_classifies_an_anonymous_send_to_self() {
    let mut world = SyncWorld::default();
    add_keypairs(&mut world, &["alice", "bob"]);
    bootstrap_transfer(&mut world, 40, "bob".into(), "alice".into());
    spending_transfer(&mut world, 25, "alice".into(), "alice".into());
    sync_fresh_wallet(&mut world, "alice".into());
    self_transfer_recorded(&mut world, 25);
    #[cfg(feature = "parallel")]
    parallel_scan_agrees(&mut world);
}

#[test]
fn wallet_sync_restores_split_and_payment_request_history() {
    let mut world = SyncWorld::default();
    add_keypairs(&mut world, &["alice", "bob", "carol"]);
    bootstrap_transfer(&mut world, 40, "bob".into(), "alice".into());
    recorded_split(&mut world, "alice".into(), 4);
    request_transfer(&mut world, 5, "carol".into(), "alice".into(), 0);
    sync_fresh_wallet(&mut world, "alice".into());
    wallet_holds(&mut world, 6, 1);
    unspent_sol_balance(&mut world, 45);
    wallet_counts(&mut world, 0, 1);
    knows_sender(&mut world, "carol".into(), 0);
    private_tx_count(&mut world, 3);
    inbound_from(&mut world, 40, "bob".into());
    split_recorded(&mut world, 40);
    inbound_from(&mut world, 5, "carol".into());
}
