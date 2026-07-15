use cucumber::{given, then, when};
use zolana_keypair::{constants::BLINDING_LEN, viewing_key::random_salt};
use zolana_transaction::{
    serialization::{
        anonymous::AnonymousTransferSenderPlaintext,
        split::{Split, SplitBundlePlaintext, SplitEncode},
        OwnerCx, UtxoSerialization,
    },
    wallet::{AssetBalance, PrivateTransactionDirection, PrivateTransactionKind, Wallet},
    Address, AssetRegistry, Data, LocalWalletAuthority, OutputContext, OutputSlot,
    ShieldedTransaction, Utxo, SOL_ASSET_ID, SOL_MINT,
};

use super::transfer::{build_anonymous_transfer, RecipientSpec};
use crate::TransactionWorld;

enum TagKind {
    Bootstrap,
    Shared(u64),
    Request(u64),
}

fn record_transfer(
    world: &mut TransactionWorld,
    sender: &str,
    recipient: &str,
    amount: u64,
    tag: TagKind,
    spend: bool,
) {
    let assets = AssetRegistry::default();
    let tx_count = world.sent_counts.get(sender).copied().unwrap_or(0);
    let seq = (world.sync_transactions.len() + 1) as u8;
    let input = spend.then(|| {
        world
            .owned_utxos
            .get(sender)
            .and_then(|utxos| utxos.last())
            .cloned()
            .expect("no utxo to spend")
    });

    let sender_kp = world.fresh_keypair(sender);
    let recipient_kp = world.fresh_keypair(recipient);
    let first_nullifier = match &input {
        Some(utxo) => {
            let nullifier_pk = sender_kp.nullifier_key.pubkey().unwrap();
            let hash = utxo.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32]).unwrap();
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

    let sender_plaintext = AnonymousTransferSenderPlaintext {
        owner_pubkey: sender_kp.signing_pubkey(),
        spl_asset_id: 0,
        spl_amount: 0,
        sol_amount: change_amount,
        blinding_seed: [seq; BLINDING_LEN],
        recipient_viewing_pks: vec![recipient_kp.viewing_pubkey()],
        spl_data: Data::default(),
        sol_data: Data::default(),
    };

    let sender_view_tag = sender_kp.get_sender_view_tag(tx_count).unwrap();
    let specs = vec![RecipientSpec {
        keypair: recipient_kp.clone(),
        amount,
        blinding: [seq.wrapping_add(100); BLINDING_LEN],
        asset: SOL_MINT,
        asset_id: SOL_ASSET_ID,
        view_tag,
        data: Data::default(),
    }];

    let built = build_anonymous_transfer(
        &assets,
        &sender_kp,
        sender_plaintext,
        &specs,
        first_nullifier,
        sender_view_tag,
    );

    world.sync_transactions.push(built.transaction);
    world.sent_counts.insert(sender.to_string(), tx_count + 1);
    world
        .owned_utxos
        .entry(recipient.to_string())
        .or_default()
        .extend(built.recipient_utxos);
    world
        .owned_utxos
        .entry(sender.to_string())
        .or_default()
        .extend(built.change_utxos);
    if let Some(utxo) = input {
        world.spent_utxos.push(utxo);
    }
}

#[given(expr = "a recorded bootstrap transfer of {int} sol from {string} to {string}")]
fn bootstrap_transfer(
    world: &mut TransactionWorld,
    amount: u64,
    sender: String,
    recipient: String,
) {
    record_transfer(
        world,
        &sender,
        &recipient,
        amount,
        TagKind::Bootstrap,
        false,
    );
}

#[given(
    expr = "a recorded transfer of {int} sol from {string} to {string} spending her latest utxo"
)]
fn spending_transfer(world: &mut TransactionWorld, amount: u64, sender: String, recipient: String) {
    record_transfer(world, &sender, &recipient, amount, TagKind::Bootstrap, true);
}

#[given(expr = "a recorded shared transfer of {int} sol from {string} to {string} at index {int}")]
fn shared_transfer(
    world: &mut TransactionWorld,
    amount: u64,
    sender: String,
    recipient: String,
    i: u64,
) {
    record_transfer(
        world,
        &sender,
        &recipient,
        amount,
        TagKind::Shared(i),
        false,
    );
}

#[given(
    expr = "a recorded request transfer of {int} sol from {string} to {string} at request index {int}"
)]
fn request_transfer(
    world: &mut TransactionWorld,
    amount: u64,
    sender: String,
    recipient: String,
    i: u64,
) {
    record_transfer(
        world,
        &sender,
        &recipient,
        amount,
        TagKind::Request(i),
        false,
    );
}

#[given(expr = "a recorded split of {string}'s latest utxo into {int} parts")]
fn recorded_split(world: &mut TransactionWorld, owner: String, parts: u8) {
    let assets = AssetRegistry::default();
    let tx_count = world.sent_counts.get(&owner).copied().unwrap_or(0);
    let seq = (world.sync_transactions.len() + 1) as u8;
    let input = world
        .owned_utxos
        .get(&owner)
        .and_then(|utxos| utxos.last())
        .cloned()
        .expect("no utxo to split");

    let owner_kp = world.fresh_keypair(&owner);
    let nullifier_pk = owner_kp.nullifier_key.pubkey().unwrap();
    let hash = input.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32]).unwrap();
    let first_nullifier = input.nullifier(&hash, &owner_kp.nullifier_key).unwrap();
    let bundle = SplitBundlePlaintext {
        owner_pubkey: owner_kp.signing_pubkey(),
        num_outputs: parts,
        asset_id: SOL_ASSET_ID,
        asset_amount: input.amount / u64::from(parts),
        blinding_seed: [seq; BLINDING_LEN],
        data: Data::default(),
    };
    let outputs = bundle.clone().into_utxos(&assets, None).unwrap();

    let salt = random_salt();
    let tx = owner_kp
        .viewing_key
        .get_transaction_viewing_key(&first_nullifier)
        .unwrap();
    let tx_viewing_pk = tx.pubkey();
    let owner_cx = OwnerCx {
        owner: owner_kp.signing_pubkey(),
        assets: &assets,
        zone_program_id: None,
    };
    let sender_view_tag = owner_kp.get_sender_view_tag(tx_count).unwrap();
    let ciphertext = Split::encode(
        &outputs,
        &owner_cx,
        sender_view_tag,
        &SplitEncode {
            tx: tx.clone(),
            recipient_pubkey: owner_kp.viewing_pubkey(),
            salt,
            slot_index: 0,
            blinding_seed: [seq; BLINDING_LEN],
        },
    )
    .unwrap();

    let owner_nullifier_pk = owner_kp.nullifier_key.pubkey().unwrap();
    let mut output_slots = Vec::with_capacity(outputs.len());
    for (i, output) in outputs.iter().enumerate() {
        let hash = output
            .hash(&owner_nullifier_pk, &[0u8; 32], &[0u8; 32])
            .unwrap();
        if i == 0 {
            output_slots.push(OutputSlot {
                view_tag: ciphertext.view_tag,
                output_context: OutputContext {
                    hash,
                    tree: Default::default(),
                    leaf_index: 0,
                },
                payload: ciphertext.data.clone(),
            });
        } else {
            output_slots.push(OutputSlot {
                view_tag: [0u8; 32],
                output_context: OutputContext {
                    hash,
                    tree: Default::default(),
                    leaf_index: i as u64,
                },
                payload: Vec::new(),
            });
        }
    }

    let transaction = ShieldedTransaction {
        slot: 0,
        tx_signature: solana_signature::Signature::default(),
        tx_viewing_pk: Some(tx_viewing_pk),
        salt: Some(salt),
        output_slots,
        nullifiers: vec![first_nullifier],
        proofless: false,
    };

    world.sync_transactions.push(transaction);
    world.sent_counts.insert(owner.clone(), tx_count + 1);
    world.owned_utxos.entry(owner).or_default().extend(outputs);
    world.spent_utxos.push(input);
}

#[when(expr = "a fresh wallet for {string} is synced from the recorded transactions")]
fn sync_fresh_wallet(world: &mut TransactionWorld, name: String) {
    let keypair = world.fresh_keypair(&name);
    let mut wallet = Wallet::new(
        keypair.shielded_address().unwrap(),
        AssetRegistry::default(),
    )
    .unwrap();
    let authority = LocalWalletAuthority::new(Address::default(), &keypair);
    let report = wallet
        .sync(&authority, &world.sync_transactions, 1_700_000_000, 8)
        .unwrap();
    assert_eq!(report.unparsed_transactions, 0);
    assert_eq!(report.stored_utxos, wallet.utxos.len());
    assert_eq!(wallet.last_synced, 1_700_000_000);
    world.wallet = Some(wallet);
    world.wallet_name = Some(name);
}

#[then(expr = "the wallet holds {int} utxos of which {int} is spent")]
fn wallet_holds(world: &mut TransactionWorld, total: usize, spent: usize) {
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    assert_eq!(wallet.utxos.len(), total);
    assert_eq!(wallet.utxos.iter().filter(|u| u.spent).count(), spent);
}

#[then(expr = "the unspent sol balance is {int}")]
fn unspent_sol_balance(world: &mut TransactionWorld, amount: u64) {
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    let owner = world.wallet_name.as_ref().expect("wallet not synced");
    let balances = wallet.balances(false).unwrap();
    assert_eq!(balances.len(), 1);
    let mut actual = balances.into_iter().next().unwrap();
    actual.utxos.sort_by_key(|a| a.blinding);
    let mut expected_utxos: Vec<Utxo> = world
        .owned_utxos
        .get(owner)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|utxo| !world.spent_utxos.contains(utxo))
        .collect();
    expected_utxos.sort_by_key(|a| a.blinding);
    assert_eq!(
        actual,
        AssetBalance {
            asset_id: SOL_ASSET_ID,
            mint: SOL_MINT,
            amount,
            utxos: expected_utxos,
        }
    );
}

#[then(expr = "the wallet tx count is {int} and request count is {int}")]
fn wallet_counts(world: &mut TransactionWorld, tx_count: u64, request_count: u64) {
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

#[then(expr = "the wallet knows sender {string} with next index {int}")]
fn knows_sender(world: &mut TransactionWorld, name: String, index: u64) {
    let pubkey = world.kp(&name).viewing_pubkey();
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    let entry = wallet
        .viewing_key_history
        .last()
        .expect("no viewing key entry");
    assert_eq!(entry.known_senders.get(&pubkey), Some(&index));
}

#[then(expr = "the wallet knows recipient {string} with next index {int}")]
fn knows_recipient(world: &mut TransactionWorld, name: String, index: u64) {
    let pubkey = world.kp(&name).viewing_pubkey();
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    let entry = wallet
        .viewing_key_history
        .last()
        .expect("no viewing key entry");
    assert_eq!(entry.known_recipients.get(&pubkey), Some(&index));
}

#[then(expr = "the wallet has {int} private transactions")]
fn private_tx_count(world: &mut TransactionWorld, count: usize) {
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    assert_eq!(wallet.private_transactions().len(), count);
}

#[then(expr = "an inbound private transfer of {int} sol from {string} is recorded")]
fn inbound_from(world: &mut TransactionWorld, amount: u64, sender: String) {
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

#[then(expr = "an outbound private transfer of {int} sol to {string} is recorded")]
fn outbound_to(world: &mut TransactionWorld, amount: u64, recipient: String) {
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

#[then(expr = "a split of {int} sol is recorded")]
fn split_recorded(world: &mut TransactionWorld, amount: u64) {
    let wallet = world.wallet.as_ref().expect("wallet not synced");
    let found = wallet.private_transactions().iter().any(|tx| {
        tx.kind == PrivateTransactionKind::Split
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
