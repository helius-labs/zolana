use cucumber::{given, then, when};
use zolana_keypair::constants::BLINDING_LEN;
use zolana_transaction::split::SplitBundlePlaintext;
use zolana_transaction::transfer::{
    OutputCiphertext, RecipientOutput, TransferSenderPlaintext, SENDER_SLOT_COUNT,
};
use zolana_transaction::wallet::{AssetBalance, SyncTransaction, Wallet};
use zolana_transaction::{
    AssetRegistry, Data, TransactionEncryption, Utxo, SOL_ASSET_ID, SOL_MINT, SPLIT, TRANSFER,
};

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

    let sender_kp = world.kp(sender);
    let recipient_kp = world.kp(recipient);
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

    let recipient_utxo = Utxo {
        owner: recipient_kp.signing_pubkey(),
        asset: SOL_MINT,
        amount,
        blinding: [seq.wrapping_add(100); BLINDING_LEN],
        zone_program_id: None,
        data: Data::default(),
    };
    let view_tag = match tag {
        TagKind::Bootstrap => recipient_kp.recipient_bootstrap_view_tag(),
        TagKind::Shared(i) => sender_kp
            .get_send_shared_view_tag(&recipient_kp.viewing_pubkey(), i)
            .unwrap(),
        TagKind::Request(i) => recipient_kp.get_recipient_request_view_tag(i).unwrap(),
    };
    let recipient_plaintext = recipient_utxo
        .to_recipient_plaintext(sender_kp.viewing_pubkey(), &assets)
        .unwrap();
    let sender_plaintext = TransferSenderPlaintext {
        owner_pubkey: sender_kp.signing_pubkey(),
        spl_asset_id: 0,
        spl_amount: 0,
        sol_amount: change_amount,
        blinding_seed: [seq; BLINDING_LEN],
        recipient_viewing_pks: vec![recipient_kp.viewing_pubkey()],
        spl_data: Data::default(),
        sol_data: Data::default(),
    };
    let change = sender_plaintext.clone().into_utxos(&assets, None).unwrap();
    let blob = sender_kp
        .viewing_key
        .encrypt_transfer(
            &first_nullifier,
            &sender_plaintext,
            &[RecipientOutput {
                view_tag,
                plaintext: recipient_plaintext,
            }],
        )
        .unwrap();
    let sender_view_tag = sender_kp.get_sender_view_tag(tx_count).unwrap();
    let output_slots = blob
        .to_output_ciphertexts(
            sender_view_tag,
            SENDER_SLOT_COUNT,
            SENDER_SLOT_COUNT + blob.recipient_slots.len(),
        )
        .unwrap();

    world.sync_transactions.push(SyncTransaction {
        scheme: TRANSFER,
        tx_viewing_pk: blob.tx_viewing_pk,
        salt: blob.salt,
        output_slots,
        nullifiers: vec![first_nullifier],
    });
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
        .extend(change);
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

    let owner_kp = world.kp(&owner);
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
    let blob = owner_kp
        .viewing_key
        .encrypt_split(&first_nullifier, &bundle)
        .unwrap();
    let sender_view_tag = owner_kp.get_sender_view_tag(tx_count).unwrap();

    world.sync_transactions.push(SyncTransaction {
        scheme: SPLIT,
        tx_viewing_pk: blob.tx_viewing_pk,
        salt: blob.salt,
        output_slots: vec![OutputCiphertext {
            view_tag: sender_view_tag,
            data: blob.ciphertext.clone(),
        }],
        nullifiers: vec![first_nullifier],
    });
    world.sent_counts.insert(owner.clone(), tx_count + 1);
    world.owned_utxos.entry(owner).or_default().extend(outputs);
    world.spent_utxos.push(input);
}

#[when(expr = "a fresh wallet for {string} is synced from the recorded transactions")]
fn sync_fresh_wallet(world: &mut TransactionWorld, name: String) {
    let mut wallet = Wallet::new(world.fresh_keypair(&name)).unwrap();
    let report = wallet
        .sync(
            &world.sync_transactions,
            &[],
            &AssetRegistry::default(),
            1_700_000_000,
            8,
        )
        .unwrap();
    assert_eq!(report.unparsed_transactions, 0);
    assert_eq!(report.undecryptable_candidates, 0);
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
    let balances = wallet.balances(&AssetRegistry::default(), false).unwrap();
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
