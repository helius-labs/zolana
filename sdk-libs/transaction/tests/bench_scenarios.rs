mod common;

use std::time::{Duration, Instant};

use common::{
    build_transfer, keypair_from_index, local_authority, unique31, unique_nullifier, wallet_for,
    TransferSpec,
};
use zolana_keypair::{viewing_key::ViewTag, ShieldedKeypair};
use zolana_transaction::{
    serialization::split::{Split, SplitEncode},
    Address, AssetRegistry, Data, OutputContext, OutputSlot, OwnerCx, ShieldedTransaction,
    SyncReport, Utxo, UtxoSerialization, Wallet, DEFAULT_TAG_WINDOW, SOL_MINT,
};

const KNOWN_SENDERS: usize = 100;
const KNOWN_RECIPIENTS: usize = 50;
const BOOTSTRAP_RECEIVES: u64 = KNOWN_SENDERS as u64;
const REQUEST_RECEIVES: u64 = 400;
const TOP_PAIR_SHARED_RECEIVES: [u64; 5] = [450, 400, 300, 200, 150];
const TAIL_PAIR_SHARED_RECEIVES: u64 = 10;
const TOP_RECIPIENT_SENDS: [u64; 5] = [500, 450, 400, 350, 300];
const TAIL_RECIPIENT_SENDS: u64 = 106;
const SPLIT_COUNT: u64 = 200;
const SPLIT_OUTPUTS: u8 = 8;
const RECEIVE_AMOUNT: u64 = 800;
const SEND_AMOUNT: u64 = 1_000;
const FUNDING_AMOUNT: u64 = 100_000_000;
const SKIP_PERIOD: u64 = 7;
const MAX_SKIP: u64 = 5;
const MIN_SYNC_TIME: Duration = Duration::from_millis(8_600);
const MAX_SYNC_TIME: Duration = Duration::from_millis(9_600);
#[cfg(feature = "parallel")]
const MIN_PARALLEL_SYNC_TIME: Duration = Duration::from_millis(700);
#[cfg(feature = "parallel")]
const MAX_PARALLEL_SYNC_TIME: Duration = Duration::from_millis(950);

fn slot(view_tag: ViewTag, hash: [u8; 32], payload: Vec<u8>) -> OutputSlot {
    OutputSlot {
        view_tag,
        output_context: OutputContext {
            hash,
            tree: Address::new_from_array([0u8; 32]),
            leaf_index: 0,
        },
        payload,
    }
}

fn shared_receives_for(sender: usize) -> u64 {
    TOP_PAIR_SHARED_RECEIVES
        .get(sender)
        .copied()
        .unwrap_or(TAIL_PAIR_SHARED_RECEIVES)
}

fn sends_for(recipient: usize) -> u64 {
    TOP_RECIPIENT_SENDS
        .get(recipient)
        .copied()
        .unwrap_or(TAIL_RECIPIENT_SENDS)
}

fn skip_for(n: u64) -> u64 {
    if n.is_multiple_of(SKIP_PERIOD) {
        n % (MAX_SKIP + 1)
    } else {
        0
    }
}

fn total_shared_receives() -> u64 {
    (0..KNOWN_SENDERS).map(shared_receives_for).sum()
}

fn total_sends() -> u64 {
    (0..KNOWN_RECIPIENTS).map(sends_for).sum()
}

struct Scenario {
    alice: ShieldedKeypair,
    senders: Vec<ShieldedKeypair>,
    sender_tx_counts: Vec<u64>,
    recipients: Vec<ShieldedKeypair>,
    assets: AssetRegistry,
    txs: Vec<ShieldedTransaction>,
    counter: u64,
    hot: Option<Utxo>,
    split_inputs: Vec<Utxo>,
    tx_next: u64,
    tx_max: u64,
    request_next: u64,
    request_max: u64,
}

impl Scenario {
    fn new() -> Self {
        Self {
            alice: keypair_from_index(0),
            senders: (1..=KNOWN_SENDERS as u16).map(keypair_from_index).collect(),
            sender_tx_counts: vec![0; KNOWN_SENDERS],
            recipients: (201..=200 + KNOWN_RECIPIENTS as u16)
                .map(keypair_from_index)
                .collect(),
            assets: AssetRegistry::default(),
            txs: Vec::new(),
            counter: 0,
            hot: None,
            split_inputs: Vec::new(),
            tx_next: 0,
            tx_max: 0,
            request_next: 0,
            request_max: 0,
        }
    }

    fn receive(&mut self, sender_idx: usize, amount: u64, slot_tag: ViewTag) -> Utxo {
        let first_nullifier = unique_nullifier(&mut self.counter);
        let blinding = unique31(&mut self.counter, 0xBB);
        let blinding_seed = unique31(&mut self.counter, 0xCC);
        let count = self
            .sender_tx_counts
            .get_mut(sender_idx)
            .expect("sender index");
        let tx_count = *count;
        *count += 1;
        let sender = self.senders.get(sender_idx).expect("sender index");
        let sender_view_tag = sender.get_sender_view_tag(tx_count).unwrap();
        let (tx, utxo, _) = build_transfer(
            &self.assets,
            TransferSpec {
                sender,
                recipient: &self.alice,
                amount,
                slot_tag,
                sender_view_tag,
                first_nullifier,
                change_amount: 0,
                blinding,
                blinding_seed,
            },
        );
        self.txs.push(tx);
        utxo
    }

    fn receive_bootstrap(&mut self) {
        let bootstrap = self.alice.recipient_bootstrap_view_tag();
        for s in 0..KNOWN_SENDERS {
            let amount = if s == 0 {
                FUNDING_AMOUNT
            } else {
                RECEIVE_AMOUNT
            };
            let utxo = self.receive(s, amount, bootstrap);
            if s == 0 {
                self.hot = Some(utxo);
            } else {
                self.split_inputs.push(utxo);
            }
        }
    }

    fn receive_requests(&mut self) {
        for i in 0..REQUEST_RECEIVES {
            let idx = self.request_next + skip_for(i);
            self.request_next = idx + 1;
            self.request_max = idx;
            let tag = self.alice.get_recipient_request_view_tag(idx).unwrap();
            let sender_idx = (i % KNOWN_SENDERS as u64) as usize;
            let utxo = self.receive(sender_idx, RECEIVE_AMOUNT, tag);
            self.split_inputs.push(utxo);
        }
    }

    fn receive_shared(&mut self) {
        for s in 0..KNOWN_SENDERS {
            let mut next = 0u64;
            for j in 0..shared_receives_for(s) {
                let idx = next + skip_for(j);
                next = idx + 1;
                let tag = self
                    .senders
                    .get(s)
                    .expect("sender index")
                    .get_send_shared_view_tag(&self.alice.viewing_pubkey(), idx)
                    .unwrap();
                let utxo = self.receive(s, RECEIVE_AMOUNT, tag);
                self.split_inputs.push(utxo);
            }
        }
    }

    fn send(&mut self, recipient_idx: usize, ordinal: u64, nth: u64, shared_next: &mut u64) {
        let input = self.hot.take().expect("hot utxo");
        let nullifier_pk = self.alice.nullifier_key.pubkey().unwrap();
        let hash = input.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32]).unwrap();
        let first_nullifier = input.nullifier(&hash, &self.alice.nullifier_key).unwrap();
        let tx_idx = self.tx_next + skip_for(ordinal);
        self.tx_next = tx_idx + 1;
        self.tx_max = tx_idx;
        let sender_view_tag = self.alice.get_sender_view_tag(tx_idx).unwrap();
        let recipient = self.recipients.get(recipient_idx).expect("recipient index");
        let slot_tag = if nth == 0 {
            recipient.recipient_bootstrap_view_tag()
        } else {
            let idx = *shared_next + skip_for(nth);
            *shared_next = idx + 1;
            self.alice
                .get_send_shared_view_tag(&recipient.viewing_pubkey(), idx)
                .unwrap()
        };
        let blinding = unique31(&mut self.counter, 0xBB);
        let blinding_seed = unique31(&mut self.counter, 0xCC);
        let (tx, _, change) = build_transfer(
            &self.assets,
            TransferSpec {
                sender: &self.alice,
                recipient,
                amount: SEND_AMOUNT,
                slot_tag,
                sender_view_tag,
                first_nullifier,
                change_amount: input.amount - SEND_AMOUNT,
                blinding,
                blinding_seed,
            },
        );
        self.txs.push(tx);
        self.hot = change.into_iter().next();
    }

    fn send_all(&mut self) {
        let mut ordinal = 0u64;
        for r in 0..KNOWN_RECIPIENTS {
            let mut shared_next = 0u64;
            for nth in 0..sends_for(r) {
                self.send(r, ordinal, nth, &mut shared_next);
                ordinal += 1;
            }
        }
    }

    fn split_all(&mut self) {
        for k in 0..SPLIT_COUNT {
            let input = self.split_inputs.pop().expect("split input");
            let nullifier_pk = self.alice.nullifier_key.pubkey().unwrap();
            let hash = input.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32]).unwrap();
            let first_nullifier = input.nullifier(&hash, &self.alice.nullifier_key).unwrap();
            let tx_idx = self.tx_next + skip_for(total_sends() + k);
            self.tx_next = tx_idx + 1;
            self.tx_max = tx_idx;
            let sender_view_tag = self.alice.get_sender_view_tag(tx_idx).unwrap();

            let tx_key = self
                .alice
                .viewing_key
                .get_transaction_viewing_key(&first_nullifier)
                .unwrap();
            let tx_viewing_pk = tx_key.pubkey();
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&first_nullifier[..16]);
            let blinding_seed = unique31(&mut self.counter, 0xCC);
            let asset_amount = input.amount / u64::from(SPLIT_OUTPUTS);

            let outputs: Vec<Utxo> = (0..SPLIT_OUTPUTS)
                .map(|i| Utxo {
                    owner: self.alice.signing_pubkey(),
                    asset: SOL_MINT,
                    amount: asset_amount,
                    blinding: zolana_transaction::derive_blinding(&blinding_seed, i),
                    zone_program_id: None,
                    data: Data::default(),
                })
                .collect();

            let owner_cx = OwnerCx {
                owner: self.alice.signing_pubkey(),
                assets: &self.assets,
                zone_program_id: None,
            };
            let cx = SplitEncode {
                tx: tx_key,
                recipient_pubkey: self.alice.viewing_pubkey(),
                salt,
                slot_index: 0,
                blinding_seed,
            };
            let ciphertext = Split::encode(&outputs, &owner_cx, sender_view_tag, &cx).unwrap();

            let mut output_slots = vec![slot(sender_view_tag, [0u8; 32], ciphertext.data)];
            for output in &outputs {
                let output_hash = output.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32]).unwrap();
                output_slots.push(slot(sender_view_tag, output_hash, Vec::new()));
            }

            self.txs.push(ShieldedTransaction {
                slot: 0,
                tx_signature: solana_signature::Signature::default(),
                tx_viewing_pk: Some(tx_viewing_pk),
                salt: Some(salt),
                output_slots,
                nullifiers: vec![first_nullifier],
                proofless: false,
            });
        }
    }
}

fn build_scenario() -> Scenario {
    let mut scenario = Scenario::new();
    scenario.receive_bootstrap();
    scenario.receive_requests();
    scenario.receive_shared();
    scenario.send_all();
    scenario.split_all();
    scenario
}

fn verify_sync(scenario: &Scenario, wallet: &Wallet, report: &SyncReport) {
    let own_transactions = BOOTSTRAP_RECEIVES
        + REQUEST_RECEIVES
        + total_shared_receives()
        + total_sends()
        + SPLIT_COUNT;
    assert_eq!(scenario.txs.len() as u64, own_transactions);
    assert_eq!(report.unparsed_transactions, 0);
    assert_eq!(report.undecryptable_candidates, 0);

    let receives = BOOTSTRAP_RECEIVES + REQUEST_RECEIVES + total_shared_receives();
    let stored = receives + total_sends() + SPLIT_COUNT * u64::from(SPLIT_OUTPUTS);
    assert_eq!(wallet.utxos.len() as u64, stored);
    assert_eq!(report.stored_utxos as u64, stored);
    let spent = total_sends() + SPLIT_COUNT;
    assert_eq!(
        wallet.utxos.iter().filter(|u| u.spent).count() as u64,
        spent
    );

    let entry = wallet
        .viewing_key_history
        .last()
        .expect("viewing key entry");
    assert_eq!(entry.tx_count, scenario.tx_max + 1);
    assert_eq!(entry.request_count, scenario.request_max + 1);
    assert_eq!(entry.known_senders.len(), KNOWN_SENDERS);
    assert_eq!(entry.known_recipients.len(), KNOWN_RECIPIENTS);
}

#[test]
#[ignore]
fn defi_trader_full_sync() {
    let scenario = build_scenario();
    let keypair = keypair_from_index(0);
    let mut wallet = wallet_for(&keypair, scenario.assets.clone());
    let started = Instant::now();
    let report = wallet
        .sync(
            &local_authority(&keypair),
            &scenario.txs,
            1i64,
            DEFAULT_TAG_WINDOW,
        )
        .unwrap();
    let elapsed = started.elapsed();

    verify_sync(&scenario, &wallet, &report);
    println!(
        "defi trader full sync: {} transactions, {} utxos, window {}: {:?}",
        scenario.txs.len(),
        wallet.utxos.len(),
        DEFAULT_TAG_WINDOW,
        elapsed
    );
    assert!(
        elapsed >= MIN_SYNC_TIME && elapsed <= MAX_SYNC_TIME,
        "full sync took {:?}, expected within {:?}..{:?}",
        elapsed,
        MIN_SYNC_TIME,
        MAX_SYNC_TIME
    );
}

#[cfg(feature = "parallel")]
#[test]
#[ignore]
fn defi_trader_full_sync_parallel() {
    let scenario = build_scenario();
    let keypair = keypair_from_index(0);
    let mut wallet = wallet_for(&keypair, scenario.assets.clone());
    let started = Instant::now();
    let report = wallet
        .sync_parallel(
            &local_authority(&keypair),
            &scenario.txs,
            1,
            DEFAULT_TAG_WINDOW,
        )
        .unwrap();
    let elapsed = started.elapsed();

    verify_sync(&scenario, &wallet, &report);
    println!(
        "defi trader full sync_parallel: {} transactions, {} utxos, window {}: {:?}",
        scenario.txs.len(),
        wallet.utxos.len(),
        DEFAULT_TAG_WINDOW,
        elapsed
    );
    assert!(
        elapsed >= MIN_PARALLEL_SYNC_TIME && elapsed <= MAX_PARALLEL_SYNC_TIME,
        "parallel full sync took {:?}, expected within {:?}..{:?}",
        elapsed,
        MIN_PARALLEL_SYNC_TIME,
        MAX_PARALLEL_SYNC_TIME
    );
}
