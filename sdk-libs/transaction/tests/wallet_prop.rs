mod common;

use std::collections::HashMap;

use common::{build_transfer, keypair_from_index, unique31, unique_nullifier, TransferSpec};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::test_wallet::TestWallet;
#[cfg(feature = "parallel")]
use zolana_transaction::wallet::SyncReport;
use zolana_transaction::wallet::SyncTransaction;
use zolana_transaction::{AssetRegistry, Utxo};

const NUM_CPS: usize = 3;
const WINDOW: u64 = 8;
const MAX_SKIP: u64 = 5;

#[derive(Debug, Clone)]
struct Step {
    action: u8,
    cp: usize,
    tag: u8,
    skip: u64,
    amount: u64,
    pick: usize,
}

fn step_strategy() -> impl Strategy<Value = Step> {
    (
        0u8..10,
        0usize..NUM_CPS,
        0u8..3,
        0u64..=MAX_SKIP,
        1u64..1_000_000,
        0usize..1 << 16,
    )
        .prop_map(|(action, cp, tag, skip, amount, pick)| Step {
            action,
            cp,
            tag,
            skip,
            amount,
            pick,
        })
}

fn small_steps() -> impl Strategy<Value = Vec<Step>> {
    prop::collection::vec(step_strategy(), 1..=64)
}

fn large_steps() -> impl Strategy<Value = Vec<Step>> {
    prop::collection::vec(step_strategy(), 500..=1000)
}

struct CpState {
    keypair: ShieldedKeypair,
    tx_count: u64,
    shared_in_next: u64,
    shared_in_max: Option<u64>,
    shared_out_next: u64,
    shared_out_max: Option<u64>,
    received_from: bool,
    sent_to: bool,
}

struct Harness {
    alice: ShieldedKeypair,
    cps: Vec<CpState>,
    assets: AssetRegistry,
    txs: Vec<SyncTransaction>,
    expected: Vec<(Utxo, bool)>,
    counter: u64,
    tx_next: u64,
    tx_max: Option<u64>,
    request_next: u64,
    request_max: Option<u64>,
}

impl Harness {
    fn new() -> Self {
        Self {
            alice: keypair_from_index(0),
            cps: (0..NUM_CPS)
                .map(|i| CpState {
                    keypair: keypair_from_index(i as u16 + 1),
                    tx_count: 0,
                    shared_in_next: 0,
                    shared_in_max: None,
                    shared_out_next: 0,
                    shared_out_max: None,
                    received_from: false,
                    sent_to: false,
                })
                .collect(),
            assets: AssetRegistry::default(),
            txs: Vec::new(),
            expected: Vec::new(),
            counter: 0,
            tx_next: 0,
            tx_max: None,
            request_next: 0,
            request_max: None,
        }
    }

    fn receive(&mut self, cp_idx: usize, tag: u8, skip: u64, amount: u64) {
        let cp_idx = cp_idx % NUM_CPS;
        let received_from = self.cps.get(cp_idx).expect("cp index").received_from;
        let slot_tag = match tag {
            2 if received_from => {
                let alice_viewing = self.alice.viewing_pubkey();
                let cp = self.cps.get_mut(cp_idx).expect("cp index");
                let idx = cp.shared_in_next + skip;
                cp.shared_in_next = idx + 1;
                cp.shared_in_max = Some(idx);
                cp.keypair
                    .get_send_shared_view_tag(&alice_viewing, idx)
                    .unwrap()
            }
            1 => {
                let idx = self.request_next + skip;
                self.request_next = idx + 1;
                self.request_max = Some(idx);
                self.alice.get_recipient_request_view_tag(idx).unwrap()
            }
            _ => self.alice.recipient_bootstrap_view_tag(),
        };
        let first_nullifier = unique_nullifier(&mut self.counter);
        let blinding = unique31(&mut self.counter, 0xBB);
        let blinding_seed = unique31(&mut self.counter, 0xCC);
        let cp = self.cps.get_mut(cp_idx).expect("cp index");
        let sender_view_tag = cp.keypair.get_sender_view_tag(cp.tx_count).unwrap();
        cp.tx_count += 1;
        cp.received_from = true;
        let (tx, recipient_utxo, _) = build_transfer(
            &self.assets,
            TransferSpec {
                sender: &cp.keypair,
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
        self.expected.push((recipient_utxo, false));
    }

    fn send(&mut self, cp_idx: usize, skip: u64, amount_seed: u64, pick: usize) -> bool {
        let cp_idx = cp_idx % NUM_CPS;
        let unspent: Vec<usize> = self
            .expected
            .iter()
            .enumerate()
            .filter(|(_, (_, spent))| !spent)
            .map(|(i, _)| i)
            .collect();
        let Some(&chosen) = unspent.get(pick % unspent.len().max(1)) else {
            return false;
        };
        let input = self.expected.get(chosen).expect("input utxo").0.clone();
        let amount = amount_seed % input.amount + 1;
        let change_amount = input.amount - amount;

        let nullifier_pk = self.alice.nullifier_key.pubkey().unwrap();
        let input_hash = input.hash(&nullifier_pk, &[0u8; 32], &[0u8; 32]).unwrap();
        let first_nullifier = input
            .nullifier(&input_hash, &self.alice.nullifier_key)
            .unwrap();

        let tx_idx = self.tx_next + skip;
        self.tx_next = tx_idx + 1;
        self.tx_max = Some(tx_idx);
        let sender_view_tag = self.alice.get_sender_view_tag(tx_idx).unwrap();

        let blinding = unique31(&mut self.counter, 0xBB);
        let blinding_seed = unique31(&mut self.counter, 0xCC);
        let cp = self.cps.get_mut(cp_idx).expect("cp index");
        let slot_tag = if cp.sent_to {
            let idx = cp.shared_out_next + skip;
            cp.shared_out_next = idx + 1;
            cp.shared_out_max = Some(idx);
            self.alice
                .get_send_shared_view_tag(&cp.keypair.viewing_pubkey(), idx)
                .unwrap()
        } else {
            cp.keypair.recipient_bootstrap_view_tag()
        };
        cp.sent_to = true;
        let (tx, _, change) = build_transfer(
            &self.assets,
            TransferSpec {
                sender: &self.alice,
                recipient: &cp.keypair,
                amount,
                slot_tag,
                sender_view_tag,
                first_nullifier,
                change_amount,
                blinding,
                blinding_seed,
            },
        );
        self.txs.push(tx);
        if let Some(entry) = self.expected.get_mut(chosen) {
            entry.1 = true;
        }
        for utxo in change {
            self.expected.push((utxo, false));
        }
        true
    }

    fn noise(&mut self, cp_idx: usize, amount: u64) {
        let a = cp_idx % NUM_CPS;
        let b = (cp_idx + 1) % NUM_CPS;
        let first_nullifier = unique_nullifier(&mut self.counter);
        let blinding = unique31(&mut self.counter, 0xBB);
        let blinding_seed = unique31(&mut self.counter, 0xCC);
        let slot_tag = self
            .cps
            .get(b)
            .expect("cp index")
            .keypair
            .recipient_bootstrap_view_tag();
        let sender_view_tag = {
            let cp = self.cps.get_mut(a).expect("cp index");
            let tag = cp.keypair.get_sender_view_tag(cp.tx_count).unwrap();
            cp.tx_count += 1;
            tag
        };
        let sender = &self.cps.get(a).expect("cp index").keypair;
        let recipient = &self.cps.get(b).expect("cp index").keypair;
        let (tx, _, _) = build_transfer(
            &self.assets,
            TransferSpec {
                sender,
                recipient,
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
    }

    fn apply(&mut self, step: &Step) {
        match step.action {
            0..=4 => self.receive(step.cp, step.tag, step.skip, step.amount),
            5..=8 => {
                if !self.send(step.cp, step.skip, step.amount, step.pick) {
                    self.receive(step.cp, step.tag, step.skip, step.amount);
                }
            }
            _ => self.noise(step.cp, step.amount),
        }
    }

    fn check(&self, at: i64) -> Result<(), TestCaseError> {
        let signing = SigningKey::from_bytes(&self.alice.signing_key.secret_bytes()).unwrap();
        let viewing = ViewingKey::from_bytes(&self.alice.viewing_key.secret_bytes()).unwrap();
        let keypair = ShieldedKeypair::from_keys(signing, viewing).unwrap();
        let mut wallet = TestWallet::new(keypair).unwrap();
        let report = wallet.sync(&self.txs, &self.assets, at, WINDOW).unwrap();
        prop_assert_eq!(report.unparsed_transactions, 0);
        prop_assert_eq!(report.undecryptable_candidates, 0);
        prop_assert_eq!(wallet.last_synced, at);

        let mut actual: Vec<(Utxo, bool)> = wallet
            .utxos
            .iter()
            .map(|w| (w.utxo.clone(), w.spent))
            .collect();
        actual.sort_by_key(|(utxo, _)| utxo.blinding);
        let mut expected = self.expected.clone();
        expected.sort_by_key(|(utxo, _)| utxo.blinding);
        prop_assert_eq!(actual, expected);

        let entry = wallet
            .viewing_key_history
            .last()
            .expect("viewing key entry");
        prop_assert_eq!(entry.tx_count, self.tx_max.map_or(0, |m| m + 1));
        prop_assert_eq!(entry.request_count, self.request_max.map_or(0, |m| m + 1));

        let mut known_senders = HashMap::new();
        let mut known_recipients = HashMap::new();
        for cp in &self.cps {
            if cp.received_from {
                known_senders.insert(
                    cp.keypair.viewing_pubkey(),
                    cp.shared_in_max.map_or(0, |m| m + 1),
                );
            }
            if cp.sent_to {
                known_recipients.insert(
                    cp.keypair.viewing_pubkey(),
                    cp.shared_out_max.map_or(0, |m| m + 1),
                );
            }
        }
        prop_assert_eq!(&entry.known_senders, &known_senders);
        prop_assert_eq!(&entry.known_recipients, &known_recipients);

        let balances = wallet.balances(&self.assets, true).unwrap();
        let expected_total: u64 = self
            .expected
            .iter()
            .filter(|(_, spent)| !spent)
            .map(|(utxo, _)| utxo.amount)
            .sum();
        if expected_total > 0 {
            prop_assert_eq!(balances.len(), 1);
            prop_assert_eq!(balances.first().map(|b| b.amount), Some(expected_total));
        } else {
            prop_assert!(balances.is_empty());
        }

        #[cfg(feature = "parallel")]
        self.check_parallel(&wallet, &report, at)?;
        Ok(())
    }

    #[cfg(feature = "parallel")]
    fn check_parallel(
        &self,
        sequential: &TestWallet,
        report: &SyncReport,
        at: i64,
    ) -> Result<(), TestCaseError> {
        let signing = SigningKey::from_bytes(&self.alice.signing_key.secret_bytes()).unwrap();
        let viewing = ViewingKey::from_bytes(&self.alice.viewing_key.secret_bytes()).unwrap();
        let keypair = ShieldedKeypair::from_keys(signing, viewing).unwrap();
        let mut wallet = TestWallet::new(keypair).unwrap();
        let parallel_report = wallet
            .sync_parallel(&self.txs, &self.assets, at, WINDOW)
            .unwrap();
        prop_assert_eq!(&parallel_report, report);
        prop_assert_eq!(wallet.last_synced, sequential.last_synced);

        let mut actual = wallet.utxos.clone();
        actual.sort_by_key(|u| u.hash);
        let mut expected = sequential.utxos.clone();
        expected.sort_by_key(|u| u.hash);
        prop_assert_eq!(actual, expected);

        prop_assert_eq!(
            wallet.viewing_key_history.len(),
            sequential.viewing_key_history.len()
        );
        for (parallel_entry, sequential_entry) in wallet
            .viewing_key_history
            .iter()
            .zip(sequential.viewing_key_history.iter())
        {
            prop_assert_eq!(parallel_entry.tx_count, sequential_entry.tx_count);
            prop_assert_eq!(parallel_entry.request_count, sequential_entry.request_count);
            prop_assert_eq!(
                &parallel_entry.known_senders,
                &sequential_entry.known_senders
            );
            prop_assert_eq!(
                &parallel_entry.known_recipients,
                &sequential_entry.known_recipients
            );
        }
        Ok(())
    }
}

fn run(steps: &[Step]) -> Result<(), TestCaseError> {
    let mut harness = Harness::new();
    for (i, step) in steps.iter().enumerate() {
        harness.apply(step);
        harness.check(i as i64 + 1)?;
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 6,
        max_shrink_iters: 256,
        .. ProptestConfig::default()
    })]
    #[test]
    fn first_time_sync_tracks_every_transfer(steps in small_steps()) {
        run(&steps)?;
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 1,
        max_shrink_iters: 16,
        .. ProptestConfig::default()
    })]
    #[test]
    #[ignore]
    fn first_time_sync_soak_up_to_1000(steps in large_steps()) {
        run(&steps)?;
    }
}
