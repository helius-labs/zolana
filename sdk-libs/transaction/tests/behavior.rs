mod cases;

use std::collections::HashMap;

use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::{
    serialization::{
        anonymous::{AnonymousTransferRecipientPlaintext, AnonymousTransferSenderPlaintext},
        plaintext::TransferPlaintextUtxos,
        split::SplitBundlePlaintext,
    },
    utxo::Utxo,
    wallet::Wallet,
    ShieldedTransaction,
};

#[derive(Default)]
pub struct TransactionWorld {
    pub keypairs: HashMap<String, ShieldedKeypair>,
    pub sender_name: Option<String>,
    pub recipient_names: Vec<String>,
    pub recipient_plaintexts: Vec<AnonymousTransferRecipientPlaintext>,
    pub sender_plaintext: Option<AnonymousTransferSenderPlaintext>,
    pub transfer_tx: Option<ShieldedTransaction>,
    pub split_bundle: Option<SplitBundlePlaintext>,
    pub split_tx: Option<ShieldedTransaction>,
    pub plaintext_transfer: Option<TransferPlaintextUtxos>,
    pub sync_transactions: Vec<ShieldedTransaction>,
    pub owned_utxos: HashMap<String, Vec<Utxo>>,
    pub spent_utxos: Vec<Utxo>,
    pub sent_counts: HashMap<String, u64>,
    pub wallet: Option<Wallet>,
    pub wallet_name: Option<String>,
}

impl TransactionWorld {
    pub fn kp(&self, name: &str) -> &ShieldedKeypair {
        self.keypairs.get(name).expect("shielded keypair not set")
    }

    pub fn sender(&self) -> &ShieldedKeypair {
        let name = self.sender_name.as_ref().expect("sender not set");
        self.kp(name)
    }

    pub fn slot_of(&self, name: &str) -> usize {
        self.recipient_names
            .iter()
            .position(|candidate| candidate == name)
            .expect("recipient not present")
    }

    pub fn fresh_keypair(&self, name: &str) -> ShieldedKeypair {
        let keypair = self.kp(name);
        let signing = SigningKey::from_p256_bytes(&keypair.signing_key.secret_bytes())
            .expect("signing key round-trip");
        let viewing = ViewingKey::from_bytes(&keypair.viewing_key.secret_bytes())
            .expect("viewing key round-trip");
        ShieldedKeypair::with_viewing_key(signing, viewing).expect("keypair rebuild")
    }
}

fn add_keypairs(world: &mut TransactionWorld, names: &[&str]) {
    for name in names {
        cases::common::shielded_keypair(world, (*name).to_string());
    }
}

#[test]
fn asset_registry_and_blinding_rules_are_explicit() {
    cases::asset::sol_resolves();
    cases::asset::spl_resolves_both_ways();
    cases::asset::unknown_asset_id();
    cases::asset::unknown_mint();
    cases::asset::sol_reserved();
    cases::asset::duplicate_asset_id();
    cases::asset::duplicate_mint();
    cases::blinding::blindings_deterministic();
    cases::blinding::blinding_top_byte_dropped();
}

#[test]
fn merge_recovery_derivations_match_circuit_vectors() {
    cases::merge_derivation::recovery_domains_are_the_ascii_tags();
    cases::merge_derivation::recovery_derivations_match_circuit_vectors();
    cases::merge_derivation::recovery_derivations_match_shared_vectors();
    cases::merge_derivation::recovery_derivations_bind_every_input();
    cases::merge_derivation::recovery_derivations_are_deterministic();
}

#[test]
fn a_remote_keypair_backend_is_a_wallet_authority() {
    cases::remote_authority::remote_backend_publishes_the_same_identity();
    cases::remote_authority::remote_backend_signs_through_the_trait();
    cases::remote_authority::remote_backend_encrypts_with_the_same_transaction_key();
    cases::remote_authority::historical_viewing_keys_are_carried_through();
    cases::remote_authority::viewing_keys_must_contain_the_keypairs_own();
    cases::remote_authority::derivation_shaped_payloads_are_refused_before_signing();
}

#[test]
fn plaintext_transfers_are_canonical_and_indexed_by_owner() {
    let mut world = TransactionWorld::default();
    add_keypairs(&mut world, &["alice", "bob", "carol"]);
    cases::plaintext_transfer::build(&mut world, "alice".into(), "bob".into(), "carol".into());
    cases::plaintext_transfer::round_trips(&mut world);
    cases::plaintext_transfer::sequential_blindings(&mut world);
    cases::plaintext_transfer::sender_indexed(&mut world, "alice".into());
    cases::plaintext_transfer::recipient_indexed(&mut world, 0, "bob".into());
    cases::plaintext_transfer::recipient_indexed(&mut world, 1, "carol".into());
    cases::plaintext_transfer::output_amounts(&mut world, 100, 50, 40, 10);
    cases::plaintext_transfer::rejects_bad_discriminator(&mut world);
    cases::plaintext_transfer::sender_data_without_output(&mut world, "alice".into());
    cases::plaintext_transfer::ed25519_recipient_indexed();
}

#[test]
fn serialized_payloads_round_trip_and_reject_noncanonical_data() {
    let mut world = TransactionWorld::default();
    add_keypairs(&mut world, &["alice", "sender", "owner"]);
    cases::serialization::recipient_plaintext_round_trips("alice".into());
    cases::serialization::duplicate_data_records_rejected("alice".into());
    cases::serialization::out_of_order_data_records_rejected("alice".into());
    cases::serialization::sender_plaintext_round_trips(&mut world, "sender".into(), "alice".into());
    cases::serialization::transfer_blob_round_trips();
    cases::serialization::invalid_viewing_pubkey_rejected();
    cases::serialization::split_bundle_round_trips(&mut world, "owner".into());
    cases::serialization::split_blob_round_trips();
}

#[test]
fn split_outputs_round_trip_at_regular_and_maximum_shapes() {
    let mut world = TransactionWorld::default();
    add_keypairs(&mut world, &["owner"]);
    for (count, amount) in [(4, 200), (8, 125)] {
        cases::split::build_split(&mut world, "owner".into(), count, amount);
        cases::split::split_round_trips(&mut world);
        cases::split::split_blindings(&mut world, usize::from(count));
        cases::split::split_decrypt(&mut world, "owner".into(), count, amount);
    }
    cases::split::split_data_zero_outputs(&mut world, "owner".into());
}

#[test]
fn anonymous_transfers_cover_recipient_isolation_and_program_data() {
    let mut world = TransactionWorld::default();
    add_keypairs(&mut world, &["sender", "alice", "bob"]);

    cases::transfer::build_one(&mut world, "sender".into(), 1_000, "alice".into());
    cases::transfer::blob_round_trips(&mut world);
    cases::transfer::slot_view_tag(&mut world, "alice".into());
    cases::transfer::sender_recovers(&mut world, "sender".into());
    cases::transfer::recipient_reads(&mut world, "alice".into(), 1_000);
    cases::transfer::stranger_cannot(&mut world, "alice".into());
    cases::transfer::build_two(
        &mut world,
        "sender".into(),
        1_000,
        "alice".into(),
        2_000,
        "bob".into(),
    );
    cases::transfer::blob_round_trips(&mut world);
    cases::transfer::sender_recovers(&mut world, "sender".into());
    cases::transfer::recipient_reads(&mut world, "alice".into(), 1_000);
    cases::transfer::recipient_reads(&mut world, "bob".into(), 2_000);
    cases::transfer::recipient_cannot_read_other_slot(&mut world, "alice".into(), "bob".into());

    cases::transfer::build_zero(&mut world, "sender".into());
    cases::transfer::blob_round_trips(&mut world);
    cases::transfer::sender_recovers(&mut world, "sender".into());

    cases::transfer::build_with_data(&mut world, "sender".into(), "alice".into());
    cases::transfer::sender_recovers(&mut world, "sender".into());
    cases::transfer::recover_data(&mut world, "alice".into());
}

#[test]
fn utxo_hashes_nullifiers_and_encryption_bind_all_context() {
    let mut world = TransactionWorld::default();
    add_keypairs(&mut world, &["alice", "sender", "owner"]);
    cases::utxo::utxo_hash_props(&mut world, "alice".into());
    cases::utxo::utxo_hash_nesting(&mut world, "alice".into());
    cases::utxo::utxo_nullifier(&mut world, "alice".into());
    cases::utxo_encryption::standard_transfer_round_trips(
        &mut world,
        "sender".into(),
        "alice".into(),
    );
    cases::utxo_encryption::ring_owned_with_data_round_trips(&mut world, "owner".into());
    cases::utxo_encryption::ring_data_without_id_rejected(&mut world, "owner".into());
    cases::utxo_encryption::ring_id_carried_onto_utxo(&mut world, "owner".into());
    cases::utxo_encryption::data_without_output_rejected(&mut world, "owner".into());
    cases::utxo_encryption::split_round_trips(&mut world, "owner".into());
}

#[test]
fn wallet_sync_restores_contacts_counters_spends_and_history() {
    let mut world = TransactionWorld::default();
    add_keypairs(&mut world, &["alice", "bob", "carol"]);
    cases::wallet::bootstrap_transfer(&mut world, 40, "bob".into(), "alice".into());
    cases::wallet::spending_transfer(&mut world, 25, "alice".into(), "carol".into());
    cases::wallet::shared_transfer(&mut world, 10, "bob".into(), "alice".into(), 0);
    cases::wallet::sync_fresh_wallet(&mut world, "alice".into());
    cases::wallet::wallet_holds(&mut world, 3, 1);
    cases::wallet::unspent_sol_balance(&mut world, 25);
    cases::wallet::wallet_counts(&mut world, 1, 0);
    cases::wallet::knows_sender(&mut world, "bob".into(), 1);
    cases::wallet::knows_recipient(&mut world, "carol".into(), 0);
    cases::wallet::private_tx_count(&mut world, 3);
    cases::wallet::inbound_from(&mut world, 40, "bob".into());
    cases::wallet::outbound_to(&mut world, 25, "carol".into());
    cases::wallet::inbound_from(&mut world, 10, "bob".into());
}

/// The anonymous rail classifies a send whose only recipient is the sender as a
/// self transfer, matching the confidential rail. Both the sender-bundle row and
/// the recipient receipt say `SelfTransfer`, so no row contradicts the other.
#[test]
fn wallet_sync_classifies_an_anonymous_send_to_self() {
    let mut world = TransactionWorld::default();
    add_keypairs(&mut world, &["alice", "bob"]);
    cases::wallet::bootstrap_transfer(&mut world, 40, "bob".into(), "alice".into());
    cases::wallet::spending_transfer(&mut world, 25, "alice".into(), "alice".into());
    cases::wallet::sync_fresh_wallet(&mut world, "alice".into());
    cases::wallet::self_transfer_recorded(&mut world, 25);
    #[cfg(feature = "parallel")]
    cases::wallet::parallel_scan_agrees(&mut world);
}

#[test]
fn wallet_sync_restores_split_and_payment_request_history() {
    let mut world = TransactionWorld::default();
    add_keypairs(&mut world, &["alice", "bob", "carol"]);
    cases::wallet::bootstrap_transfer(&mut world, 40, "bob".into(), "alice".into());
    cases::wallet::recorded_split(&mut world, "alice".into(), 4);
    cases::wallet::request_transfer(&mut world, 5, "carol".into(), "alice".into(), 0);
    cases::wallet::sync_fresh_wallet(&mut world, "alice".into());
    cases::wallet::wallet_holds(&mut world, 6, 1);
    cases::wallet::unspent_sol_balance(&mut world, 45);
    cases::wallet::wallet_counts(&mut world, 1, 1);
    cases::wallet::knows_sender(&mut world, "carol".into(), 0);
    cases::wallet::private_tx_count(&mut world, 3);
    cases::wallet::inbound_from(&mut world, 40, "bob".into());
    cases::wallet::split_recorded(&mut world, 40);
    cases::wallet::inbound_from(&mut world, 5, "carol".into());
}
