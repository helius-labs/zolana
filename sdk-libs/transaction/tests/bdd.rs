mod steps;

use std::collections::HashMap;

use cucumber::World;
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

#[derive(Default, World)]
pub struct TransactionWorld {
    pub keypairs: HashMap<String, ShieldedKeypair>,
    pub sender_name: Option<String>,
    pub recipient_names: Vec<String>,
    pub recipient_plaintexts: Vec<AnonymousTransferRecipientPlaintext>,
    pub recipient_utxos: Vec<Utxo>,
    pub sender_plaintext: Option<AnonymousTransferSenderPlaintext>,
    pub transfer_tx: Option<ShieldedTransaction>,
    pub split_bundle: Option<SplitBundlePlaintext>,
    pub split_tx: Option<ShieldedTransaction>,
    pub plaintext_transfer: Option<TransferPlaintextUtxos>,
    pub first_nullifier: [u8; 32],
    pub sync_transactions: Vec<ShieldedTransaction>,
    pub owned_utxos: HashMap<String, Vec<Utxo>>,
    pub spent_utxos: Vec<Utxo>,
    pub sent_counts: HashMap<String, u64>,
    pub wallet: Option<Wallet>,
    pub wallet_name: Option<String>,
}

impl std::fmt::Debug for TransactionWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TransactionWorld")
    }
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
            .position(|n| n == name)
            .expect("recipient not present")
    }

    pub fn fresh_keypair(&self, name: &str) -> ShieldedKeypair {
        let kp = self.kp(name);
        let signing =
            SigningKey::from_bytes(&kp.signing_key.secret_bytes()).expect("signing key round-trip");
        let viewing =
            ViewingKey::from_bytes(&kp.viewing_key.secret_bytes()).expect("viewing key round-trip");
        ShieldedKeypair::from_keys(signing, viewing).expect("keypair rebuild")
    }
}

#[tokio::main]
async fn main() {
    TransactionWorld::cucumber()
        .fail_on_skipped()
        .run_and_exit("tests/features")
        .await;
}
