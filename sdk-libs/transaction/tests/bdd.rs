mod steps;

use std::collections::HashMap;

use cucumber::World;
use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::split::{SplitBundlePlaintext, SplitEncryptedUtxos};
use zolana_transaction::test_wallet::TestWallet;
use zolana_transaction::transfer::{
    RecipientOutput, TransferEncryptedUtxos, TransferSenderPlaintext,
};
use zolana_transaction::utxo::Utxo;
use zolana_transaction::wallet::SyncTransaction;

#[derive(Default, World)]
pub struct TransactionWorld {
    pub keypairs: HashMap<String, ShieldedKeypair>,
    pub sender_name: Option<String>,
    pub recipient_names: Vec<String>,
    pub recipients: Vec<RecipientOutput>,
    pub sender_plaintext: Option<TransferSenderPlaintext>,
    pub transfer_blob: Option<TransferEncryptedUtxos>,
    pub split_bundle: Option<SplitBundlePlaintext>,
    pub split_blob: Option<SplitEncryptedUtxos>,
    pub first_nullifier: [u8; 32],
    pub sync_transactions: Vec<SyncTransaction>,
    pub owned_utxos: HashMap<String, Vec<Utxo>>,
    pub spent_utxos: Vec<Utxo>,
    pub sent_counts: HashMap<String, u64>,
    pub wallet: Option<TestWallet>,
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
