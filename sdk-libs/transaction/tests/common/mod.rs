use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::viewing_key::ViewTag;
use zolana_keypair::{ShieldedKeypair, SigningKey, ViewingKey};
use zolana_transaction::transfer::{RecipientOutput, TransferSenderPlaintext};
use zolana_transaction::wallet::SyncTransaction;
use zolana_transaction::{AssetRegistry, Data, TransactionEncryption, Utxo, SOL_MINT};

pub fn keypair_from_index(index: u16) -> ShieldedKeypair {
    let mut signing_bytes = [0u8; 32];
    signing_bytes[0] = 0x10;
    signing_bytes[1..3].copy_from_slice(&index.to_be_bytes());
    let mut viewing_bytes = [0u8; 32];
    viewing_bytes[0] = 0x20;
    viewing_bytes[1..3].copy_from_slice(&index.to_be_bytes());
    let signing = SigningKey::from_bytes(&signing_bytes).unwrap();
    let viewing = ViewingKey::from_bytes(&viewing_bytes).unwrap();
    ShieldedKeypair::from_keys(signing, viewing).unwrap()
}

pub fn unique31(counter: &mut u64, prefix: u8) -> [u8; BLINDING_LEN] {
    *counter += 1;
    let mut out = [0u8; BLINDING_LEN];
    out[0] = prefix;
    out[1..9].copy_from_slice(&counter.to_be_bytes());
    out
}

pub fn unique_nullifier(counter: &mut u64) -> [u8; 32] {
    *counter += 1;
    let mut out = [0u8; 32];
    out[0] = 0xAA;
    out[1..9].copy_from_slice(&counter.to_be_bytes());
    out
}

pub struct TransferSpec<'a> {
    pub sender: &'a ShieldedKeypair,
    pub recipient: &'a ShieldedKeypair,
    pub amount: u64,
    pub slot_tag: ViewTag,
    pub sender_view_tag: ViewTag,
    pub first_nullifier: [u8; 32],
    pub change_amount: u64,
    pub blinding: [u8; BLINDING_LEN],
    pub blinding_seed: [u8; BLINDING_LEN],
}

pub fn build_transfer(
    assets: &AssetRegistry,
    spec: TransferSpec<'_>,
) -> (SyncTransaction, Utxo, Vec<Utxo>) {
    let recipient_utxo = Utxo {
        owner: spec.recipient.signing_pubkey(),
        asset: SOL_MINT,
        amount: spec.amount,
        blinding: spec.blinding,
        zone_program_id: None,
        data: Data::default(),
    };
    let recipient_plaintext = recipient_utxo
        .to_recipient_plaintext(spec.sender.viewing_pubkey(), assets)
        .unwrap();
    let sender_plaintext = TransferSenderPlaintext {
        owner_pubkey: spec.sender.signing_pubkey(),
        spl_asset_id: 0,
        spl_amount: 0,
        sol_amount: spec.change_amount,
        blinding_seed: spec.blinding_seed,
        recipient_viewing_pks: vec![spec.recipient.viewing_pubkey()],
        spl_data: Data::default(),
        sol_data: Data::default(),
    };
    let change = sender_plaintext.clone().into_utxos(assets, None).unwrap();
    let blob = spec
        .sender
        .viewing_key
        .encrypt_transfer(
            &spec.first_nullifier,
            &sender_plaintext,
            &[RecipientOutput {
                view_tag: spec.slot_tag,
                plaintext: recipient_plaintext,
            }],
        )
        .unwrap();
    let tx = SyncTransaction {
        encrypted_utxos: blob.serialize().unwrap(),
        sender_view_tag: spec.sender_view_tag,
        nullifiers: vec![spec.first_nullifier],
    };
    (tx, recipient_utxo, change)
}

use std::ops::{Deref, DerefMut};

use zolana_interface::event::DepositView;
use zolana_keypair::P256Pubkey;
use zolana_transaction::wallet::{AssetBalance, SyncReport, Wallet, WalletKeyProvider};
use zolana_transaction::TransactionError;

struct KeypairWalletKeyProvider<'a>(&'a ShieldedKeypair);

impl WalletKeyProvider for KeypairWalletKeyProvider<'_> {
    fn signing_pubkey(&self) -> zolana_keypair::PublicKey {
        self.0.signing_pubkey()
    }

    fn nullifier_pubkey(&self) -> Result<[u8; 32], TransactionError> {
        Ok(self.0.nullifier_key.pubkey()?)
    }

    fn viewing_pubkey(&self) -> P256Pubkey {
        self.0.viewing_pubkey()
    }

    fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; BLINDING_LEN],
    ) -> Result<[u8; 32], TransactionError> {
        Ok(self.0.nullifier_key.nullifier(utxo_hash, blinding)?)
    }

    fn recipient_bootstrap_view_tag(&self) -> ViewTag {
        self.0.recipient_bootstrap_view_tag()
    }

    fn get_sender_view_tag(&self, index: u64) -> Result<ViewTag, zolana_keypair::KeypairError> {
        self.0.get_sender_view_tag(index)
    }

    fn get_recipient_request_view_tag(
        &self,
        index: u64,
    ) -> Result<ViewTag, zolana_keypair::KeypairError> {
        self.0.get_recipient_request_view_tag(index)
    }

    fn get_send_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        index: u64,
    ) -> Result<ViewTag, zolana_keypair::KeypairError> {
        self.0.get_send_shared_view_tag(counterparty, index)
    }

    fn get_recipient_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        index: u64,
    ) -> Result<ViewTag, zolana_keypair::KeypairError> {
        self.0.get_recipient_shared_view_tag(counterparty, index)
    }

    fn transaction_viewing_pubkey(
        &self,
        first_nullifier: &[u8; 32],
    ) -> Result<P256Pubkey, TransactionError> {
        Ok(self
            .0
            .get_transaction_viewing_key(first_nullifier)?
            .pubkey())
    }

    fn encrypt_transaction_slot(
        &self,
        first_nullifier: &[u8; 32],
        recipient: &P256Pubkey,
        plaintext: &[u8],
        salt: [u8; zolana_keypair::constants::SALT_LEN],
        slot: u32,
    ) -> Result<Vec<u8>, TransactionError> {
        Ok(self
            .0
            .get_transaction_viewing_key(first_nullifier)?
            .encrypt_slot(recipient, plaintext, salt, slot)?)
    }

    fn decrypt_root_slot(
        &self,
        peer: &P256Pubkey,
        ciphertext: &[u8],
        salt: [u8; zolana_keypair::constants::SALT_LEN],
        slot: u32,
    ) -> Result<Vec<u8>, TransactionError> {
        Ok(self
            .0
            .viewing_key
            .decrypt_utxo(ciphertext, peer, salt, slot)?)
    }

    fn decrypt_transaction_slot(
        &self,
        first_nullifier: &[u8; 32],
        peer: &P256Pubkey,
        ciphertext: &[u8],
        salt: [u8; zolana_keypair::constants::SALT_LEN],
        slot: u32,
    ) -> Result<Vec<u8>, TransactionError> {
        Ok(self
            .0
            .get_transaction_viewing_key(first_nullifier)?
            .decrypt_slot_ephemeral(peer, ciphertext, salt, slot)?)
    }

    fn owner_hash(&self) -> Result<[u8; 32], TransactionError> {
        Ok(self.0.owner_hash()?)
    }

    fn derive_proofless_blinding(
        &self,
        salt: &[u8; zolana_keypair::constants::SALT_LEN],
    ) -> Result<[u8; BLINDING_LEN], TransactionError> {
        Ok(self.0.viewing_key.derive_proofless_blinding(salt)?)
    }
}

pub struct InMemoryWallet {
    pub keypair: ShieldedKeypair,
    pub wallet: Wallet,
}

impl InMemoryWallet {
    pub fn new(keypair: ShieldedKeypair) -> Result<Self, TransactionError> {
        let wallet = Wallet::new(
            keypair.signing_pubkey(),
            keypair.nullifier_key.pubkey()?,
            keypair.viewing_pubkey(),
        );
        Ok(Self { keypair, wallet })
    }

    pub fn sync(
        &mut self,
        transactions: &[SyncTransaction],
        proofless_deposits: &[DepositView],
        assets: &AssetRegistry,
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        self.wallet.sync(
            &KeypairWalletKeyProvider(&self.keypair),
            transactions,
            proofless_deposits,
            assets,
            synced_at,
            window,
        )
    }

    #[cfg(feature = "parallel")]
    pub fn sync_parallel(
        &mut self,
        transactions: &[SyncTransaction],
        proofless_deposits: &[DepositView],
        assets: &AssetRegistry,
        synced_at: i64,
        window: u64,
    ) -> Result<SyncReport, TransactionError> {
        self.wallet.sync_parallel(
            &KeypairWalletKeyProvider(&self.keypair),
            transactions,
            assets,
            synced_at,
            window,
        )
    }

    pub fn balances(
        &self,
        assets: &AssetRegistry,
        skip_utxos: bool,
    ) -> Result<Vec<AssetBalance>, TransactionError> {
        self.wallet.balances(assets, skip_utxos)
    }
}

impl Deref for InMemoryWallet {
    type Target = Wallet;

    fn deref(&self) -> &Self::Target {
        &self.wallet
    }
}

impl DerefMut for InMemoryWallet {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.wallet
    }
}
