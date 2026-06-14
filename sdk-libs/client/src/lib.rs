use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use solana_address::Address;
use solana_instruction::Instruction;
use thiserror::Error;
use zolana_keypair::constants::{BLINDING_LEN, SALT_LEN};
#[cfg(feature = "test-utils")]
use zolana_keypair::ShieldedKeypair;
use zolana_keypair::{random_salt, P256Pubkey, PublicKey};
use zolana_transaction::test_wallet::TestWallet;
#[cfg(feature = "test-utils")]
use zolana_transaction::transfer::RecipientOutput;
use zolana_transaction::transfer::{
    RecipientSlot, TransferEncryptedUtxos, TransferSenderPlaintext,
};
use zolana_transaction::wallet::{SyncTransaction, Wallet, WalletCrypto};
#[cfg(feature = "test-utils")]
use zolana_transaction::TransactionEncryption;
use zolana_transaction::{AssetRegistry, Data, TransactionError, Utxo, SOL_MINT, TRANSFER};

pub use zolana_transaction::wallet::SyncReport;
pub use zolana_transaction::Address as SolanaAddress;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("private wallet not found")]
    PrivateWalletNotFound,
    #[error("private wallet already created")]
    PrivateWalletAlreadyCreated,
    #[error("private wallet inbox must match owner")]
    InboxOwnerMismatch,
    #[error("private wallet inbox already registered")]
    InboxAlreadyRegistered,
    #[error("recipient private wallet not found")]
    RecipientPrivateWalletNotFound,
    #[error("insufficient private balance")]
    InsufficientPrivateBalance,
    #[error("amount must be greater than zero")]
    InvalidAmount,
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),
    #[error("client state lock poisoned")]
    LockPoisoned,
    #[error("transaction error: {0}")]
    Transaction(#[from] TransactionError),
    #[error("keypair error: {0}")]
    Keypair(#[from] zolana_keypair::KeypairError),
}

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PrivateWalletId(u64);

impl PrivateWalletId {
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivateWalletStatus {
    Active,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecryptionMode {
    Local,
    Delegated {
        provider: Address,
        expires_at: Option<i64>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShieldedPublicKey {
    pub signing_pubkey: PublicKey,
    pub nullifier_pubkey: [u8; 32],
    pub viewing_pubkey: P256Pubkey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateWallet {
    pub id: PrivateWalletId,
    pub owner: Address,
    pub inbox: Address,
    pub shielded_public_key: ShieldedPublicKey,
    pub status: PrivateWalletStatus,
    pub label: Option<String>,
    pub decryption_mode: DecryptionMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatePrivateWalletInput {
    pub inbox: Address,
    pub label: Option<String>,
    pub decryption_mode: DecryptionMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetDecryptionModeInput {
    pub private_wallet_id: PrivateWalletId,
    pub mode: DecryptionMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateTokenBalance {
    pub mint: Address,
    pub amount: u64,
    pub asset_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateTokenBalances {
    pub status: SyncStatus,
    pub synced_at: Option<i64>,
    pub balances: Vec<PrivateTokenBalance>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyncStatus {
    Synced,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetPrivateTransactionsInput {
    pub limit: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateTransactionKind {
    MockAirdrop,
    PrivateTransfer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransactionStatus {
    Confirmed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateTransaction {
    pub kind: PrivateTransactionKind,
    pub direction: TransactionDirection,
    pub mint: Address,
    pub amount: u64,
    pub status: TransactionStatus,
    pub signature: Option<String>,
    pub slot: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetDepositInstructionInput {
    pub private_wallet_id: PrivateWalletId,
    pub owner: Address,
    pub source_token_account: Address,
    pub mint: Address,
    pub decimals: u8,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendPrivateTransferInput {
    pub private_wallet_id: PrivateWalletId,
    pub recipient: Address,
    pub mint: Address,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrivateTransferRoute {
    PrivateTransfer,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendPrivateTransferResult {
    pub status: TransactionStatus,
    pub route: PrivateTransferRoute,
    pub signatures: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub private_wallet_id: PrivateWalletId,
    pub recipient: Address,
    pub mint: Address,
    pub amount: u64,
}

pub type P256Signature = [u8; 64];
pub type ViewTag = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeriveViewTagsRequest {
    RecipientBootstrap,
    Sender {
        start: u64,
        limit: u64,
    },
    RecipientRequest {
        start: u64,
        limit: u64,
    },
    SendShared {
        counterparty: P256Pubkey,
        start: u64,
        limit: u64,
    },
    RecipientShared {
        counterparty: P256Pubkey,
        start: u64,
        limit: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HpkeKey {
    RootViewing,
    TransactionViewing { first_nullifier: [u8; 32] },
}

pub struct HpkeEncryptRequest {
    pub key: HpkeKey,
    pub recipient: P256Pubkey,
    pub plaintext: Vec<u8>,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
}

pub struct HpkeEncryptResult {
    pub public_key: P256Pubkey,
    pub ciphertext: Vec<u8>,
}

pub struct HpkeDecryptRequest {
    pub key: HpkeKey,
    pub peer: P256Pubkey,
    pub ciphertext: Vec<u8>,
    pub salt: [u8; SALT_LEN],
    pub slot_index: u32,
}

pub trait HeliusPrivacyInterface: Send {
    fn create_p256_keypair(&mut self, wallet_id: PrivateWalletId) -> Result<ShieldedPublicKey>;

    fn get_shielded_public_key(&self, wallet_id: PrivateWalletId) -> Result<ShieldedPublicKey>;

    fn sign_p256(&self, wallet_id: PrivateWalletId, message: &[u8]) -> Result<P256Signature>;

    fn derive_nullifier(
        &self,
        wallet_id: PrivateWalletId,
        utxo_hash: &[u8; 32],
        blinding: &[u8; BLINDING_LEN],
    ) -> Result<[u8; 32]>;

    fn derive_view_tags(
        &self,
        wallet_id: PrivateWalletId,
        request: DeriveViewTagsRequest,
    ) -> Result<Vec<ViewTag>>;

    fn transaction_viewing_pubkey(
        &self,
        wallet_id: PrivateWalletId,
        first_nullifier: &[u8; 32],
    ) -> Result<P256Pubkey>;

    fn encrypt_hpke(
        &self,
        wallet_id: PrivateWalletId,
        request: HpkeEncryptRequest,
    ) -> Result<HpkeEncryptResult>;

    fn decrypt_hpke(
        &self,
        wallet_id: PrivateWalletId,
        request: HpkeDecryptRequest,
    ) -> Result<Vec<u8>>;

    fn read_state(&self, wallet_id: PrivateWalletId) -> Result<Option<Vec<u8>>>;

    fn write_state(&mut self, wallet_id: PrivateWalletId, encrypted_state: Vec<u8>) -> Result<()>;

    fn request_user_approval(&self, request: &ApprovalRequest) -> Result<()>;
}

impl HeliusPrivacyInterface for TestWallet {
    fn create_p256_keypair(&mut self, _wallet_id: PrivateWalletId) -> Result<ShieldedPublicKey> {
        if self.private_wallet_created {
            return Err(ClientError::PrivateWalletAlreadyCreated);
        }
        self.private_wallet_created = true;
        Ok(ShieldedPublicKey {
            signing_pubkey: self.keypair.signing_pubkey(),
            nullifier_pubkey: self.keypair.nullifier_key.pubkey()?,
            viewing_pubkey: self.keypair.viewing_pubkey(),
        })
    }

    fn get_shielded_public_key(&self, _wallet_id: PrivateWalletId) -> Result<ShieldedPublicKey> {
        Ok(ShieldedPublicKey {
            signing_pubkey: self.keypair.signing_pubkey(),
            nullifier_pubkey: self.keypair.nullifier_key.pubkey()?,
            viewing_pubkey: self.keypair.viewing_pubkey(),
        })
    }

    fn sign_p256(&self, _wallet_id: PrivateWalletId, message: &[u8]) -> Result<P256Signature> {
        Ok(self.keypair.sign(message))
    }

    fn derive_nullifier(
        &self,
        _wallet_id: PrivateWalletId,
        utxo_hash: &[u8; 32],
        blinding: &[u8; BLINDING_LEN],
    ) -> Result<[u8; 32]> {
        Ok(self.keypair.nullifier_key.nullifier(utxo_hash, blinding)?)
    }

    fn derive_view_tags(
        &self,
        _wallet_id: PrivateWalletId,
        request: DeriveViewTagsRequest,
    ) -> Result<Vec<ViewTag>> {
        let tags = match request {
            DeriveViewTagsRequest::RecipientBootstrap => {
                vec![self.keypair.recipient_bootstrap_view_tag()]
            }
            DeriveViewTagsRequest::Sender { start, limit } => (start..start.saturating_add(limit))
                .map(|index| {
                    self.keypair
                        .get_sender_view_tag(index)
                        .map_err(ClientError::from)
                })
                .collect::<Result<Vec<_>>>()?,
            DeriveViewTagsRequest::RecipientRequest { start, limit } => (start
                ..start.saturating_add(limit))
                .map(|index| {
                    self.keypair
                        .get_recipient_request_view_tag(index)
                        .map_err(ClientError::from)
                })
                .collect::<Result<Vec<_>>>()?,
            DeriveViewTagsRequest::SendShared {
                counterparty,
                start,
                limit,
            } => (start..start.saturating_add(limit))
                .map(|index| {
                    self.keypair
                        .get_send_shared_view_tag(&counterparty, index)
                        .map_err(ClientError::from)
                })
                .collect::<Result<Vec<_>>>()?,
            DeriveViewTagsRequest::RecipientShared {
                counterparty,
                start,
                limit,
            } => (start..start.saturating_add(limit))
                .map(|index| {
                    self.keypair
                        .get_recipient_shared_view_tag(&counterparty, index)
                        .map_err(ClientError::from)
                })
                .collect::<Result<Vec<_>>>()?,
        };
        Ok(tags)
    }

    fn transaction_viewing_pubkey(
        &self,
        _wallet_id: PrivateWalletId,
        first_nullifier: &[u8; 32],
    ) -> Result<P256Pubkey> {
        Ok(self
            .keypair
            .get_transaction_viewing_key(first_nullifier)?
            .pubkey())
    }

    fn encrypt_hpke(
        &self,
        _wallet_id: PrivateWalletId,
        request: HpkeEncryptRequest,
    ) -> Result<HpkeEncryptResult> {
        let (public_key, ciphertext) = match request.key {
            HpkeKey::RootViewing => (
                self.keypair.viewing_pubkey(),
                self.keypair.viewing_key.encrypt_slot(
                    &request.recipient,
                    &request.plaintext,
                    request.salt,
                    request.slot_index,
                )?,
            ),
            HpkeKey::TransactionViewing { first_nullifier } => {
                let tx = self.keypair.get_transaction_viewing_key(&first_nullifier)?;
                (
                    tx.pubkey(),
                    tx.encrypt_slot(
                        &request.recipient,
                        &request.plaintext,
                        request.salt,
                        request.slot_index,
                    )?,
                )
            }
        };
        Ok(HpkeEncryptResult {
            public_key,
            ciphertext,
        })
    }

    fn decrypt_hpke(
        &self,
        _wallet_id: PrivateWalletId,
        request: HpkeDecryptRequest,
    ) -> Result<Vec<u8>> {
        match request.key {
            HpkeKey::RootViewing => Ok(self.keypair.viewing_key.decrypt_utxo(
                &request.ciphertext,
                &request.peer,
                request.salt,
                request.slot_index,
            )?),
            HpkeKey::TransactionViewing { first_nullifier } => Ok(self
                .keypair
                .get_transaction_viewing_key(&first_nullifier)?
                .decrypt_slot_ephemeral(
                    &request.peer,
                    &request.ciphertext,
                    request.salt,
                    request.slot_index,
                )?),
        }
    }

    fn read_state(&self, _wallet_id: PrivateWalletId) -> Result<Option<Vec<u8>>> {
        Ok(self.encrypted_state.clone())
    }

    fn write_state(&mut self, _wallet_id: PrivateWalletId, encrypted_state: Vec<u8>) -> Result<()> {
        self.encrypted_state = Some(encrypted_state);
        Ok(())
    }

    fn request_user_approval(&self, _request: &ApprovalRequest) -> Result<()> {
        Ok(())
    }
}

struct HostCrypto<'a> {
    wallet_id: PrivateWalletId,
    host: &'a dyn HeliusPrivacyInterface,
}

impl WalletCrypto for HostCrypto<'_> {
    fn signing_pubkey(&self) -> PublicKey {
        self.host
            .get_shielded_public_key(self.wallet_id)
            .expect("wallet public key must exist")
            .signing_pubkey
    }

    fn nullifier_pubkey(&self) -> std::result::Result<[u8; 32], TransactionError> {
        Ok(self
            .host
            .get_shielded_public_key(self.wallet_id)
            .map_err(|e| TransactionError::Serialize(e.to_string()))?
            .nullifier_pubkey)
    }

    fn viewing_pubkey(&self) -> P256Pubkey {
        self.host
            .get_shielded_public_key(self.wallet_id)
            .expect("wallet public key must exist")
            .viewing_pubkey
    }

    fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; BLINDING_LEN],
    ) -> std::result::Result<[u8; 32], TransactionError> {
        self.host
            .derive_nullifier(self.wallet_id, utxo_hash, blinding)
            .map_err(|e| TransactionError::Serialize(e.to_string()))
    }

    fn recipient_bootstrap_view_tag(&self) -> ViewTag {
        self.host
            .derive_view_tags(self.wallet_id, DeriveViewTagsRequest::RecipientBootstrap)
            .expect("recipient bootstrap tag must derive")[0]
    }

    fn get_sender_view_tag(
        &self,
        index: u64,
    ) -> std::result::Result<ViewTag, zolana_keypair::KeypairError> {
        self.host
            .derive_view_tags(
                self.wallet_id,
                DeriveViewTagsRequest::Sender {
                    start: index,
                    limit: 1,
                },
            )
            .map(|tags| tags[0])
            .map_err(|_| zolana_keypair::KeypairError::Hkdf)
    }

    fn get_recipient_request_view_tag(
        &self,
        index: u64,
    ) -> std::result::Result<ViewTag, zolana_keypair::KeypairError> {
        self.host
            .derive_view_tags(
                self.wallet_id,
                DeriveViewTagsRequest::RecipientRequest {
                    start: index,
                    limit: 1,
                },
            )
            .map(|tags| tags[0])
            .map_err(|_| zolana_keypair::KeypairError::Hkdf)
    }

    fn get_send_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        index: u64,
    ) -> std::result::Result<ViewTag, zolana_keypair::KeypairError> {
        self.host
            .derive_view_tags(
                self.wallet_id,
                DeriveViewTagsRequest::SendShared {
                    counterparty: *counterparty,
                    start: index,
                    limit: 1,
                },
            )
            .map(|tags| tags[0])
            .map_err(|_| zolana_keypair::KeypairError::Hkdf)
    }

    fn get_recipient_shared_view_tag(
        &self,
        counterparty: &P256Pubkey,
        index: u64,
    ) -> std::result::Result<ViewTag, zolana_keypair::KeypairError> {
        self.host
            .derive_view_tags(
                self.wallet_id,
                DeriveViewTagsRequest::RecipientShared {
                    counterparty: *counterparty,
                    start: index,
                    limit: 1,
                },
            )
            .map(|tags| tags[0])
            .map_err(|_| zolana_keypair::KeypairError::Hkdf)
    }

    fn transaction_viewing_pubkey(
        &self,
        first_nullifier: &[u8; 32],
    ) -> std::result::Result<P256Pubkey, TransactionError> {
        self.host
            .transaction_viewing_pubkey(self.wallet_id, first_nullifier)
            .map_err(|e| TransactionError::Serialize(e.to_string()))
    }

    fn encrypt_transaction_slot(
        &self,
        first_nullifier: &[u8; 32],
        recipient: &P256Pubkey,
        plaintext: &[u8],
        salt: [u8; SALT_LEN],
        slot: u32,
    ) -> std::result::Result<Vec<u8>, TransactionError> {
        self.host
            .encrypt_hpke(
                self.wallet_id,
                HpkeEncryptRequest {
                    key: HpkeKey::TransactionViewing {
                        first_nullifier: *first_nullifier,
                    },
                    recipient: *recipient,
                    plaintext: plaintext.to_vec(),
                    salt,
                    slot_index: slot,
                },
            )
            .map(|result| result.ciphertext)
            .map_err(|e| TransactionError::Serialize(e.to_string()))
    }

    fn decrypt_root_slot(
        &self,
        peer: &P256Pubkey,
        ciphertext: &[u8],
        salt: [u8; SALT_LEN],
        slot: u32,
    ) -> std::result::Result<Vec<u8>, TransactionError> {
        self.host
            .decrypt_hpke(
                self.wallet_id,
                HpkeDecryptRequest {
                    key: HpkeKey::RootViewing,
                    peer: *peer,
                    ciphertext: ciphertext.to_vec(),
                    salt,
                    slot_index: slot,
                },
            )
            .map_err(|e| TransactionError::Serialize(e.to_string()))
    }

    fn decrypt_transaction_slot(
        &self,
        first_nullifier: &[u8; 32],
        peer: &P256Pubkey,
        ciphertext: &[u8],
        salt: [u8; SALT_LEN],
        slot: u32,
    ) -> std::result::Result<Vec<u8>, TransactionError> {
        self.host
            .decrypt_hpke(
                self.wallet_id,
                HpkeDecryptRequest {
                    key: HpkeKey::TransactionViewing {
                        first_nullifier: *first_nullifier,
                    },
                    peer: *peer,
                    ciphertext: ciphertext.to_vec(),
                    salt,
                    slot_index: slot,
                },
            )
            .map_err(|e| TransactionError::Serialize(e.to_string()))
    }
}

#[derive(Clone)]
struct PrivacyNetwork {
    state: Arc<Mutex<NetworkState>>,
}

impl PrivacyNetwork {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Default for PrivacyNetwork {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(NetworkState::default())),
        }
    }
}

#[cfg(feature = "test-utils")]
pub mod testing {
    use super::PrivacyNetwork;

    #[derive(Clone)]
    pub struct InMemoryPrivacyProvider {
        pub(crate) network: PrivacyNetwork,
    }

    impl InMemoryPrivacyProvider {
        pub fn new() -> Self {
            Self::default()
        }
    }

    impl Default for InMemoryPrivacyProvider {
        fn default() -> Self {
            Self {
                network: PrivacyNetwork::new(),
            }
        }
    }
}

#[derive(Default)]
struct NetworkState {
    next_wallet_id: u64,
    next_asset_id: u64,
    next_counter: u64,
    next_signature: u64,
    wallets: HashMap<PrivateWalletId, PrivateWallet>,
    inboxes: HashMap<Address, PrivateWalletId>,
    transactions: Vec<SyncTransaction>,
    history: HashMap<PrivateWalletId, Vec<PrivateTransaction>>,
    assets: AssetRegistry,
}

impl NetworkState {
    fn asset_id_for_mint(&mut self, mint: Address) -> Result<u64> {
        if let Ok(asset_id) = self.assets.asset_id(&mint) {
            return Ok(asset_id);
        }
        self.next_asset_id = self.next_asset_id.max(2);
        let asset_id = self.next_asset_id;
        self.next_asset_id += 1;
        self.assets.insert(asset_id, mint)?;
        Ok(asset_id)
    }

    fn unique_blinding(&mut self) -> [u8; BLINDING_LEN] {
        self.next_counter += 1;
        let mut out = [0u8; BLINDING_LEN];
        out[0] = 0x42;
        out[1..9].copy_from_slice(&self.next_counter.to_be_bytes());
        out
    }

    #[cfg(feature = "test-utils")]
    fn unique_nullifier(&mut self) -> [u8; 32] {
        self.next_counter += 1;
        let mut out = [0u8; 32];
        out[0] = 0xAA;
        out[1..9].copy_from_slice(&self.next_counter.to_be_bytes());
        out
    }

    fn next_signature(&mut self) -> String {
        self.next_signature += 1;
        format!("mock-signature-{}", self.next_signature)
    }
}

struct LocalPrivateWallet {
    metadata: PrivateWallet,
    wallet: Wallet,
    host: Box<dyn HeliusPrivacyInterface>,
}

pub struct PrivacyClient {
    owner: Address,
    network: PrivacyNetwork,
    wallets: HashMap<PrivateWalletId, LocalPrivateWallet>,
    pending_host: Option<Box<dyn HeliusPrivacyInterface>>,
}

impl PrivacyClient {
    pub fn new(owner: Address, host: impl HeliusPrivacyInterface + 'static) -> Self {
        Self::with_network(owner, Box::new(host), PrivacyNetwork::new())
    }

    fn with_network(
        owner: Address,
        host: Box<dyn HeliusPrivacyInterface>,
        network: PrivacyNetwork,
    ) -> Self {
        Self {
            owner,
            network,
            wallets: HashMap::new(),
            pending_host: Some(host),
        }
    }

    #[cfg(feature = "test-utils")]
    pub fn new_with_test_provider(
        owner: Address,
        host: impl HeliusPrivacyInterface + 'static,
        provider: testing::InMemoryPrivacyProvider,
    ) -> Self {
        Self::with_network(owner, Box::new(host), provider.network)
    }

    #[cfg(feature = "test-utils")]
    pub fn new_for_tests(
        owner: Address,
        keypair: ShieldedKeypair,
        provider: testing::InMemoryPrivacyProvider,
    ) -> Result<Self> {
        Ok(Self::new_with_test_provider(
            owner,
            TestWallet::new(keypair)?,
            provider,
        ))
    }

    pub async fn create_private_wallet(
        &mut self,
        input: CreatePrivateWalletInput,
    ) -> Result<PrivateWallet> {
        if input.inbox != self.owner {
            return Err(ClientError::InboxOwnerMismatch);
        }
        if self.pending_host.is_none() {
            return Err(ClientError::PrivateWalletAlreadyCreated);
        }
        let mut network = self
            .network
            .state
            .lock()
            .map_err(|_| ClientError::LockPoisoned)?;
        if network.inboxes.contains_key(&input.inbox) {
            return Err(ClientError::InboxAlreadyRegistered);
        }
        network.next_wallet_id += 1;
        let id = PrivateWalletId(network.next_wallet_id);
        let mut host = self
            .pending_host
            .take()
            .ok_or(ClientError::PrivateWalletAlreadyCreated)?;
        let shielded_public_key = host.create_p256_keypair(id)?;
        host.write_state(id, Vec::new())?;
        let wallet = Wallet::new(
            shielded_public_key.signing_pubkey,
            shielded_public_key.nullifier_pubkey,
            shielded_public_key.viewing_pubkey,
        );
        let metadata = PrivateWallet {
            id,
            owner: self.owner,
            inbox: input.inbox,
            shielded_public_key,
            status: PrivateWalletStatus::Active,
            label: input.label,
            decryption_mode: input.decryption_mode,
        };
        network.inboxes.insert(metadata.inbox, id);
        network.wallets.insert(id, metadata.clone());
        drop(network);
        self.wallets.insert(
            id,
            LocalPrivateWallet {
                metadata: metadata.clone(),
                wallet,
                host,
            },
        );
        Ok(metadata)
    }

    pub async fn set_decryption_mode(
        &mut self,
        input: SetDecryptionModeInput,
    ) -> Result<PrivateWallet> {
        let local = self
            .wallets
            .get_mut(&input.private_wallet_id)
            .ok_or(ClientError::PrivateWalletNotFound)?;
        local.metadata.decryption_mode = input.mode;
        let mut network = self
            .network
            .state
            .lock()
            .map_err(|_| ClientError::LockPoisoned)?;
        let remote = network
            .wallets
            .get_mut(&input.private_wallet_id)
            .ok_or(ClientError::PrivateWalletNotFound)?;
        remote.decryption_mode = input.mode;
        Ok(local.metadata.clone())
    }

    pub async fn sync_private_wallet(
        &mut self,
        private_wallet_id: PrivateWalletId,
    ) -> Result<SyncReport> {
        let local = self
            .wallets
            .get_mut(&private_wallet_id)
            .ok_or(ClientError::PrivateWalletNotFound)?;
        let network = self
            .network
            .state
            .lock()
            .map_err(|_| ClientError::LockPoisoned)?;
        let transactions = network.transactions.clone();
        let assets = network.assets.clone();
        drop(network);
        let _state = local.host.read_state(private_wallet_id)?;
        let _tags = local
            .host
            .derive_view_tags(private_wallet_id, DeriveViewTagsRequest::RecipientBootstrap)?;
        let crypto = HostCrypto {
            wallet_id: private_wallet_id,
            host: local.host.as_ref(),
        };
        let report = local
            .wallet
            .sync(&crypto, &transactions, &assets, 1_700_000_000, 64)?;
        local.host.write_state(
            private_wallet_id,
            report.stored_utxos.to_be_bytes().to_vec(),
        )?;
        Ok(report)
    }

    pub async fn get_private_token_balances(
        &self,
        private_wallet_id: PrivateWalletId,
    ) -> Result<PrivateTokenBalances> {
        let local = self
            .wallets
            .get(&private_wallet_id)
            .ok_or(ClientError::PrivateWalletNotFound)?;
        let network = self
            .network
            .state
            .lock()
            .map_err(|_| ClientError::LockPoisoned)?;
        let balances = local.wallet.balances(&network.assets, true)?;
        Ok(PrivateTokenBalances {
            status: SyncStatus::Synced,
            synced_at: Some(local.wallet.last_synced),
            balances: balances
                .into_iter()
                .map(|balance| PrivateTokenBalance {
                    mint: balance.mint,
                    amount: balance.amount,
                    asset_id: balance.asset_id,
                })
                .collect(),
        })
    }

    pub async fn get_private_transactions(
        &self,
        private_wallet_id: PrivateWalletId,
        input: GetPrivateTransactionsInput,
    ) -> Result<Vec<PrivateTransaction>> {
        if !self.wallets.contains_key(&private_wallet_id) {
            return Err(ClientError::PrivateWalletNotFound);
        }
        let network = self
            .network
            .state
            .lock()
            .map_err(|_| ClientError::LockPoisoned)?;
        let mut history = network
            .history
            .get(&private_wallet_id)
            .cloned()
            .unwrap_or_default();
        if history.len() > input.limit {
            history.truncate(input.limit);
        }
        Ok(history)
    }

    pub async fn get_deposit_instruction(
        &self,
        _input: GetDepositInstructionInput,
    ) -> Result<Instruction> {
        Err(ClientError::Unsupported("deposit instruction"))
    }

    pub async fn send_private_transfer(
        &mut self,
        input: SendPrivateTransferInput,
    ) -> Result<SendPrivateTransferResult> {
        if input.amount == 0 {
            return Err(ClientError::InvalidAmount);
        }
        let sender = self
            .wallets
            .get_mut(&input.private_wallet_id)
            .ok_or(ClientError::PrivateWalletNotFound)?;
        let mut network = self
            .network
            .state
            .lock()
            .map_err(|_| ClientError::LockPoisoned)?;
        let recipient_id = *network
            .inboxes
            .get(&input.recipient)
            .ok_or(ClientError::RecipientPrivateWalletNotFound)?;
        let recipient = network
            .wallets
            .get(&recipient_id)
            .ok_or(ClientError::RecipientPrivateWalletNotFound)?
            .clone();
        let asset_id = network.asset_id_for_mint(input.mint)?;
        sender.host.request_user_approval(&ApprovalRequest {
            private_wallet_id: input.private_wallet_id,
            recipient: input.recipient,
            mint: input.mint,
            amount: input.amount,
        })?;
        let mut selected_indices = Vec::new();
        let mut selected_nullifiers = Vec::new();
        let mut selected_amount = 0u64;
        for (index, entry) in sender.wallet.utxos.iter().enumerate() {
            if entry.spent || entry.utxo.asset != input.mint {
                continue;
            }
            selected_indices.push(index);
            selected_nullifiers.push(entry.nullifier);
            selected_amount = selected_amount.saturating_add(entry.utxo.amount);
            if selected_amount >= input.amount {
                break;
            }
        }
        if selected_amount < input.amount {
            return Err(ClientError::InsufficientPrivateBalance);
        }

        let first_nullifier = selected_nullifiers[0];
        let change_amount = selected_amount - input.amount;
        let sender_public_key = sender.metadata.shielded_public_key;
        let output_blinding = network.unique_blinding();
        let change_blinding_seed = network.unique_blinding();
        let recipient_utxo = Utxo {
            owner: recipient.shielded_public_key.signing_pubkey,
            asset: input.mint,
            amount: input.amount,
            blinding: output_blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let recipient_plaintext = recipient_utxo
            .to_recipient_plaintext(sender_public_key.viewing_pubkey, &network.assets)?;
        let viewing_entry = sender
            .wallet
            .viewing_key_history
            .last()
            .ok_or(ClientError::PrivateWalletNotFound)?;
        let crypto = HostCrypto {
            wallet_id: input.private_wallet_id,
            host: sender.host.as_ref(),
        };
        let view_tag = match viewing_entry
            .known_recipients
            .get(&recipient.shielded_public_key.viewing_pubkey)
        {
            Some(index) => crypto
                .get_send_shared_view_tag(&recipient.shielded_public_key.viewing_pubkey, *index)
                .map_err(ClientError::from)?,
            None => recipient.shielded_public_key.viewing_pubkey.x(),
        };
        let sender_view_tag = crypto
            .get_sender_view_tag(viewing_entry.tx_count)
            .map_err(ClientError::from)?;
        let sender_plaintext = if input.mint == SOL_MINT {
            TransferSenderPlaintext {
                owner_pubkey: sender_public_key.signing_pubkey,
                spl_asset_id: asset_id,
                spl_amount: 0,
                sol_amount: change_amount,
                blinding_seed: change_blinding_seed,
                recipient_viewing_pks: vec![recipient.shielded_public_key.viewing_pubkey],
                spl_data: Data::default(),
                sol_data: Data::default(),
            }
        } else {
            TransferSenderPlaintext {
                owner_pubkey: sender_public_key.signing_pubkey,
                spl_asset_id: asset_id,
                spl_amount: change_amount,
                sol_amount: 0,
                blinding_seed: change_blinding_seed,
                recipient_viewing_pks: vec![recipient.shielded_public_key.viewing_pubkey],
                spl_data: Data::default(),
                sol_data: Data::default(),
            }
        };
        let salt = random_salt();
        let tx_viewing_pk = crypto.transaction_viewing_pubkey(&first_nullifier)?;
        let sender_ciphertext = crypto.encrypt_transaction_slot(
            &first_nullifier,
            &sender_public_key.viewing_pubkey,
            &sender_plaintext.serialize()?,
            salt,
            0,
        )?;
        let recipient_ciphertext = crypto.encrypt_transaction_slot(
            &first_nullifier,
            &recipient.shielded_public_key.viewing_pubkey,
            &recipient_plaintext.serialize()?,
            salt,
            1,
        )?;
        let encrypted = TransferEncryptedUtxos {
            type_prefix: TRANSFER,
            tx_viewing_pk,
            salt,
            sender_ciphertext,
            recipient_slots: vec![RecipientSlot {
                view_tag,
                ciphertext: recipient_ciphertext,
            }],
        };
        let transaction = SyncTransaction {
            encrypted_utxos: encrypted.serialize()?,
            sender_view_tag,
            nullifiers: selected_nullifiers,
        };
        let _signature = sender
            .host
            .sign_p256(input.private_wallet_id, &transaction.encrypted_utxos)?;
        for index in selected_indices {
            if let Some(entry) = sender.wallet.utxos.get_mut(index) {
                entry.spent = true;
            }
        }
        network.transactions.push(transaction);
        let signature = network.next_signature();
        let slot = network.next_signature;
        network
            .history
            .entry(input.private_wallet_id)
            .or_default()
            .insert(
                0,
                PrivateTransaction {
                    kind: PrivateTransactionKind::PrivateTransfer,
                    direction: TransactionDirection::Outbound,
                    mint: input.mint,
                    amount: input.amount,
                    status: TransactionStatus::Confirmed,
                    signature: Some(signature.clone()),
                    slot: Some(slot),
                },
            );
        network.history.entry(recipient_id).or_default().insert(
            0,
            PrivateTransaction {
                kind: PrivateTransactionKind::PrivateTransfer,
                direction: TransactionDirection::Inbound,
                mint: input.mint,
                amount: input.amount,
                status: TransactionStatus::Confirmed,
                signature: Some(signature.clone()),
                slot: Some(slot),
            },
        );
        Ok(SendPrivateTransferResult {
            status: TransactionStatus::Confirmed,
            route: PrivateTransferRoute::PrivateTransfer,
            signatures: vec![signature],
        })
    }

    #[cfg(feature = "test-utils")]
    pub async fn mock_airdrop(
        &mut self,
        private_wallet_id: PrivateWalletId,
        mint: Address,
        amount: u64,
    ) -> Result<String> {
        if amount == 0 {
            return Err(ClientError::InvalidAmount);
        }
        let local = self
            .wallets
            .get(&private_wallet_id)
            .ok_or(ClientError::PrivateWalletNotFound)?;
        let faucet = ShieldedKeypair::new()?;
        let mut network = self
            .network
            .state
            .lock()
            .map_err(|_| ClientError::LockPoisoned)?;
        let asset_id = network.asset_id_for_mint(mint)?;
        let blinding = network.unique_blinding();
        let blinding_seed = network.unique_blinding();
        let first_nullifier = network.unique_nullifier();
        let recipient_utxo = Utxo {
            owner: local.metadata.shielded_public_key.signing_pubkey,
            asset: mint,
            amount,
            blinding,
            zone_program_id: None,
            data: Data::default(),
        };
        let recipient_plaintext =
            recipient_utxo.to_recipient_plaintext(faucet.viewing_pubkey(), &network.assets)?;
        let sender_plaintext = TransferSenderPlaintext {
            owner_pubkey: faucet.signing_pubkey(),
            spl_asset_id: asset_id,
            spl_amount: 0,
            sol_amount: 0,
            blinding_seed,
            recipient_viewing_pks: vec![local.metadata.shielded_public_key.viewing_pubkey],
            spl_data: Data::default(),
            sol_data: Data::default(),
        };
        let encrypted = faucet.viewing_key.encrypt_transfer(
            &first_nullifier,
            &sender_plaintext,
            &[RecipientOutput {
                view_tag: local.metadata.shielded_public_key.viewing_pubkey.x(),
                plaintext: recipient_plaintext,
            }],
        )?;
        network.transactions.push(SyncTransaction {
            encrypted_utxos: encrypted.serialize()?,
            sender_view_tag: faucet.get_sender_view_tag(0)?,
            nullifiers: vec![first_nullifier],
        });
        let signature = network.next_signature();
        let slot = network.next_signature;
        network
            .history
            .entry(private_wallet_id)
            .or_default()
            .insert(
                0,
                PrivateTransaction {
                    kind: PrivateTransactionKind::MockAirdrop,
                    direction: TransactionDirection::Inbound,
                    mint,
                    amount,
                    status: TransactionStatus::Confirmed,
                    signature: Some(signature.clone()),
                    slot: Some(slot),
                },
            );
        Ok(signature)
    }
}
