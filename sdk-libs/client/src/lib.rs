pub mod actions;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::generic_array::GenericArray;
use p256::elliptic_curve::hash2curve::FromOkm;
use p256::{NonZeroScalar, Scalar, SecretKey};
use sha2::Sha256;
use solana_address::Address;
use solana_instruction::Instruction;
use thiserror::Error;
use zolana_keypair::constants::{BLINDING_LEN, P256_PUBKEY_LEN, P_CONST_SEC1, SALT_LEN};
#[cfg(feature = "test-utils")]
use zolana_keypair::ShieldedKeypair;
use zolana_keypair::{random_salt, P256Pubkey, PublicKey};
#[cfg(feature = "test-utils")]
use zolana_transaction::transfer::RecipientOutput;
use zolana_transaction::transfer::{
    RecipientSlot, TransferEncryptedUtxos, TransferSenderPlaintext,
};
use zolana_transaction::wallet::{SyncTransaction, Wallet, WalletKeyProvider};
#[cfg(feature = "test-utils")]
use zolana_transaction::TransactionEncryption;
use zolana_transaction::{AssetRegistry, Data, TransactionError, Utxo, SOL_MINT, TRANSFER};


pub mod error;
pub mod private_transaction;
pub mod prover;
pub mod rpc;

#[cfg(feature = "indexer-api")]
pub mod indexer;
#[cfg(feature = "solana-rpc")]
pub mod solana_rpc;

#[cfg(feature = "indexer-api")]
pub mod indexer;
#[cfg(feature = "solana-rpc")]
pub mod solana_rpc;

pub use error::ClientError;
#[cfg(feature = "indexer-api")]
pub use indexer::ZolanaIndexer;
pub use private_transaction::{
    CircuitType, InputCommitment, SignedTransaction, SpendProof, SpendUtxo, Transaction,
    WithdrawalTarget,
};
pub use prover::{
    canonical_shape, resolve_shape, spawn_prover, Commitments, CompressedCommitments, P256Owner,
    Proof, ProofCompressed, ProverClient, PublicAmounts, Shape, TransferInput, TransferInputs,
    TransferOutput, TransferP256Inputs, TransferP256ProofResult, TransferP256Prover,
    TransferProofResult, TransferProver, TransferSpendInput, UtxoInputs, SUPPORTED_SHAPES,
};
pub use rpc::{
    Context, EncryptedUtxoMatch, GetEncryptedUtxosByTagsResponse, GetMerkleProofsResponse,
    GetNonInclusionProofsResponse, GetShieldedTransactionsByTagsResponse, MerkleContext,
    MerkleProof, NonInclusionProof, NullifierNonInclusionProof, OutputSlot, ProveResult, Rpc,
    ShieldedTransaction, ShieldedTransactionStream, StateInclusionProof, NULLIFIER_TREE_HEIGHT,
    STATE_TREE_HEIGHT,
};
#[cfg(feature = "solana-rpc")]
pub use solana_rpc::{ConfirmedInstructionGroups, SolanaRpc};

pub use zolana_transaction::wallet::SyncReport;
pub use zolana_transaction::Address as SolanaAddress;

#[derive(Debug, Error)]
pub enum WalletError {
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

pub type Result<T> = std::result::Result<T, WalletError>;

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

const ENC_INFO_TRANSFER: &[u8] = b"TSPP/tx";
const HPKE_PREFIX: &[u8] = b"TSPP/hpke/";
const INFO_TX_VIEWING: &[u8] = b"TSPP/tx_viewing";
const GCM_NONCE_LEN: usize = 12;

pub trait HeliusPrivacyInterface: Send {
    fn create_p256_keypair(&mut self, wallet_id: PrivateWalletId) -> Result<ShieldedPublicKey>;

    fn get_shielded_public_key(&self, wallet_id: PrivateWalletId) -> Result<ShieldedPublicKey>;

    fn sign_p256(&self, wallet_id: PrivateWalletId, message: &[u8]) -> Result<P256Signature>;

    fn ecdh_p256(&self, wallet_id: PrivateWalletId, public_key: &P256Pubkey) -> Result<[u8; 32]>;

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

    fn read_state(&self, wallet_id: PrivateWalletId) -> Result<Option<Vec<u8>>>;

    fn write_state(&mut self, wallet_id: PrivateWalletId, encrypted_state: Vec<u8>) -> Result<()>;

    fn request_user_approval(&self, request: &ApprovalRequest) -> Result<()>;
}

fn tx_error(message: impl Into<String>) -> TransactionError {
    TransactionError::Serialize(message.into())
}

fn derive_hpke_key_nonce(
    dh: &[u8; 32],
    ephemeral_pubkey: &P256Pubkey,
    recipient_pubkey: &P256Pubkey,
    salt: [u8; SALT_LEN],
    slot: u32,
) -> std::result::Result<([u8; 32], [u8; GCM_NONCE_LEN]), TransactionError> {
    let mut ikm = [0u8; 32 + 2 * P256_PUBKEY_LEN];
    ikm[..32].copy_from_slice(dh);
    ikm[32..32 + P256_PUBKEY_LEN].copy_from_slice(ephemeral_pubkey.as_bytes());
    ikm[32 + P256_PUBKEY_LEN..].copy_from_slice(recipient_pubkey.as_bytes());

    let mut okm = [0u8; 32 + GCM_NONCE_LEN];
    let slot_bytes = slot.to_be_bytes();
    Hkdf::<Sha256>::new(None, &ikm)
        .expand_multi_info(
            &[HPKE_PREFIX, ENC_INFO_TRANSFER, salt.as_slice(), &slot_bytes],
            &mut okm,
        )
        .map_err(|_| tx_error("failed to derive transfer encryption key"))?;

    let mut key = [0u8; 32];
    key.copy_from_slice(&okm[..32]);
    let mut nonce = [0u8; GCM_NONCE_LEN];
    nonce.copy_from_slice(&okm[32..]);
    Ok((key, nonce))
}

fn encrypt_transfer_slot(
    shared_secret: &[u8; 32],
    ephemeral_pubkey: &P256Pubkey,
    recipient_pubkey: &P256Pubkey,
    plaintext: &[u8],
    salt: [u8; SALT_LEN],
    slot: u32,
) -> std::result::Result<Vec<u8>, TransactionError> {
    let (key, nonce) = derive_hpke_key_nonce(
        shared_secret,
        ephemeral_pubkey,
        recipient_pubkey,
        salt,
        slot,
    )?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| tx_error("failed to initialize transfer cipher"))?;
    cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| tx_error("failed to encrypt transfer slot"))
}

fn decrypt_transfer_slot(
    shared_secret: &[u8; 32],
    ephemeral_pubkey: &P256Pubkey,
    recipient_pubkey: &P256Pubkey,
    ciphertext: &[u8],
    salt: [u8; SALT_LEN],
    slot: u32,
) -> std::result::Result<Vec<u8>, TransactionError> {
    let (key, nonce) = derive_hpke_key_nonce(
        shared_secret,
        ephemeral_pubkey,
        recipient_pubkey,
        salt,
        slot,
    )?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| tx_error("failed to initialize transfer cipher"))?;
    cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .map_err(|_| tx_error("failed to decrypt transfer slot"))
}

fn ecdh_with_secret(
    secret: &SecretKey,
    counterparty: &P256Pubkey,
) -> std::result::Result<[u8; 32], TransactionError> {
    let point = counterparty
        .to_p256()
        .map_err(|err| tx_error(err.to_string()))?;
    let shared = diffie_hellman(secret.to_nonzero_scalar(), point.as_affine());
    let mut out = [0u8; 32];
    out.copy_from_slice(shared.raw_secret_bytes().as_slice());
    Ok(out)
}

struct HostWalletKeyProvider<'a> {
    wallet_id: PrivateWalletId,
    host: &'a dyn HeliusPrivacyInterface,
    shielded_public_key: ShieldedPublicKey,
    view_root: [u8; 32],
}

impl<'a> HostWalletKeyProvider<'a> {
    fn new(wallet_id: PrivateWalletId, host: &'a dyn HeliusPrivacyInterface) -> Result<Self> {
        let shielded_public_key = host.get_shielded_public_key(wallet_id)?;
        let p_const = P256Pubkey::from_bytes(P_CONST_SEC1)?;
        let shared = host.ecdh_p256(wallet_id, &p_const)?;
        let (prk, _) = Hkdf::<Sha256>::extract(None, &shared);
        let mut view_root = [0u8; 32];
        view_root.copy_from_slice(&prk);
        Ok(Self {
            wallet_id,
            host,
            shielded_public_key,
            view_root,
        })
    }

    fn tx_viewing_secret(
        &self,
        first_nullifier: &[u8; 32],
    ) -> std::result::Result<SecretKey, TransactionError> {
        let mut tx_viewing_seed = [0u8; 32];
        Hkdf::<Sha256>::from_prk(&self.view_root)
            .map_err(|_| tx_error("invalid host view root"))?
            .expand_multi_info(&[INFO_TX_VIEWING], &mut tx_viewing_seed)
            .map_err(|_| tx_error("failed to derive transaction viewing seed"))?;

        let mut okm = [0u8; 48];
        Hkdf::<Sha256>::new(Some(first_nullifier), &tx_viewing_seed)
            .expand_multi_info(&[INFO_TX_VIEWING], &mut okm)
            .map_err(|_| tx_error("failed to derive transaction viewing key"))?;

        let scalar = Scalar::from_okm(GenericArray::from_slice(&okm));
        let nonzero = Option::<NonZeroScalar>::from(NonZeroScalar::new(scalar))
            .ok_or_else(|| tx_error("derived transaction viewing key was zero"))?;
        Ok(SecretKey::from(nonzero))
    }
}

impl WalletKeyProvider for HostWalletKeyProvider<'_> {
    fn signing_pubkey(&self) -> PublicKey {
        self.shielded_public_key.signing_pubkey
    }

    fn nullifier_pubkey(&self) -> std::result::Result<[u8; 32], TransactionError> {
        Ok(self.shielded_public_key.nullifier_pubkey)
    }

    fn viewing_pubkey(&self) -> P256Pubkey {
        self.shielded_public_key.viewing_pubkey
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
        let tx_secret = self.tx_viewing_secret(first_nullifier)?;
        Ok(P256Pubkey::from_p256(&tx_secret.public_key()))
    }

    fn encrypt_transaction_slot(
        &self,
        first_nullifier: &[u8; 32],
        recipient: &P256Pubkey,
        plaintext: &[u8],
        salt: [u8; SALT_LEN],
        slot: u32,
    ) -> std::result::Result<Vec<u8>, TransactionError> {
        let tx_secret = self.tx_viewing_secret(first_nullifier)?;
        let tx_viewing_pubkey = P256Pubkey::from_p256(&tx_secret.public_key());
        let shared = ecdh_with_secret(&tx_secret, recipient)?;
        encrypt_transfer_slot(
            &shared,
            &tx_viewing_pubkey,
            recipient,
            plaintext,
            salt,
            slot,
        )
    }

    fn decrypt_root_slot(
        &self,
        peer: &P256Pubkey,
        ciphertext: &[u8],
        salt: [u8; SALT_LEN],
        slot: u32,
    ) -> std::result::Result<Vec<u8>, TransactionError> {
        let shared = self
            .host
            .ecdh_p256(self.wallet_id, peer)
            .map_err(|e| TransactionError::Serialize(e.to_string()))?;
        decrypt_transfer_slot(
            &shared,
            peer,
            &self.shielded_public_key.viewing_pubkey,
            ciphertext,
            salt,
            slot,
        )
    }

    fn decrypt_transaction_slot(
        &self,
        first_nullifier: &[u8; 32],
        peer: &P256Pubkey,
        ciphertext: &[u8],
        salt: [u8; SALT_LEN],
        slot: u32,
    ) -> std::result::Result<Vec<u8>, TransactionError> {
        let tx_secret = self.tx_viewing_secret(first_nullifier)?;
        let tx_viewing_pubkey = P256Pubkey::from_p256(&tx_secret.public_key());
        let shared = ecdh_with_secret(&tx_secret, peer)?;
        decrypt_transfer_slot(&shared, &tx_viewing_pubkey, peer, ciphertext, salt, slot)
    }

    fn owner_hash(&self) -> std::result::Result<[u8; 32], TransactionError> {
        zolana_keypair::hash::owner_hash(
            &self.shielded_public_key.signing_pubkey,
            &self.shielded_public_key.nullifier_pubkey,
        )
        .map_err(|e| TransactionError::Serialize(e.to_string()))
    }

    fn derive_proofless_blinding(
        &self,
        salt: &[u8; SALT_LEN],
    ) -> std::result::Result<[u8; BLINDING_LEN], TransactionError> {
        let mut recipient_secret = [0u8; 32];
        Hkdf::<Sha256>::from_prk(&self.view_root)
            .map_err(|_| tx_error("invalid host view root"))?
            .expand_multi_info(&[b"TSPP/recipient_view_tag"], &mut recipient_secret)
            .map_err(|_| tx_error("failed to derive recipient view tag secret"))?;
        let mut out = [0u8; BLINDING_LEN];
        Hkdf::<Sha256>::new(None, &recipient_secret)
            .expand_multi_info(&[b"TSPP/deposit/blinding", salt.as_slice()], &mut out)
            .map_err(|_| tx_error("failed to derive proofless blinding"))?;
        Ok(out)
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
pub mod testing;

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
            testing::MockHost::new(keypair)?,
            provider,
        ))
    }

    pub async fn create_private_wallet(
        &mut self,
        input: CreatePrivateWalletInput,
    ) -> Result<PrivateWallet> {
        if input.inbox != self.owner {
            return Err(WalletError::InboxOwnerMismatch);
        }
        if self.pending_host.is_none() {
            return Err(WalletError::PrivateWalletAlreadyCreated);
        }
        let mut network = self
            .network
            .state
            .lock()
            .map_err(|_| WalletError::LockPoisoned)?;
        if network.inboxes.contains_key(&input.inbox) {
            return Err(WalletError::InboxAlreadyRegistered);
        }
        network.next_wallet_id += 1;
        let id = PrivateWalletId(network.next_wallet_id);
        let mut host = self
            .pending_host
            .take()
            .ok_or(WalletError::PrivateWalletAlreadyCreated)?;
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
            .ok_or(WalletError::PrivateWalletNotFound)?;
        local.metadata.decryption_mode = input.mode;
        let mut network = self
            .network
            .state
            .lock()
            .map_err(|_| WalletError::LockPoisoned)?;
        let remote = network
            .wallets
            .get_mut(&input.private_wallet_id)
            .ok_or(WalletError::PrivateWalletNotFound)?;
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
            .ok_or(WalletError::PrivateWalletNotFound)?;
        let network = self
            .network
            .state
            .lock()
            .map_err(|_| WalletError::LockPoisoned)?;
        let transactions = network.transactions.clone();
        let assets = network.assets.clone();
        drop(network);
        let _state = local.host.read_state(private_wallet_id)?;
        let _tags = local
            .host
            .derive_view_tags(private_wallet_id, DeriveViewTagsRequest::RecipientBootstrap)?;
        let key_ops = HostWalletKeyProvider::new(private_wallet_id, local.host.as_ref())?;
        let report = local
            .wallet
            .sync(&key_ops, &transactions, &[], &assets, 1_700_000_000, 64)?;
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
            .ok_or(WalletError::PrivateWalletNotFound)?;
        let network = self
            .network
            .state
            .lock()
            .map_err(|_| WalletError::LockPoisoned)?;
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
            return Err(WalletError::PrivateWalletNotFound);
        }
        let network = self
            .network
            .state
            .lock()
            .map_err(|_| WalletError::LockPoisoned)?;
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
        Err(WalletError::Unsupported("deposit instruction"))
    }

    pub async fn send_private_transfer(
        &mut self,
        input: SendPrivateTransferInput,
    ) -> Result<SendPrivateTransferResult> {
        if input.amount == 0 {
            return Err(WalletError::InvalidAmount);
        }
        let sender = self
            .wallets
            .get_mut(&input.private_wallet_id)
            .ok_or(WalletError::PrivateWalletNotFound)?;
        let mut network = self
            .network
            .state
            .lock()
            .map_err(|_| WalletError::LockPoisoned)?;
        let recipient_id = *network
            .inboxes
            .get(&input.recipient)
            .ok_or(WalletError::RecipientPrivateWalletNotFound)?;
        let recipient = network
            .wallets
            .get(&recipient_id)
            .ok_or(WalletError::RecipientPrivateWalletNotFound)?
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
            return Err(WalletError::InsufficientPrivateBalance);
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
            .ok_or(WalletError::PrivateWalletNotFound)?;
        let key_ops = HostWalletKeyProvider::new(input.private_wallet_id, sender.host.as_ref())?;
        let view_tag = match viewing_entry
            .known_recipients
            .get(&recipient.shielded_public_key.viewing_pubkey)
        {
            Some(index) => key_ops
                .get_send_shared_view_tag(&recipient.shielded_public_key.viewing_pubkey, *index)
                .map_err(WalletError::from)?,
            None => recipient.shielded_public_key.viewing_pubkey.x(),
        };
        let sender_view_tag = key_ops
            .get_sender_view_tag(viewing_entry.tx_count)
            .map_err(WalletError::from)?;
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
        let tx_viewing_pk = key_ops.transaction_viewing_pubkey(&first_nullifier)?;
        let sender_ciphertext = key_ops.encrypt_transaction_slot(
            &first_nullifier,
            &sender_public_key.viewing_pubkey,
            &sender_plaintext.serialize()?,
            salt,
            0,
        )?;
        let recipient_ciphertext = key_ops.encrypt_transaction_slot(
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
            return Err(WalletError::InvalidAmount);
        }
        let local = self
            .wallets
            .get(&private_wallet_id)
            .ok_or(WalletError::PrivateWalletNotFound)?;
        let faucet = ShieldedKeypair::new()?;
        let mut network = self
            .network
            .state
            .lock()
            .map_err(|_| WalletError::LockPoisoned)?;
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
