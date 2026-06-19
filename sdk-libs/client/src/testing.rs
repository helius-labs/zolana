use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use zolana_interface::event::DepositView;
use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::{P256Pubkey, ShieldedKeypair};
use zolana_transaction::wallet::SyncTransaction;
use zolana_transaction::{Address, AssetRegistry};

use crate::{
    ApprovalRequest, DeriveViewTagsRequest, HeliusPrivacyInterface, P256Signature,
    PrivateTransaction, PrivateWallet, PrivateWalletId, Result, ShieldedPublicKey, ViewTag,
    WalletError,
};

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

#[derive(Clone)]
pub(crate) struct PrivacyNetwork {
    pub(crate) state: Arc<Mutex<NetworkState>>,
}

impl PrivacyNetwork {
    pub(crate) fn new() -> Self {
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

#[derive(Default)]
pub(crate) struct NetworkState {
    pub(crate) next_wallet_id: u64,
    pub(crate) next_asset_id: u64,
    pub(crate) next_counter: u64,
    pub(crate) next_signature: u64,
    pub(crate) wallets: HashMap<PrivateWalletId, PrivateWallet>,
    pub(crate) inboxes: HashMap<Address, PrivateWalletId>,
    pub(crate) transactions: Vec<SyncTransaction>,
    pub(crate) proofless_deposits: Vec<DepositView>,
    pub(crate) history: HashMap<PrivateWalletId, Vec<PrivateTransaction>>,
    pub(crate) assets: AssetRegistry,
}

impl NetworkState {
    pub(crate) fn asset_id_for_mint(&mut self, mint: Address) -> Result<u64> {
        if let Ok(asset_id) = self.assets.asset_id(&mint) {
            return Ok(asset_id);
        }
        self.next_asset_id = self.next_asset_id.max(2);
        let asset_id = self.next_asset_id;
        self.next_asset_id += 1;
        self.assets.insert(asset_id, mint)?;
        Ok(asset_id)
    }

    pub(crate) fn unique_blinding(&mut self) -> [u8; BLINDING_LEN] {
        self.next_counter += 1;
        let mut out = [0u8; BLINDING_LEN];
        out[0] = 0x42;
        out[1..9].copy_from_slice(&self.next_counter.to_be_bytes());
        out
    }

    pub(crate) fn next_signature(&mut self) -> String {
        self.next_signature += 1;
        format!("mock-signature-{}", self.next_signature)
    }
}

pub struct MockHost {
    pub keypair: ShieldedKeypair,
    pub private_wallet_created: bool,
    pub encrypted_state: Option<Vec<u8>>,
}

impl MockHost {
    pub fn new(keypair: ShieldedKeypair) -> Result<Self> {
        Ok(Self {
            keypair,
            private_wallet_created: false,
            encrypted_state: None,
        })
    }
}

impl HeliusPrivacyInterface for MockHost {
    fn create_p256_keypair(&mut self, _wallet_id: PrivateWalletId) -> Result<ShieldedPublicKey> {
        if self.private_wallet_created {
            return Err(WalletError::PrivateWalletAlreadyCreated);
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

    fn ecdh_p256(&self, _wallet_id: PrivateWalletId, public_key: &P256Pubkey) -> Result<[u8; 32]> {
        Ok(self.keypair.viewing_key.ecdh(public_key)?)
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
        match request {
            DeriveViewTagsRequest::RecipientBootstrap => {
                Ok(vec![self.keypair.recipient_bootstrap_view_tag()])
            }
            DeriveViewTagsRequest::Sender { start, limit } => (start..start.saturating_add(limit))
                .map(|index| {
                    self.keypair
                        .get_sender_view_tag(index)
                        .map_err(WalletError::from)
                })
                .collect(),
            DeriveViewTagsRequest::RecipientRequest { start, limit } => (start
                ..start.saturating_add(limit))
                .map(|index| {
                    self.keypair
                        .get_recipient_request_view_tag(index)
                        .map_err(WalletError::from)
                })
                .collect(),
            DeriveViewTagsRequest::SendShared {
                counterparty,
                start,
                limit,
            } => (start..start.saturating_add(limit))
                .map(|index| {
                    self.keypair
                        .get_send_shared_view_tag(&counterparty, index)
                        .map_err(WalletError::from)
                })
                .collect(),
            DeriveViewTagsRequest::RecipientShared {
                counterparty,
                start,
                limit,
            } => (start..start.saturating_add(limit))
                .map(|index| {
                    self.keypair
                        .get_recipient_shared_view_tag(&counterparty, index)
                        .map_err(WalletError::from)
                })
                .collect(),
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
