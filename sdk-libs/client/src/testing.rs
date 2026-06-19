use zolana_keypair::constants::BLINDING_LEN;
use zolana_keypair::{P256Pubkey, ShieldedKeypair};

use crate::{
    ApprovalRequest, DeriveViewTagsRequest, HeliusPrivacyInterface, P256Signature, PrivateWalletId,
    Result, ShieldedPublicKey, ViewTag, WalletError,
};

pub use crate::backend::{InMemoryPrivacyProvider, ProviderParts};

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

