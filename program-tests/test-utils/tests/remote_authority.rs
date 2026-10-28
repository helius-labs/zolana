//! [`KeypairWalletAuthority`] over a keypair that is not a [`ShieldedKeypair`].
//!
//! This is the case the generic parameter exists for: a backend whose signing
//! key is device-resident implements [`ShieldedKeypairTrait`] and
//! [`ViewingKeyTrait`] and becomes a wallet authority, without reimplementing
//! any encryption body. The assertions pin it to the software authority, since
//! a wrong-but-well-formed identity still produces valid signatures and
//! correct-looking addresses.

use std::sync::atomic::{AtomicUsize, Ordering};

use spr_keypair::{
    derivation::{self, DERIVATION_PAYLOAD_PREFIX, ED25519_DERIVATION_MSG},
    hash,
    shielded::{CompressedShieldedAddress, ShieldedAddress},
    Curve, KeypairError, NullifierKey, PublicKey, ShieldedKeypair, ShieldedKeypairTrait,
    SigningKey, ViewingKey, X25519Pubkey,
};
use spr_test_utils::wallet::{KeypairWalletAuthority, SyncWalletAuthority};
use spr_transaction::{Address, TransactionError};

const SIGNING_SECRET: [u8; 32] = [31u8; 32];

/// Stands in for a remote custodian: the signing key is reachable only through
/// a call that this double counts, and the role secrets are held beside it —
/// the same shape as a hardware or remote-custody backend.
struct RemoteKeypair {
    device: SigningKey,
    nullifier_key: NullifierKey,
    viewing_key: ViewingKey,
    sign_calls: AtomicUsize,
}

impl RemoteKeypair {
    fn mirroring(keypair: &ShieldedKeypair) -> Self {
        Self {
            device: SigningKey::from_ed25519_bytes(&SIGNING_SECRET),
            nullifier_key: keypair.nullifier_key.clone(),
            viewing_key: keypair.viewing_key.clone(),
            sign_calls: AtomicUsize::new(0),
        }
    }
}

impl ShieldedKeypairTrait for RemoteKeypair {
    fn signing_pubkey(&self) -> PublicKey {
        self.device.pubkey()
    }

    fn viewing_pubkey(&self) -> X25519Pubkey {
        self.viewing_key.pubkey()
    }

    fn curve(&self) -> Curve {
        self.device.curve()
    }

    fn shielded_address(&self) -> Result<ShieldedAddress, KeypairError> {
        Ok(ShieldedAddress {
            signing_pubkey: self.signing_pubkey(),
            nullifier_pubkey: self.nullifier_key.pubkey()?,
            viewing_pubkey: self.viewing_key.pubkey(),
        })
    }

    fn owner_hash(&self) -> Result<[u8; 32], KeypairError> {
        hash::owner_hash(&self.signing_pubkey(), &self.nullifier_key.pubkey()?)
    }

    fn compressed_address(&self) -> Result<CompressedShieldedAddress, KeypairError> {
        Ok(CompressedShieldedAddress {
            owner_hash: self.owner_hash()?,
            viewing_pubkey: self.viewing_key.pubkey(),
        })
    }

    fn sign_message(&self, message: &[u8]) -> Result<[u8; 64], KeypairError> {
        if derivation::is_derivation_input(message) {
            return Err(KeypairError::DerivationInput);
        }
        self.sign_calls.fetch_add(1, Ordering::SeqCst);
        self.device.sign_message(message)
    }

    fn nullifier(
        &self,
        utxo_hash: &[u8; 32],
        blinding: &[u8; 32],
    ) -> Result<[u8; 32], KeypairError> {
        self.nullifier_key.nullifier(utxo_hash, blinding)
    }

    fn nullifier_key(&self) -> NullifierKey {
        self.nullifier_key.clone()
    }
}

// The viewing half of a backend with a host-side viewing key: one line, where
// twelve verbatim forwarding methods used to be.
spr_keypair::forward_viewing_key_trait!(RemoteKeypair => viewing_key);

fn software_keypair() -> ShieldedKeypair {
    ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&SIGNING_SECRET))
        .expect("software keypair")
}

/// Every identity the authority publishes is the same whether the keypair is a
/// `ShieldedKeypair` or a foreign backend built from the same key material.
fn remote_backend_publishes_the_same_identity() {
    let software = software_keypair();
    let remote = RemoteKeypair::mirroring(&software);

    let software_authority = KeypairWalletAuthority::new(Address::default(), &software);
    let remote_authority = KeypairWalletAuthority::with_viewing_keys(
        Address::default(),
        &remote,
        vec![software.viewing_key.clone()],
    )
    .expect("the keypair's own viewing key is supplied");

    assert_eq!(
        SyncWalletAuthority::shielded_address(&remote_authority).unwrap(),
        SyncWalletAuthority::shielded_address(&software_authority).unwrap()
    );
    assert_eq!(
        SyncWalletAuthority::spend_nullifier_key(&remote_authority)
            .unwrap()
            .pubkey()
            .unwrap(),
        SyncWalletAuthority::spend_nullifier_key(&software_authority)
            .unwrap()
            .pubkey()
            .unwrap()
    );
    assert_eq!(
        SyncWalletAuthority::viewing_keys(&remote_authority)
            .unwrap()
            .iter()
            .map(|key| key.pubkey())
            .collect::<Vec<_>>(),
        SyncWalletAuthority::viewing_keys(&software_authority)
            .unwrap()
            .iter()
            .map(|key| key.pubkey())
            .collect::<Vec<_>>()
    );
}

/// Ed25519 signatures match the software path while remaining device-resident.
fn remote_backend_signs_through_the_trait() {
    let software = software_keypair();
    let remote = RemoteKeypair::mirroring(&software);
    let digest = [7; 32];
    assert_eq!(
        ShieldedKeypairTrait::sign_message(&remote, &digest).unwrap(),
        software.sign_message(&digest).unwrap()
    );
    assert_eq!(remote.sign_calls.load(Ordering::SeqCst), 1);
}

/// The encryption bodies run unchanged over the foreign backend: the
/// per-transaction viewing key is derived from the same viewing secret, so the
/// published `tx_viewing_pk` matches. (Only that field is deterministic — the
/// salt is random per call.)
fn remote_backend_encrypts_with_the_same_transaction_key() {
    let software = software_keypair();
    let remote = RemoteKeypair::mirroring(&software);
    let first_nullifier = [3u8; 32];

    let remote_authority = KeypairWalletAuthority::with_viewing_keys(
        Address::default(),
        &remote,
        vec![software.viewing_key.clone()],
    )
    .expect("the keypair's own viewing key is supplied");
    let software_authority = KeypairWalletAuthority::new(Address::default(), &software);

    let from_remote = SyncWalletAuthority::encrypt_confidential_transfer(
        &remote_authority,
        &first_nullifier,
        &[],
    )
    .unwrap();
    let from_software = SyncWalletAuthority::encrypt_confidential_transfer(
        &software_authority,
        &first_nullifier,
        &[],
    )
    .unwrap();

    assert_eq!(from_remote.tx_viewing_pk, from_software.tx_viewing_pk);
}

/// Refuse derivation-shaped messages before exposing role derivation material.
fn derivation_shaped_payloads_are_refused_before_signing() {
    let software = software_keypair();
    let mut prefixed = [0u8; 32];
    prefixed[..DERIVATION_PAYLOAD_PREFIX.len()].copy_from_slice(DERIVATION_PAYLOAD_PREFIX);
    for message in [prefixed.as_slice(), ED25519_DERIVATION_MSG] {
        assert_eq!(
            ShieldedKeypairTrait::sign_message(&software, message),
            Err(KeypairError::DerivationInput)
        );
    }
    assert!(ShieldedKeypairTrait::sign_message(&software, &[7; 32]).is_ok());
}

/// A rotated-out viewing key can now be supplied, which the keypair-only
/// constructor cannot express — a `ShieldedKeypair` holds exactly one.
fn historical_viewing_keys_are_carried_through() {
    let software = software_keypair();
    let remote = RemoteKeypair::mirroring(&software);
    let retired = ViewingKey::from_bytes(&[9u8; 32]);

    let authority = KeypairWalletAuthority::with_viewing_keys(
        Address::default(),
        &remote,
        vec![software.viewing_key.clone(), retired.clone()],
    )
    .expect("the keypair's own viewing key is supplied");

    assert_eq!(
        SyncWalletAuthority::viewing_keys(&authority)
            .unwrap()
            .iter()
            .map(|key| key.pubkey())
            .collect::<Vec<_>>(),
        vec![software.viewing_key.pubkey(), retired.pubkey()]
    );
}

/// A viewing-key set that omits the keypair's own is refused at construction.
/// The encryption bodies key off the keypair while a scan keys off this vector,
/// so accepting the pair would build a wallet that encrypts to one key and
/// scans with another.
fn viewing_keys_must_contain_the_keypairs_own() {
    let software = software_keypair();
    let remote = RemoteKeypair::mirroring(&software);
    let unrelated = ViewingKey::from_bytes(&[4u8; 32]);

    assert!(matches!(
        KeypairWalletAuthority::with_viewing_keys(
            Address::default(),
            &remote,
            vec![unrelated.clone()],
        ),
        Err(TransactionError::AuthorityViewingKeyMismatch)
    ));
    assert!(matches!(
        KeypairWalletAuthority::with_viewing_keys(Address::default(), &remote, Vec::new()),
        Err(TransactionError::AuthorityViewingKeyMismatch)
    ));

    // Extra keys alongside the current one are fine: that is key rotation.
    assert!(KeypairWalletAuthority::with_viewing_keys(
        Address::default(),
        &remote,
        vec![unrelated, software.viewing_key.clone()],
    )
    .is_ok());
}

#[test]
fn a_remote_keypair_backend_is_a_wallet_authority() {
    remote_backend_publishes_the_same_identity();
    remote_backend_signs_through_the_trait();
    remote_backend_encrypts_with_the_same_transaction_key();
    historical_viewing_keys_are_carried_through();
    viewing_keys_must_contain_the_keypairs_own();
    derivation_shaped_payloads_are_refused_before_signing();
}

#[test]
fn confidential_encryption_preserves_mint_id_and_ring() {
    use borsh::BorshDeserialize;
    use spr_event::OutputDataEncoding;
    use spr_transaction::{
        serialization::confidential::{Confidential, ConfidentialOutputPlaintext},
        Data, EncryptedScheme, Mint, SppProofOutputUtxo,
    };
    let owner = software_keypair();
    let authority = KeypairWalletAuthority::new(Address::default(), &owner);
    let ring = Address::new_from_array([9; 32]);
    let mint = Mint {
        asset: Address::new_from_array([7; 32]),
        asset_id: 7,
    };
    let mut output = SppProofOutputUtxo::new(mint, 42, owner.shielded_address().unwrap()).unwrap();
    output.ring_program_id = Some(ring);
    let first_nullifier = [3; 32];
    let encrypted = SyncWalletAuthority::encrypt_confidential_transfer(
        &authority,
        &first_nullifier,
        &[output.clone()],
    )
    .unwrap();
    let [slot] = encrypted.payload.as_slice() else {
        panic!("one output ciphertext expected")
    };
    let OutputDataEncoding::Encrypted(blob) =
        OutputDataEncoding::try_from_slice(&slot.data).unwrap()
    else {
        panic!("encrypted output expected")
    };
    let (scheme, body) = blob.split_first().unwrap();
    assert_eq!(*scheme, EncryptedScheme::RingConfidential.as_byte());
    assert_eq!(
        slot.view_tag,
        owner.signing_pubkey().confidential_view_tag().unwrap()
    );
    let key = owner.get_transaction_viewing_key(&first_nullifier).unwrap();
    assert_eq!(
        Confidential::decrypt_with_tx_key(&key, body, encrypted.salt, 0).unwrap(),
        ConfidentialOutputPlaintext {
            asset_id: 7,
            amount: 42,
            blinding: output.blinding,
            ring_program_id: Some(ring),
            data: Data::default(),
        }
    );
}
