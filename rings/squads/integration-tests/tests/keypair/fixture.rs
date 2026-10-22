//! Deterministic Ed25519 owner keys for the keypair-rail suite and the backend
//! auditor key. A user keeps only its owner (signing) key; the viewing and
//! nullifier secrets are minted by the backend when it creates the viewing key
//! account and recovered through the auditor key.

use solana_pubkey::Pubkey;
use squads_ring_tests::localnet::viewing_key_account_pda;
use zolana_keypair::SigningKey;
use zolana_keypair::X25519Keypair;

/// SHA-256 of `domain || name` with the top byte cleared, a valid BN254 field
/// element and Ed25519 seed.
fn field_element(name: &str, domain: &[u8]) -> [u8; 32] {
    let mut input = domain.to_vec();
    input.extend_from_slice(name.as_bytes());
    let mut out = zolana_keypair::hash::sha256_be(&input);
    if let Some(top) = out.first_mut() {
        *top = 0;
    }
    out
}

pub(crate) struct OwnerKeypair {
    secret: [u8; 32],
}

impl OwnerKeypair {
    pub(crate) fn owner_pubkey_bytes(&self) -> [u8; 32] {
        self.signing_key()
            .pubkey()
            .as_ed25519()
            .expect("Ed25519 owner")
    }

    /// The SPP owner identity, stored as the viewing key account `owner`.
    pub(crate) fn owner_identity(&self) -> [u8; 32] {
        self.signing_key()
            .pubkey()
            .owner_proof_input_hash()
            .expect("Ed25519 owner identity")
    }

    pub(crate) fn signing_key(&self) -> SigningKey {
        SigningKey::from_ed25519_bytes(&self.secret)
    }

    pub(crate) fn viewing_key_account(&self) -> Pubkey {
        viewing_key_account_pda(&self.owner_identity())
    }
}

pub(crate) fn owner_keypair(name: &str) -> OwnerKeypair {
    OwnerKeypair {
        secret: field_element(name, b"squads-vka-owner-sk"),
    }
}

pub(crate) fn viewing_key_account_address(name: &str) -> Pubkey {
    owner_keypair(name).viewing_key_account()
}

/// The backend auditor secret, also the auditor key configured in the ring
/// config.
pub(crate) fn auditor_secret() -> X25519Keypair {
    X25519Keypair::from_bytes(&field_element("auditor", b"squads-ring-auditor-sk"))
}
