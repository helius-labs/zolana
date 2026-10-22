//! Public identities of the smart-account suite. Every sender name maps to the
//! proposer smart account's vault; the names in [`ED25519_RECIPIENTS`] are Ed25519
//! identities that only receive. The backend holds every viewing and
//! nullifier secret, recovered through the auditor key.

use solana_pubkey::Pubkey;
use squads_ring_tests::localnet::viewing_key_account_pda;
use zolana_keypair::X25519Keypair;
use zolana_keypair::{PublicKey, SigningKey};
use zolana_test_utils::smart_account;

pub(crate) const VAULT_SENDER: &str = "vault";

pub(crate) const ED25519_RECIPIENTS: [&str; 1] = ["wendy"];

/// The five standard role smart accounts take seeds 1..=5.
pub(crate) const PROPOSER_SETTINGS_SEED: u128 = 6;

pub(crate) const PROPOSAL_WITHDRAWN: u64 = 2_000_000_000;

pub(crate) const TRANSFER_PROPOSAL_AMOUNT: u64 = 1_000_000_000;

pub(crate) fn is_vault_sender(name: &str) -> bool {
    !ED25519_RECIPIENTS.contains(&name)
}

pub(crate) fn proposer_settings() -> Pubkey {
    smart_account::settings_pda(PROPOSER_SETTINGS_SEED).0
}

pub(crate) fn proposer_vault() -> Pubkey {
    smart_account::smart_account_pda(&proposer_settings(), 0).0
}

pub(crate) fn vault_owner_identity() -> [u8; 32] {
    PublicKey::from_pda(&proposer_vault())
        .owner_proof_input_hash()
        .expect("vault owner identity")
}

fn field_element(name: &str, domain: &[u8]) -> [u8; 32] {
    let mut input = domain.to_vec();
    input.extend_from_slice(name.as_bytes());
    let mut out = zolana_keypair::hash::sha256_be(&input);
    if let Some(top) = out.first_mut() {
        *top = 0;
    }
    out
}

pub(crate) fn recipient_owner_identity(name: &str) -> [u8; 32] {
    SigningKey::from_ed25519_bytes(&field_element(name, b"squads-vka-owner-sk"))
        .pubkey()
        .owner_proof_input_hash()
        .expect("Ed25519 owner identity")
}

pub(crate) fn owner_identity(name: &str) -> [u8; 32] {
    if is_vault_sender(name) {
        vault_owner_identity()
    } else {
        recipient_owner_identity(name)
    }
}

pub(crate) fn viewing_key_account_address(name: &str) -> Pubkey {
    viewing_key_account_pda(&owner_identity(name))
}

pub(crate) fn auditor_secret() -> X25519Keypair {
    X25519Keypair::from_bytes(&field_element("auditor", b"squads-ring-auditor-sk"))
}
