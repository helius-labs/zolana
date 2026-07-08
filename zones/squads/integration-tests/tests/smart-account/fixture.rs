//! Public identities for the Squads SMART ACCOUNT lifecycle suite.
//!
//! Viewing key accounts are no longer genesis-seeded with deterministic secrets;
//! they are created at runtime through the backend
//! (`request_create_viewing_key_account`), which mints RANDOM viewing / nullifier
//! secrets recoverable only via the auditor key. This module therefore holds only
//! PUBLIC identity data: the vault sender's `owner_pk_field`, each P256 recipient's
//! `owner_pk_field`, the canonical viewing-key-account PDA derivation, the backend
//! auditor key (also the auditor configured in `zone_config`), and the fixed
//! scenario amounts. Every secret lives in the backend and is recovered from the
//! on-chain account plus the auditor key.

use p256::SecretKey;
use solana_pubkey::Pubkey;
use zolana_keypair::{P256Pubkey, PublicKey};
use zolana_squads_interface::{PROGRAM_ID_PUBKEY, VIEWING_KEY_ACCOUNT_PDA_SEED};
use zolana_test_utils::smart_account;

/// The smart-account sender name (a single vault identity that owns every UTXO the
/// scenarios deposit and spend). All scenario "sender" names map to this identity.
pub(crate) const VAULT_SENDER: &str = "vault";

/// Transfer recipients that are ordinary P256 identities (not the vault sender). A
/// name not in this list is treated as the smart-account vault sender.
pub(crate) const P256_RECIPIENTS: [&str; 1] = ["wendy"];

/// The seed index of the proposer smart account created by the World bootstrap.
pub(crate) const PROPOSER_SETTINGS_SEED: u128 = 6;

/// The fixed withdrawal amount for the async SOL withdrawal-proposal scenario.
pub(crate) const PROPOSAL_WITHDRAWN: u64 = 2_000_000_000;

/// The fixed transfer amount for the async transfer-proposal scenario.
pub(crate) const TRANSFER_PROPOSAL_AMOUNT: u64 = 1_000_000_000;

/// Whether `name` addresses the smart-account vault sender (rather than a P256
/// recipient).
pub(crate) fn is_vault_sender(name: &str) -> bool {
    !P256_RECIPIENTS.contains(&name)
}

/// The proposer smart account's `settings` PDA.
pub(crate) fn proposer_settings() -> Pubkey {
    smart_account::settings_pda(PROPOSER_SETTINGS_SEED).0
}

/// The proposer smart account's vault (account index 0), which owns the shielded
/// UTXOs and is the deposit/transact executor.
pub(crate) fn proposer_vault() -> Pubkey {
    smart_account::smart_account_pda(&proposer_settings(), 0).0
}

/// The vault's shielded owner field element (`owner_pk_field = hash_field(vault)`),
/// the on-chain `owner` of the smart-account sender viewing key account.
pub(crate) fn vault_owner_field() -> [u8; 32] {
    PublicKey::from_ed25519(&proposer_vault().to_bytes())
        .owner_pk_field()
        .expect("owner pk field")
}

/// A P256 recipient's `owner_pk_field`, derived from a deterministic P256 owner
/// public key. This is the on-chain `owner` the recipient's viewing key account is
/// created with; it is public identity data (a hash of a public key), not a secret
/// the suite decrypts with.
pub(crate) fn recipient_owner_field(name: &str) -> [u8; 32] {
    let owner_secret = field_element(name, b"squads-vka-owner-sk");
    let owner_sk = SecretKey::from_slice(&owner_secret).expect("valid p256 owner scalar");
    let owner_p256 = P256Pubkey::from_p256(&owner_sk.public_key());
    PublicKey::from_p256(&owner_p256)
        .owner_pk_field()
        .expect("owner pk field")
}

/// The `owner_pk_field` for `name`: the vault field for a vault sender, otherwise
/// the recipient's derived owner field.
pub(crate) fn owner_field(name: &str) -> [u8; 32] {
    if is_vault_sender(name) {
        vault_owner_field()
    } else {
        recipient_owner_field(name)
    }
}

/// The canonical viewing-key-account PDA for `name`
/// (`find_program_address([VIEWING_KEY_ACCOUNT_PDA_SEED, owner], squads_program)`),
/// where the backend created it at runtime.
pub(crate) fn viewing_key_account_pda(name: &str) -> Pubkey {
    Pubkey::find_program_address(
        &[VIEWING_KEY_ACCOUNT_PDA_SEED, owner_field(name).as_ref()],
        &PROGRAM_ID_PUBKEY,
    )
    .0
}

/// A field element derived from `name` and `domain`: SHA256 with the top byte
/// cleared so it is `< 2^248 < BN254 modulus < P-256 order`.
fn field_element(name: &str, domain: &[u8]) -> [u8; 32] {
    let mut input = domain.to_vec();
    input.extend_from_slice(name.as_bytes());
    let mut out = zolana_keypair::hash::sha256_be(&input);
    out[0] = 0;
    out
}

/// The backend's deterministic auditor P256 secret. It is also the auditor key
/// configured in `zone_config`, so the shared viewing key each account publishes
/// (encrypted to this key) is recoverable by the backend.
pub(crate) fn auditor_secret() -> SecretKey {
    SecretKey::from_slice(&field_element("auditor", b"squads-zone-auditor-sk"))
        .expect("valid p256 auditor scalar")
}

/// The auditor's compressed P256 public key.
pub(crate) fn auditor_pubkey() -> P256Pubkey {
    P256Pubkey::from_p256(&auditor_secret().public_key())
}
