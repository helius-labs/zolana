//! Squads ring interface: shared instruction data, account state, ciphertext
//! types, and verifying keys for the on-chain program, the SDK, and tests.

pub mod circuits;
pub mod constants;
pub mod error;
pub mod event;
pub mod instruction;
pub mod state;
pub mod types;
#[cfg(feature = "verifying-keys")]
pub mod verifying_keys;

/// Decode a base58 program id into a `[u8; 32]` const at compile time.
#[macro_export]
macro_rules! pubkey_array {
    ($address:literal) => {{
        const _PK: ::solana_pubkey::Pubkey = ::solana_pubkey::Pubkey::from_str_const($address);
        _PK.to_bytes()
    }};
}

/// Development program id for the Squads ring program.
pub const SQUADS_RING_PROGRAM_ID: [u8; 32] =
    pubkey_array!("62EpnphqgmKwc1x9nfnLVvxGBNF8cdkrfvWPnY5VECAo");

/// [`SQUADS_RING_PROGRAM_ID`] as a `Pubkey`, used by instruction builders.
pub const PROGRAM_ID_PUBKEY: solana_pubkey::Pubkey =
    solana_pubkey::Pubkey::new_from_array(SQUADS_RING_PROGRAM_ID);

// PDA seeds (this program's accounts).
/// Singleton ring configuration PDA: `[b"ring_config"]`.
pub const RING_CONFIG_PDA_SEED: &[u8] = b"ring_config";
/// Per-owner viewing key account PDA: `[b"viewing_key_account", owner]`.
pub const VIEWING_KEY_ACCOUNT_PDA_SEED: &[u8] = b"viewing_key_account";
/// Async proposal PDA: `[b"proposal", owner, cipher_text[0..33]]`.
pub const PROPOSAL_PDA_SEED: &[u8] = b"proposal";
/// Key-update proposal PDA: `[b"key_update_proposal", target, domain, key_nonce]`.
pub const KEY_UPDATE_PROPOSAL_PDA_SEED: &[u8] = b"key_update_proposal";
/// CPI-authority PDA that signs SPP CPIs. The shielded pool derives the same
/// address from its own seed and rejects any other, so the seed is taken from
/// there and never redeclared here.
pub use zolana_interface::RING_AUTH_PDA_SEED;
