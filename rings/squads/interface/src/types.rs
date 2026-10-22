//! Shared fixed-size byte vocabulary for account state, instruction data, and
//! ciphertexts. These are plain byte arrays so they (de)serialize with wincode
//! and bytemuck without a custom schema, keeping the interface crate free of any
//! keypair/SDK dependency.

use crate::constants::{
    ENCRYPTED_NULLIFIER_SECRET_LEN, PROOF_LEN, PROPOSAL_CIPHERTEXT_LEN, RECIPIENT_CIPHERTEXT_LEN,
    SENDER_CIPHERTEXT_LEN, SHARED_KEY_CIPHERTEXT_LEN, X25519_PUBKEY_LEN,
};

/// Solana address/pubkey as stored in account data. Re-exported so account and
/// instruction-data structs use the canonical type (it derives wincode
/// `SchemaRead`/`SchemaWrite` and bytemuck `Pod` under the enabled features).
pub use solana_address::Address;

/// Tagged X25519 public key (`0x04 || u`) (recovery/auditor/shared viewing keys).
pub type X25519Pubkey = [u8; X25519_PUBKEY_LEN];

/// AES-CTR ciphertext of the shared viewing secret, one per recipient key.
pub type SharedKeyCiphertext = [u8; SHARED_KEY_CIPHERTEXT_LEN];

/// AES-CTR ciphertext of the nullifier secret (no tag).
pub type EncryptedNullifierSecret = [u8; ENCRYPTED_NULLIFIER_SECRET_LEN];

/// Proposal ciphertext: ephemeral key + AES-GCM body + tag.
pub type ProposalCiphertext = [u8; PROPOSAL_CIPHERTEXT_LEN];

/// Sender change ciphertext (`amount(8) || asset(32)`).
pub type SenderCiphertext = [u8; SENDER_CIPHERTEXT_LEN];

/// Recipient output ciphertext (`amount(8) || asset(32) || blinding(32)`).
pub type RecipientCiphertext = [u8; RECIPIENT_CIPHERTEXT_LEN];

/// Compressed on-chain Groth16 proof (with BSB22 commitment + PoK).
pub type ProofBytes = [u8; PROOF_LEN];
