//! Layout primitives and policy constants shared by program, SDK, and tests.

// Cryptographic primitive lengths.
/// SEC1-compressed P-256 public key.
pub const P256_PUBKEY_LEN: usize = 33;
/// AES-CTR ciphertext of the 32-byte shared viewing secret (one per recipient).
pub const SHARED_KEY_CIPHERTEXT_LEN: usize = 32;
/// AES-CTR ciphertext of the 31-byte nullifier secret (no tag).
pub const ENCRYPTED_NULLIFIER_SECRET_LEN: usize = 31;
/// Proposal ciphertext: 33-byte ephemeral key + 39-byte AES-GCM body + 16-byte tag.
pub const PROPOSAL_CIPHERTEXT_LEN: usize = 88;
/// Sender change ciphertext: `amount(8) || asset(32)`, AES-CTR, no tag.
pub const SENDER_CIPHERTEXT_LEN: usize = 40;
/// Recipient output ciphertext: `amount(8) || asset(32) || blinding(31)`, AES-CTR.
pub const RECIPIENT_CIPHERTEXT_LEN: usize = 71;
/// On-chain Groth16 proof: compressed (32 + 64 + 32) plus BSB22 commitment + PoK
/// (32 + 32). Both zone circuits carry a commitment.
pub const PROOF_LEN: usize = 192;

// ViewingKeyAccount.state values.
pub const VIEWING_KEY_STATE_ACTIVE: u8 = 0;
pub const VIEWING_KEY_STATE_BLOCKED: u8 = 1;

// ViewingKeyAccount.encryption_scheme values.
pub const ENCRYPTION_SCHEME_P256_AES: u8 = 1;

// ViewingKeyAccount.owner_kind values. A keypair/P256 owner spends via the P256 SPP
// rail (owner signature); a smart-account owner (a Squads vault, no signing key)
// settles signatureless via the zone-authority SPP rail, authorized by the co-signer
// and, for the async path, an approved proposal.
pub const OWNER_KIND_KEYPAIR: u8 = 0;
pub const OWNER_KIND_SMART_ACCOUNT: u8 = 1;

// KeyOperation.op values.
pub const KEY_OP_ADD: u8 = 0;
pub const KEY_OP_REMOVE: u8 = 1;
pub const KEY_OP_REPLACE: u8 = 2;
pub const KEY_OP_UPDATE_AUDITOR: u8 = 3;

/// The zone supports exactly one auditor key for now (spec).
pub const REQUIRED_AUDITOR_KEY_COUNT: usize = 1;
