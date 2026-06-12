use anchor_lang::prelude::*;

#[error_code]
pub enum UserRegistryError {
    #[msg("P-256 compressed pubkey prefix must be 0x02 or 0x03")]
    InvalidP256Prefix,
    #[msg("nullifier_pubkey must be a canonical BN254 field element (< Fr)")]
    NonCanonicalNullifierPubkey,
    #[msg("no sync delegate is currently set")]
    SyncDelegateNotSet,
    #[msg("signer is not the owner or active sync delegate")]
    UnauthorizedSigner,
    #[msg("signer does not match the active sync delegate")]
    InvalidSyncDelegate,
    #[msg("record cannot be closed while sync delegate entries are non-empty")]
    RecordNotEmpty,
}
