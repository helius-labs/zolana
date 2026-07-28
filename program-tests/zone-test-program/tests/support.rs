//! Shared contract types for the zone lifecycle suite.

use solana_pubkey::Pubkey;

/// Which ownership rail the last zone transact / merge took. Post-PR164 only
/// the eddsa rail remains: ownership is proven with an ed25519 signature on the
/// transaction, checked by the program against the eddsa signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Variant {
    Eddsa,
}

/// A registered SPL asset: its mint, the vault the deposit credits,
/// and the shared funding token account (owned by the payer).
#[derive(Clone, Copy)]
pub(crate) struct SplAsset {
    pub(crate) mint: Pubkey,
    pub(crate) vault: Pubkey,
    pub(crate) user_token: Pubkey,
}

/// What the consolidated-output assert needs after a `merge_zone`: the actor that
/// owns the appended output and the output's hash (for the inclusion-proof check).
pub(crate) struct MergeZoneRecord {
    pub(crate) actor: String,
    pub(crate) output_hash: [u8; 32],
}
