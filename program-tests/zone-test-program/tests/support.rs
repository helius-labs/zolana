//! Shared contract types for the zone lifecycle suite.
//!
//! These types are the stable surface the per-instruction step modules drive
//! against. They live here (not inside a single step module) so the
//! zone_transact / merge_zone / zone_authority_transact steps can depend on a
//! frozen contract without editing `world.rs` or each other's modules.

#![allow(dead_code)]

use solana_pubkey::Pubkey;

/// Which ownership rail the last zone transact / merge took. P256 proves
/// ownership inside the proof; Eddsa proves it with an ed25519 signature on the
/// transaction, checked by the program against the eddsa signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Rail {
    P256,
    Eddsa,
}

/// An SPL asset a scenario registers: its mint, the vault the deposit credits,
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
