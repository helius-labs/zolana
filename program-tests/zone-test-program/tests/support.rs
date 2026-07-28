//! Shared contract types for the zone lifecycle suite.

/// A second zone fixture program id (deployed from the same
/// `zone_test_program.so`), used to prove configs are per-program.
pub(crate) const SECOND_ZONE_TEST_PROGRAM_ID: [u8; 32] = [42u8; 32];

/// Which ownership rail the last zone transact / merge took. Post-PR164 only
/// the eddsa rail remains: ownership is proven with an ed25519 signature on the
/// transaction, checked by the program against the eddsa signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Variant {
    Eddsa,
}

/// What the consolidated-output assert needs after a `merge_zone`: the actor that
/// owns the appended output and the output's hash (for the inclusion-proof check).
pub(crate) struct MergeZoneRecord {
    pub(crate) actor: String,
    pub(crate) output_hash: [u8; 32],
}
