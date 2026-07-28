//! Shared contract types for the zone lifecycle suite.

/// A second zone fixture program id (deployed from the same
/// `zone_test_program.so`), used to prove configs are per-program.
pub(crate) const SECOND_ZONE_TEST_PROGRAM_ID: [u8; 32] = [42u8; 32];

/// What the consolidated-output assert needs after a `merge_zone`: the actor that
/// owns the appended output and the output's hash (for the inclusion-proof check).
pub(crate) struct MergeZoneRecord {
    pub(crate) actor: String,
    pub(crate) output_hash: [u8; 32],
}
