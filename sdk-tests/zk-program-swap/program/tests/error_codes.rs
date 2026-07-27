use swap_program::error::SwapError::*;

#[test]
fn error_codes_are_stable() {
    let table = [
        (Expired as u32, 8005),
        (NotYetExpired as u32, 8006),
        (ProofVerificationFailed as u32, 8007),
        (InvalidInstructionData as u32, 8011),
        (InvalidShieldedPoolProgram as u32, 8012),
        (MissingOrderAuthority as u32, 8013),
        (InvalidMarkerMessage as u32, 8014),
        (MarkerDataNotEmpty as u32, 8015),
        (HashingFailed as u32, 8016),
    ];
    for (got, want) in table {
        assert_eq!(got, want, "error code drifted");
    }
}
