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
        (TakeProofCountMismatch as u32, 8017),
        (InvalidVkRegistryAccount as u32, 8018),
        (InvalidVkRegistryIndex as u32, 8019),
        (VkRegistryAlreadyInitialized as u32, 8020),
        (VkRegistryNotReady as u32, 8021),
        (VkRegistryInitFailed as u32, 8022),
        (SerializationFailed as u32, 8023),
    ];
    for (got, want) in table {
        assert_eq!(got, want, "error code drifted");
    }
}
