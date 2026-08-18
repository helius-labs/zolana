use custom_ring_program::error::CustomRingError::*;

#[test]
fn error_codes_are_stable() {
    let table = [
        (InvalidInstructionData as u32, 8100),
        (ProofVerificationFailed as u32, 8101),
        (HashingFailed as u32, 8102),
        (InvalidShieldedPoolProgram as u32, 8103),
        (MissingRingAuth as u32, 8104),
        (ConfigAlreadyInitialized as u32, 8105),
        (ConfigNotInitialized as u32, 8106),
        (UnauthorizedAuthority as u32, 8107),
        (InvalidAuditorPubkey as u32, 8108),
        (MissingAuditorMessage as u32, 8109),
        (InvalidAuditorMessage as u32, 8110),
        (InvalidSystemProgram as u32, 8111),
        (InvalidConfigPda as u32, 8112),
        (UnsupportedCircuit as u32, 8113),
    ];
    for (got, want) in table {
        assert_eq!(got, want, "error code drifted");
    }
}
