use timelock_escrow_program::error::TimelockEscrowError::*;

#[test]
fn error_codes_are_stable() {
    let table = [
        (ProofVerificationFailed as u32, 9000),
        (InvalidInstructionData as u32, 9001),
        (InvalidShieldedPoolProgram as u32, 9002),
        (MissingEscrowAuthority as u32, 9003),
        (HashingFailed as u32, 9004),
        (NotYetUnlocked as u32, 9005),
    ];
    for (got, want) in table {
        assert_eq!(got, want, "error code drifted");
    }
}
