use dynamic_swap_program::error::DynamicSwapError::*;

#[test]
fn error_codes_are_stable() {
    let table = [
        (Expired as u32, 9000),
        (NotYetExpired as u32, 9001),
        (ProofVerificationFailed as u32, 9002),
        (InvalidInstructionData as u32, 9003),
        (InvalidShieldedPoolProgram as u32, 9004),
        (MissingPoolAuthority as u32, 9005),
        (MissingEscrowAuthority as u32, 9006),
        (HashingFailed as u32, 9007),
        (InvalidPda as u32, 9008),
        (Unauthorized as u32, 9012),
        (CreatedAtOutOfTolerance as u32, 9014),
        (PairMismatch as u32, 9015),
        (InvalidPrice as u32, 9016),
        (InsufficientCapacity as u32, 9018),
        (InvalidCapacity as u32, 9019),
    ];
    for (got, want) in table {
        assert_eq!(got, want, "error code drifted");
    }
}
