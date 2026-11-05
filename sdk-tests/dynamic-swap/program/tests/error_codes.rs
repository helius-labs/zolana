use dynamic_swap_program::error::DynamicSwapError::*;

#[test]
fn error_codes_are_stable() {
    // 9009-9011, 9013, 9014, 9018, 9019 and 9024 are retired; see error.rs.
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
        (PairMismatch as u32, 9015),
        (InvalidPrice as u32, 9016),
        (RentRecipientMismatch as u32, 9017),
        (InvalidEncryptionPubkey as u32, 9020),
        (InvalidExpiry as u32, 9021),
        (InsufficientLiquidity as u32, 9022),
        (InvalidMaxOrderSize as u32, 9023),
        (InvalidDepositAmount as u32, 9025),
        (InterfaceTransferMismatch as u32, 9026),
        (InvalidWithdrawalAmount as u32, 9027),
        (InvalidPriceTolerance as u32, 9028),
        (InvalidMinOrderAmount as u32, 9029),
        (PublicPriceFloorOutOfRange as u32, 9030),
        (PriceBelowTolerance as u32, 9031),
        (NotQueueHead as u32, 9032),
        (EscrowCancelled as u32, 9033),
    ];
    for (got, want) in table {
        assert_eq!(got, want, "error code drifted");
    }
}
