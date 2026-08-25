use custom_ring_program::CustomRingError::*;

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
        (UnauthorizedInitializer as u32, 8114),
        (TooManyAccounts as u32, 8115),
        (ReadAccessRecordAlreadyExists as u32, 8116),
        (InvalidReadAccessRecord as u32, 8117),
        (InvalidReaderKey as u32, 8118),
        (UnsupportedOutputScheme as u32, 8119),
        (PolicyConfigAlreadyInitialized as u32, 8120),
        (PolicyConfigNotInitialized as u32, 8121),
        (InvalidPolicyConfigPda as u32, 8122),
        (PolicyHashMismatch as u32, 8123),
        (InvalidPolicyMember as u32, 8124),
        (UnauthorizedRecordSigner as u32, 8125),
        (InvalidRecordKind as u32, 8126),
        (InvalidRecordState as u32, 8127),
        (EmptyPolicy as u32, 8128),
        (InvalidPolicyTree as u32, 8129),
        (RecordVersionOverflow as u32, 8130),
        (InvalidRecordsPda as u32, 8131),
    ];
    for (got, want) in table {
        assert_eq!(got, want, "error code drifted");
    }
}

/// A new variant fails the build until the match covers it.
#[allow(dead_code)]
fn every_variant_is_pinned(error: custom_ring_program::CustomRingError) {
    match error {
        InvalidInstructionData
        | ProofVerificationFailed
        | HashingFailed
        | InvalidShieldedPoolProgram
        | MissingRingAuth
        | ConfigAlreadyInitialized
        | ConfigNotInitialized
        | UnauthorizedAuthority
        | InvalidAuditorPubkey
        | MissingAuditorMessage
        | InvalidAuditorMessage
        | InvalidSystemProgram
        | InvalidConfigPda
        | UnsupportedCircuit
        | UnauthorizedInitializer
        | TooManyAccounts
        | ReadAccessRecordAlreadyExists
        | InvalidReadAccessRecord
        | InvalidReaderKey
        | UnsupportedOutputScheme
        | PolicyConfigAlreadyInitialized
        | PolicyConfigNotInitialized
        | InvalidPolicyConfigPda
        | PolicyHashMismatch
        | InvalidPolicyMember
        | UnauthorizedRecordSigner
        | InvalidRecordKind
        | InvalidRecordState
        | EmptyPolicy
        | InvalidPolicyTree
        | RecordVersionOverflow
        | InvalidRecordsPda => {}
    }
}
