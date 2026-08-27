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
        (ReadAccessEntryAlreadyExists as u32, 8116),
        (InvalidReadAccessRecord as u32, 8117),
        (InvalidReaderKey as u32, 8118),
        (UnsupportedOutputScheme as u32, 8119),
        (PolicyConfigAlreadyInitialized as u32, 8120),
        (PolicyConfigNotInitialized as u32, 8121),
        (InvalidPolicyConfigPda as u32, 8122),
        (PolicyHashMismatch as u32, 8123),
        (InvalidPolicyMember as u32, 8124),
        (UnauthorizedNamespaceSigner as u32, 8125),
        (InvalidListId as u32, 8126),
        (InvalidEntryState as u32, 8127),
        (InvalidPolicyTree as u32, 8129),
        (EntryVersionOverflow as u32, 8130),
        (InvalidNamespacePda as u32, 8131),
        (InvalidEntriesTree as u32, 8132),
        (StalePolicyRoot as u32, 8133),
        (InvalidSource as u32, 8134),
        (InvalidCuratorPolicyConfig as u32, 8135),
        (CuratorTreeMismatch as u32, 8136),
        (CuratorSourceMissing as u32, 8137),
        (ForeignSource as u32, 8138),
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
        | ReadAccessEntryAlreadyExists
        | InvalidReadAccessRecord
        | InvalidReaderKey
        | UnsupportedOutputScheme
        | PolicyConfigAlreadyInitialized
        | PolicyConfigNotInitialized
        | InvalidPolicyConfigPda
        | PolicyHashMismatch
        | InvalidPolicyMember
        | UnauthorizedNamespaceSigner
        | InvalidListId
        | InvalidEntryState
        | InvalidPolicyTree
        | EntryVersionOverflow
        | InvalidNamespacePda
        | InvalidEntriesTree
        | StalePolicyRoot
        | InvalidSource
        | InvalidCuratorPolicyConfig
        | CuratorTreeMismatch
        | CuratorSourceMissing
        | ForeignSource => {}
    }
}
