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
        (InvalidEntryContent as u32, 8139),
        (InvalidPolicyRules as u32, 8140),
        (PolicyGenerationOverflow as u32, 8141),
        (PolicyOnAuditOnlyRing as u32, 8142),
        (MissingCoSigner as u32, 8143),
        (UnauthorizedCoSigner as u32, 8144),
        (InvalidCoSignerScope as u32, 8145),
        (InvalidCoSigner as u32, 8146),
        (InvalidCoSignerThresholds as u32, 8147),
        (SpendWindowExceeded as u32, 8148),
        (InvalidSpendWindow as u32, 8149),
        (DelegateDisabled as u32, 8150),
        (UnauthorizedDelegate as u32, 8151),
        (DelegatePublicLeg as u32, 8152),
        (DelegateAlreadySet as u32, 8153),
        (InvalidDelegate as u32, 8154),
        (VelocityDepositLeg as u32, 8155),
        (InvalidSpendRecord as u32, 8156),
        (ApprovalWithoutCoSigner as u32, 8158),
        (VelocityDisabled as u32, 8159),
        (VelocityWindowImmutable as u32, 8164),
        (InvalidHeadMapRoot as u32, 8165),
        (StaleHeadMapRoot as u32, 8166),
        (InvalidHeadMapCursor as u32, 8167),
        (InvalidKeyRegistryRoot as u32, 8168),
        (StaleKeyRegistryRoot as u32, 8169),
        (InvalidKeyRegistryCursor as u32, 8170),
        (HeadMapRootAlreadyExists as u32, 8171),
        (KeyRegistryRootAlreadyExists as u32, 8172),
        (InvalidDepositAudit as u32, 8173),
        (DepositAuditRequired as u32, 8174),
        (InvalidDepositDisclosure as u32, 8175),
        (InvalidSpendCountersDisclosure as u32, 8176),
        (InvalidRevocationTarget as u32, 8177),
        (PolicyFactRevoked as u32, 8178),
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
        | ForeignSource
        | InvalidEntryContent
        | InvalidPolicyRules
        | PolicyGenerationOverflow
        | PolicyOnAuditOnlyRing
        | MissingCoSigner
        | UnauthorizedCoSigner
        | InvalidCoSignerScope
        | InvalidCoSigner
        | InvalidCoSignerThresholds
        | SpendWindowExceeded
        | InvalidSpendWindow
        | DelegateDisabled
        | UnauthorizedDelegate
        | DelegatePublicLeg
        | DelegateAlreadySet
        | InvalidDelegate
        | VelocityDepositLeg
        | InvalidSpendRecord
        | ApprovalWithoutCoSigner
        | VelocityDisabled
        | VelocityWindowImmutable
        | InvalidHeadMapRoot
        | StaleHeadMapRoot
        | InvalidHeadMapCursor
        | InvalidKeyRegistryRoot
        | StaleKeyRegistryRoot
        | InvalidKeyRegistryCursor
        | HeadMapRootAlreadyExists
        | KeyRegistryRootAlreadyExists
        | InvalidDepositAudit
        | DepositAuditRequired
        | InvalidDepositDisclosure
        | InvalidSpendCountersDisclosure
        | InvalidRevocationTarget
        | PolicyFactRevoked => {}
    }
}
