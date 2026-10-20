use custom_ring_interface::CustomRingError::*;

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
        (UnauthorizedListWrite as u32, 8125),
        (InvalidListId as u32, 8126),
        (InvalidNamespacePda as u32, 8131),
        (InvalidAddressTree as u32, 8132),
        (StalePolicyRoot as u32, 8133),
        (InvalidSource as u32, 8134),
        (InvalidCuratorRegistry as u32, 8135),
        (InvalidPolicyRules as u32, 8140),
        (PolicyGenerationOverflow as u32, 8141),
        (PolicyOnAuditOnlyRing as u32, 8142),
        (MissingCoSigner as u32, 8143),
        (UnauthorizedCoSigner as u32, 8144),
        (InvalidCoSignerScope as u32, 8145),
        (InvalidCoSigner as u32, 8146),
        (InvalidCoSignerThresholds as u32, 8147),
        (DelegateDisabled as u32, 8150),
        (UnauthorizedDelegate as u32, 8151),
        (DelegatePublicLeg as u32, 8152),
        (DelegateAlreadySet as u32, 8153),
        (InvalidDelegate as u32, 8154),
        (ApprovalWithoutCoSigner as u32, 8157),
        (InvalidMemberRegistryRoot as u32, 8160),
        (StaleMemberRegistryRoot as u32, 8161),
        (InvalidMemberRegistryCursor as u32, 8162),
        (MemberRegistryRootAlreadyExists as u32, 8163),
        (InvalidDepositAudit as u32, 8164),
        (DepositAuditRequired as u32, 8165),
        (InvalidDepositDisclosure as u32, 8166),
        (DelegateRequiresPolicy as u32, 8170),
        (InvalidPolicyTrees as u32, 8172),
        (MissingFundingSigner as u32, 8173),
        (UnexpectedMemberRegistryRoot as u32, 8175),
        (UnexpectedApproval as u32, 8176),
        (InvalidSettlementAccounts as u32, 8177),
        (TooManyPublicLegs as u32, 8178),
        (InvalidAuditedDeposit as u32, 8179),
        (InvalidDepositData as u32, 8180),
        (InvalidRingMode as u32, 8184),
        (AnonymousRingRefused as u32, 8185),
        (InvalidAnonymousOutput as u32, 8186),
        (InvalidAnonymousSigner as u32, 8187),
        (InvalidMergeDisclosure as u32, 8188),
        (MemberBatchOrder as u32, 8189),
        (MemberBatchTooLarge as u32, 8190),
        (MemberRecordMismatch as u32, 8191),
        (MissingOwnerSigner as u32, 8192),
        (InvalidAnonymousOutputBody as u32, 8193),
        (InvalidAnonymousTag as u32, 8194),
        (DuplicateAnonymousTag as u32, 8195),
        (InvalidAnonymousOutputHash as u32, 8196),
        (AnonymousOutputCount as u32, 8197),
    ];
    for (got, want) in table {
        assert_eq!(got, want, "error code drifted");
    }
}

/// A new variant fails the build until the match covers it.
#[allow(dead_code)]
fn every_variant_is_pinned(error: custom_ring_interface::CustomRingError) {
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
        | UnauthorizedListWrite
        | InvalidListId
        | InvalidNamespacePda
        | InvalidAddressTree
        | StalePolicyRoot
        | InvalidSource
        | InvalidCuratorRegistry
        | InvalidPolicyRules
        | PolicyGenerationOverflow
        | PolicyOnAuditOnlyRing
        | MissingCoSigner
        | UnauthorizedCoSigner
        | InvalidCoSignerScope
        | InvalidCoSigner
        | InvalidCoSignerThresholds
        | DelegateDisabled
        | UnauthorizedDelegate
        | DelegatePublicLeg
        | DelegateAlreadySet
        | InvalidDelegate
        | ApprovalWithoutCoSigner
        | InvalidMemberRegistryRoot
        | StaleMemberRegistryRoot
        | InvalidMemberRegistryCursor
        | MemberRegistryRootAlreadyExists
        | InvalidDepositAudit
        | DepositAuditRequired
        | InvalidDepositDisclosure
        | DelegateRequiresPolicy
        | InvalidPolicyTrees
        | MissingFundingSigner
        | UnexpectedMemberRegistryRoot
        | UnexpectedApproval
        | InvalidSettlementAccounts
        | TooManyPublicLegs
        | InvalidAuditedDeposit
        | InvalidDepositData
        | InvalidRingMode
        | AnonymousRingRefused
        | InvalidAnonymousOutput
        | InvalidAnonymousSigner
        | InvalidMergeDisclosure
        | MemberBatchOrder
        | MemberBatchTooLarge
        | MemberRecordMismatch
        | MissingOwnerSigner
        | InvalidAnonymousOutputBody
        | InvalidAnonymousTag
        | DuplicateAnonymousTag
        | InvalidAnonymousOutputHash
        | AnonymousOutputCount => {}
    }
}
