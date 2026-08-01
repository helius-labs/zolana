# Zone to Ring Rename Map

Scope: all 1,110 Git-tracked files were scanned case-insensitively. The rules
below cover every content rename in commit `8e3464f9` and every tracked path
rename required afterward. Generated build directories, Git internals, vendored
caches, `.claude` archival/review material, and `.claude` worktree/cache copies
are excluded. The geographic third-party crate names `iana-time-zone` and
`iana-time-zone-haiku` are not domain renames.

## Vocabulary and identifier rules

1. `zone` -> `ring`
1. `zones` -> `rings`
1. `Zone` -> `Ring`
1. `Zones` -> `Rings`
1. `ZONE` -> `RING`
1. `zone*` -> `ring*`
1. `*zone` -> `*ring`
1. `*zone*` -> `*ring*`
1. `zone_*` -> `ring_*`
1. `*_zone` -> `*_ring`
1. `*_zone_*` -> `*_ring_*`
1. `Zone*` -> `Ring*`
1. `*Zone` -> `*Ring`
1. `*Zone*` -> `*Ring*`
1. `ZONE_*` -> `RING_*`
1. `*_ZONE` -> `*_RING`
1. `*_ZONE_*` -> `*_RING_*`
1. `zone-*` -> `ring-*`
1. `*-zone` -> `*-ring`
1. `*-zone-*` -> `*-ring-*`

## Protocol and product terminology

1. `default zone` -> `default ring`
1. `default-zone` -> `default-ring`
1. `policy zone` -> `policy ring`
1. `policy zones` -> `policy rings`
1. `policy-zone` -> `policy-ring`
1. `policy-zones` -> `policy-rings`
1. `anonymous zone` -> `anonymous ring`
1. `anonymous-zone` -> `anonymous-ring`
1. `non-zone` -> `non-ring`
1. `Zone Program` -> `Ring Program`
1. `Zone Programs` -> `Ring Programs`
1. `Zone Program Interface` -> `Ring Program Interface`
1. `Zone RPC` -> `Ring RPC`
1. `Zone Creator` -> `Ring Creator`
1. `Zone Accounts` -> `Ring Accounts`
1. `Zone Authority Circuit` -> `Ring Authority Circuit`
1. `zone authority` -> `ring authority`
1. `zone-authority` -> `ring-authority`
1. `zone config` -> `ring config`
1. `zone-capable` -> `ring-capable`
1. `zone-owned` -> `ring-owned`
1. `zone-defined` -> `ring-defined`
1. `zone-specific` -> `ring-specific`

## Public identifiers, wire names, and operational names

1. `zone_auth` -> `ring_auth`
1. `ZONE_AUTH_PDA_SEED` -> `RING_AUTH_PDA_SEED`
1. `zone_config` -> `ring_config`
1. `ZoneConfig` -> `RingConfig`
1. `ZONE_CONFIG` -> `RING_CONFIG`
1. `create_zone_config` -> `create_ring_config`
1. `CreateZoneConfig` -> `CreateRingConfig`
1. `CREATE_ZONE_CONFIG` -> `CREATE_RING_CONFIG`
1. `CreateZoneConfigData` -> `CreateRingConfigData`
1. `update_zone_config` -> `update_ring_config`
1. `UpdateZoneConfig` -> `UpdateRingConfig`
1. `UPDATE_ZONE_CONFIG` -> `UPDATE_RING_CONFIG`
1. `UpdateZoneConfigData` -> `UpdateRingConfigData`
1. `update_zone_config_owner` -> `update_ring_config_owner`
1. `UpdateZoneConfigOwner` -> `UpdateRingConfigOwner`
1. `UPDATE_ZONE_CONFIG_OWNER` -> `UPDATE_RING_CONFIG_OWNER`
1. `zone_authority_transact` -> `ring_authority_transact`
1. `ZoneAuthorityTransact` -> `RingAuthorityTransact`
1. `ZONE_AUTHORITY_TRANSACT` -> `RING_AUTHORITY_TRANSACT`
1. `zone_authority_transact_is_enabled` -> `ring_authority_transact_is_enabled`
1. `ZoneAuthorityTransactDisabled` -> `RingAuthorityTransactDisabled`
1. `zone_transact` -> `ring_transact`
1. `ZoneTransact` -> `RingTransact`
1. `ZONE_TRANSACT` -> `RING_TRANSACT`
1. `zone_deposit` -> `ring_deposit`
1. `ZoneDeposit` -> `RingDeposit`
1. `ZONE_DEPOSIT` -> `RING_DEPOSIT`
1. `merge_zone` -> `merge_ring`
1. `MergeZone` -> `MergeRing`
1. `MERGE_ZONE` -> `MERGE_RING`
1. `zone_merge_transact` -> `ring_merge_transact`
1. `ZoneMergeTransact` -> `RingMergeTransact`
1. `ZONE_MERGE_TRANSACT` -> `RING_MERGE_TRANSACT`
1. `zone_program_id` -> `ring_program_id`
1. `zoneProgramId` -> `ringProgramId`
1. `zoneProgramID` -> `ringProgramID`
1. `ZoneProgramID` -> `RingProgramID`
1. `ZoneProgramId` -> `RingProgramId`
1. `zone_data` -> `ring_data`
1. `ZoneData` -> `RingData`
1. `zone_data_hash` -> `ring_data_hash`
1. `zoneDataHash` -> `ringDataHash`
1. `outputZoneDataHash` -> `outputRingDataHash`
1. `ZoneDataHash` -> `RingDataHash`
1. `zone_hash` -> `ring_hash`
1. `ZoneHashesAlreadySet` -> `RingHashesAlreadySet`
1. `zone_creation_authority` -> `ring_creation_authority`
1. `ZoneCreationAuthority` -> `RingCreationAuthority`
1. `zone_creation_is_permissionless` -> `ring_creation_is_permissionless`
1. `ZoneCreationPermissionless` -> `RingCreationPermissionless`
1. `known_zones` -> `known_rings`
1. `zone_rpc_url` -> `ring_rpc_url`
1. `ZoneRPC` -> `RingRPC`
1. `zoneId` -> `ringId`
1. `ZoneEddsa` -> `RingEddsa`
1. `ZoneP256` -> `RingP256`
1. `ZoneAuthority` -> `RingAuthority`
1. `ZoneVariant` -> `RingVariant`
1. `ZoneCircuit` -> `RingCircuit`
1. `ZoneDepositIxData` -> `RingDepositIxData`
1. `ZoneDepositIxDataRef` -> `RingDepositIxDataRef`
1. `ZoneDepositEntry` -> `RingDepositEntry`
1. `ZoneDepositEntryRef` -> `RingDepositEntryRef`
1. `EncryptedZoneDepositData` -> `EncryptedRingDepositData`
1. `EncryptedZoneDepositOutput` -> `EncryptedRingDepositOutput`
1. `ENCRYPTED_ZONE_DEPOSIT_SCHEME` -> `ENCRYPTED_RING_DEPOSIT_SCHEME`
1. `MergeInputZoneMismatch` -> `MergeInputRingMismatch`
1. `SplitInputZoneMismatch` -> `SplitInputRingMismatch`
1. `MissingZoneProgramId` -> `MissingRingProgramId`
1. `InvalidZoneConfig` -> `InvalidRingConfig`
1. `DataRecord::ZoneData` -> `DataRecord::RingData`
1. `OwnerMode::ZoneAuthority` -> `OwnerMode::RingAuthority`
1. `OwnerMode::ZoneP256` -> `OwnerMode::RingP256`
1. `ProcessingEntry::Zone` -> `ProcessingEntry::Ring`
1. `customzone` -> `customring`
1. `defaultzone` -> `defaultring`
1. `zoneutils` -> `ringutils`
1. `--zone-creation-permissionless` -> `--ring-creation-permissionless`
1. `ZONE_TEST_PROGRAM_ID` -> `RING_TEST_PROGRAM_ID`
1. `Zone111111111111111111111111111111111111111` -> `Ring111111111111111111111111111111111111111`
1. `zone-test-program` -> `ring-test-program`
1. `zone_test_program.so` -> `ring_test_program.so`
1. `test-zone-validator` -> `test-ring-validator`
1. `zone_lifecycle` -> `ring_lifecycle`
1. `transfer-zone` -> `transfer-ring`
1. `transfer-p256-zone` -> `transfer-p256-ring`
1. `transfer-zone-authority` -> `transfer-ring-authority`
1. `merge-zone` -> `merge-ring`
1. `TSPP/zone_deposit` -> `TSPP/ring_deposit`

## Markdown anchors

1. `#zone-creator` -> `#ring-creator`
1. `#default-zone` -> `#default-ring`
1. `#policy-zones` -> `#policy-rings`
1. `#zone-accounts` -> `#ring-accounts`
1. `#zone_transact` -> `#transact` (repaired to target the shared instruction section)
1. `#zone_deposit` -> `#ring_deposit`
1. `#zone_authority_transact` -> plain `ring_authority_transact` text (removed the broken link; no dedicated section exists)
1. `#merge_zone` -> `#merge_ring`
1. `#zone-program-interface` -> `#ring-program-interface`
1. `#zone-rpc` -> `#ring-rpc`

## Tracked path renames

1. `program-libs/interface/src/instruction/builders/merge_zone.rs` -> `program-libs/interface/src/instruction/builders/merge_ring.rs`
1. `program-libs/interface/src/instruction/builders/zone_authority_transact.rs` -> `program-libs/interface/src/instruction/builders/ring_authority_transact.rs`
1. `program-libs/interface/src/instruction/builders/zone_config/mod.rs` -> `program-libs/interface/src/instruction/builders/ring_config/mod.rs`
1. `program-libs/interface/src/instruction/builders/zone_deposit.rs` -> `program-libs/interface/src/instruction/builders/ring_deposit.rs`
1. `program-libs/interface/src/instruction/builders/zone_transact.rs` -> `program-libs/interface/src/instruction/builders/ring_transact.rs`
1. `program-libs/interface/src/instruction/instruction_data/merge_zone.rs` -> `program-libs/interface/src/instruction/instruction_data/merge_ring.rs`
1. `program-libs/interface/src/instruction/instruction_data/zone_config.rs` -> `program-libs/interface/src/instruction/instruction_data/ring_config.rs`
1. `program-libs/interface/src/state/zone_config.rs` -> `program-libs/interface/src/state/ring_config.rs`
1. `program-libs/interface/src/verifying_keys/merge_zone_8_1.rs` -> `program-libs/interface/src/verifying_keys/merge_ring_8_1.rs`
1. `program-libs/interface/src/verifying_keys/transfer_p256_zone_*.rs` -> `program-libs/interface/src/verifying_keys/transfer_p256_ring_*.rs`
1. `program-libs/interface/src/verifying_keys/transfer_zone_*.rs` -> `program-libs/interface/src/verifying_keys/transfer_ring_*.rs`
1. `program-libs/interface/src/verifying_keys/transfer_zone_authority_*.rs` -> `program-libs/interface/src/verifying_keys/transfer_ring_authority_*.rs`
1. `program-tests/shielded-pool/tests/features/zone_config.feature` -> `program-tests/shielded-pool/tests/features/ring_config.feature`
1. `program-tests/shielded-pool/tests/features/zone_proofless_shield.feature` -> `program-tests/shielded-pool/tests/features/ring_proofless_shield.feature`
1. `program-tests/shielded-pool/tests/steps/zone_config.rs` -> `program-tests/shielded-pool/tests/steps/ring_config.rs`
1. `program-tests/shielded-pool/tests/steps/zone_deposit.rs` -> `program-tests/shielded-pool/tests/steps/ring_deposit.rs`
1. `program-tests/test-utils/src/litesvm_asserts/zone_deposit.rs` -> `program-tests/test-utils/src/litesvm_asserts/ring_deposit.rs`
1. `program-tests/test-utils/src/test_validator_asserts/merge_zone.rs` -> `program-tests/test-utils/src/test_validator_asserts/merge_ring.rs`
1. `program-tests/test-utils/src/test_validator_asserts/zone_deposit.rs` -> `program-tests/test-utils/src/test_validator_asserts/ring_deposit.rs`
1. `program-tests/test-utils/src/test_validator_asserts/zone_transact.rs` -> `program-tests/test-utils/src/test_validator_asserts/ring_transact.rs`
1. `program-tests/zone-test-program/` -> `program-tests/ring-test-program/`
1. `program-tests/ring-test-program/tests/features/mixed_zone_lifecycle.feature` -> `program-tests/ring-test-program/tests/features/mixed_ring_lifecycle.feature`
1. `program-tests/ring-test-program/tests/features/p256_zone_lifecycle.feature` -> `program-tests/ring-test-program/tests/features/p256_ring_lifecycle.feature`
1. `program-tests/ring-test-program/tests/features/zone_config_deposit.feature` -> `program-tests/ring-test-program/tests/features/ring_config_deposit.feature`
1. `program-tests/ring-test-program/tests/steps/merge_zone.rs` -> `program-tests/ring-test-program/tests/steps/merge_ring.rs`
1. `program-tests/ring-test-program/tests/steps/zone_authority_transact.rs` -> `program-tests/ring-test-program/tests/steps/ring_authority_transact.rs`
1. `program-tests/ring-test-program/tests/steps/zone_config.rs` -> `program-tests/ring-test-program/tests/steps/ring_config.rs`
1. `program-tests/ring-test-program/tests/steps/zone_deposit.rs` -> `program-tests/ring-test-program/tests/steps/ring_deposit.rs`
1. `program-tests/ring-test-program/tests/steps/zone_transact.rs` -> `program-tests/ring-test-program/tests/steps/ring_transact.rs`
1. `program-tests/ring-test-program/tests/zone_lifecycle.rs` -> `program-tests/ring-test-program/tests/ring_lifecycle.rs`
1. `programs/shielded-pool/src/instructions/merge_zone/` -> `programs/shielded-pool/src/instructions/merge_ring/`
1. `programs/shielded-pool/src/instructions/zone_config/` -> `programs/shielded-pool/src/instructions/ring_config/`
1. `prover/server/circuits/spp_merge/zone.go` -> `prover/server/circuits/spp_merge/ring.go`
1. `prover/server/circuits/spp_merge/zone_test.go` -> `prover/server/circuits/spp_merge/ring_test.go`
1. `prover/server/circuits/spp_transaction/shared/zone.go` -> `prover/server/circuits/spp_transaction/shared/ring.go`
1. `prover/server/circuits/zone-utils/` -> `prover/server/circuits/ring-utils/`
1. `sdk-libs/client/src/prover/merge_zone.rs` -> `sdk-libs/client/src/prover/merge_ring.rs`
1. `sdk-libs/client/src/prover/transact/zone_eddsa.rs` -> `sdk-libs/client/src/prover/transact/ring_eddsa.rs`
1. `sdk-libs/client/src/prover/transact/zone_p256.rs` -> `sdk-libs/client/src/prover/transact/ring_p256.rs`
1. `sdk-libs/client/src/prover/zone_authority.rs` -> `sdk-libs/client/src/prover/ring_authority.rs`
1. `sdk-libs/client/tests/merge_zone/` -> `sdk-libs/client/tests/merge_ring/`
1. `sdk-libs/client/tests/merge_ring/features/merge_zone.feature` -> `sdk-libs/client/tests/merge_ring/features/merge_ring.feature`
1. `sdk-libs/client/tests/zone_authority/` -> `sdk-libs/client/tests/ring_authority/`
1. `sdk-libs/client/tests/ring_authority/features/zone_authority.feature` -> `sdk-libs/client/tests/ring_authority/features/ring_authority.feature`
1. `sdk-libs/client/tests/zone_transfer/` -> `sdk-libs/client/tests/ring_transfer/`
1. `sdk-libs/client/tests/ring_transfer/features/zone_transfer.feature` -> `sdk-libs/client/tests/ring_transfer/features/ring_transfer.feature`
1. `sdk-libs/program-test/src/zone.rs` -> `sdk-libs/program-test/src/ring.rs`
1. `sdk-libs/transaction/src/instructions/merge_zone.rs` -> `sdk-libs/transaction/src/instructions/merge_ring.rs`
1. `sdk-libs/transaction/src/instructions/zone_authority.rs` -> `sdk-libs/transaction/src/instructions/ring_authority.rs`
1. `sdk-libs/transaction/src/serialization/zone_deposit.rs` -> `sdk-libs/transaction/src/serialization/ring_deposit.rs`

## Local ignored runtime artifact renames

1. `prover/server/proving-keys/merge_zone_8_1.key` -> `prover/server/proving-keys/merge_ring_8_1.key`
1. `prover/server/proving-keys/transfer_p256_zone_*.key` -> `prover/server/proving-keys/transfer_p256_ring_*.key`
1. `prover/server/proving-keys/transfer_zone_*.key` -> `prover/server/proving-keys/transfer_ring_*.key`
1. `prover/server/proving-keys/transfer_zone_authority_*.key` -> `prover/server/proving-keys/transfer_ring_authority_*.key`
1. `program-tests/zone-test-program/test-ledger/` -> `program-tests/ring-test-program/test-ledger/`

## Intentional exceptions

1. `iana-time-zone` -> `iana-time-zone` (third-party geographic crate; do not rename)
1. `iana-time-zone-haiku` -> `iana-time-zone-haiku` (third-party geographic crate; do not rename)
