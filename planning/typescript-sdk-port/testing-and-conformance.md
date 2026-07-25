# Testing and conformance

Parity claims use frozen Rust revision
`43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f` (`43fde8e4`). The six
inventories are the coverage ledger. Each `inventory-active` row must name at
least one fixture and test owned by its packet. Each public declaration in
[public-exports.md](public-exports.md) must appear in the declaration ledger
below.

## Observable parity

Compare:

1. accepted and rejected inputs, stable error code, details, and redacted cause;
2. returned logical values and owned byte arrays;
3. hashes, keys, tags, nullifiers, signatures, ciphertexts, Merkle roots, and
   inclusion and non-inclusion paths;
4. exact prover request JSON, parsed result, BSB22 fields, and compressed proof;
5. exact instruction program ID, account order, signer/writable flags, and data;
6. exact unsigned native transaction message bytes and empty signature slots;
7. decoded indexer values, pagination, signatures, output tags, paths, and
   queue elements;
8. submitted signature, Solana confirmation, signature/tag-bound Photon
   appearance, recipient decryption, wallet sync report, balances, UTXOs,
   nullifiers, cursors, counters, and history; and
9. Solana program state and external SOL/SPL source, recipient, interface, and vault
   balance changes.

Class layout, stack text, and Rust blocking versus TypeScript Promise syntax
are not parity surfaces.

## Fixture layout and provenance

Create canonical fixtures under:

```text
sdk-libs/ts/fixtures/
  manifest.json
  interface/
  keypair/
  transaction/
  indexer-api/
  api/
  client/
  wallet/
  merkle-tree/
  smart-account-client/
  test-kit/
  workflows/
```

`manifest.json` records the fixture schema, frozen commit, `docs/spec.md`
SHA-256, Rust package features and toolchain, generator command, proving-key
release, Photon schema revision, and sorted path/SHA-256 entries. Each fixture
records a stable ID, frozen Rust path and symbol, inventory row, owning packet,
public declaration or internal responsibility, logical inputs, expected value
or error, and lower-case even-length hex bytes where applicable.

Fixed test secrets carry `testOnlySecret: true`. Random output is golden only
when random bytes are explicit fixture inputs. Integers are decimal strings.
Object keys are sorted. `null` is used only when the encoded bytes distinguish it from
omission. Errors compare code and details, not messages.

The Rust generator calls production functions. It must not duplicate protocol
math. Two runs must produce a clean diff, Rust must verify each generated
fixture, and CI must regenerate at the manifest commit.

### Revision compatibility

`manifest.json` carries nine identity keys: four entries under
`canonicalSourceRevisions` (`baseline`, `client`, `interface`, `merkleTree`),
plus `frozenCommit`, `historicalBaselineCommit`, `photonSchemaRevision`,
`specSha256`, and the `provingKeyRelease` lock hash. A parity claim assembled
from fixtures generated at different revisions is a claim about no single
protocol version, so each key states two things
([G8-1](production-readiness-issues.md#g8-1-the-manifest-pins-multiple-source-revisions-high)):

1. which other keys it must agree with, and what a legal divergence looks like;
2. what invalidates a fixture generated under it, which is its regeneration
   trigger.

The fixture gate reads those rules and fails when a fixture is consumed against
an incompatible pin. Drift recorded against the freeze, currently
`sdk-libs/merkle-tree/src/indexed.rs`, is reviewed under the rule for its key
rather than carried as a note.

## Public declaration coverage ledger

This ledger normalizes one declaration as
`package|entry-point|kind|name`. Overloads use `#2`; a typed re-export is a
`type` declaration. Each row maps exactly one of the 263 top-level `export`
declarations in canonical
[public-exports.md](public-exports.md) to a stable fixture ID and a named test
ID. Fixtures may contain logical values, typed errors, JSON, or bytes; tests
must compare bytes whenever the declaration has a wire representation. The
ledger validator extracts the same normalized identities from the TypeScript
blocks in `public-exports.md` and requires set equality, unique fixture/test
IDs, and zero uncovered or extra rows.

| Declaration | Fixture ID | Test ID |
| --- | --- | --- |
| `@zolana/interface|root|type|Address` | `fx-interface-root-type-address-v1` | `test-interface-root-type-address` |
| `@zolana/interface|root|type|Signature` | `fx-interface-root-type-signature-v1` | `test-interface-root-type-signature` |
| `@zolana/interface|root|type|Bytes16` | `fx-interface-root-type-bytes16-v1` | `test-interface-root-type-bytes16` |
| `@zolana/interface|root|type|Bytes31` | `fx-interface-root-type-bytes31-v1` | `test-interface-root-type-bytes31` |
| `@zolana/interface|root|type|Bytes32` | `fx-interface-root-type-bytes32-v1` | `test-interface-root-type-bytes32` |
| `@zolana/interface|root|type|Bytes33` | `fx-interface-root-type-bytes33-v1` | `test-interface-root-type-bytes33` |
| `@zolana/interface|root|type|Bytes64` | `fx-interface-root-type-bytes64-v1` | `test-interface-root-type-bytes64` |
| `@zolana/interface|root|type|Bytes128` | `fx-interface-root-type-bytes128-v1` | `test-interface-root-type-bytes128` |
| `@zolana/interface|root|type|Transaction` | `fx-interface-root-type-transaction-v1` | `test-interface-root-type-transaction` |
| `@zolana/interface|root|type|Instruction` | `fx-interface-root-type-instruction-v1` | `test-interface-root-type-instruction` |
| `@zolana/interface|root|interface|RequestContext` | `fx-interface-root-interface-request-context-v1` | `test-interface-root-interface-request-context` |
| `@zolana/interface|root|const|SHIELDED_POOL_PROGRAM_ID` | `fx-interface-root-const-shielded-pool-program-id-v1` | `test-interface-root-const-shielded-pool-program-id` |
| `@zolana/interface|root|const|DEFAULT_TREE_ADDRESS` | `fx-interface-root-const-default-tree-address-v1` | `test-interface-root-const-default-tree-address` |
| `@zolana/interface|root|const|SOL_INTERFACE` | `fx-interface-root-const-sol-interface-v1` | `test-interface-root-const-sol-interface` |
| `@zolana/interface|root|const|SHIELDED_POOL_CPI_AUTHORITY` | `fx-interface-root-const-shielded-pool-cpi-authority-v1` | `test-interface-root-const-shielded-pool-cpi-authority` |
| `@zolana/interface|root|const|SPL_TOKEN_PROGRAM_ID` | `fx-interface-root-const-spl-token-program-id-v1` | `test-interface-root-const-spl-token-program-id` |
| `@zolana/interface|root|const|ASSOCIATED_TOKEN_PROGRAM_ID` | `fx-interface-root-const-associated-token-program-id-v1` | `test-interface-root-const-associated-token-program-id` |
| `@zolana/interface|root|const|UTXO_DOMAIN` | `fx-interface-root-const-utxo-domain-v1` | `test-interface-root-const-utxo-domain` |
| `@zolana/interface|root|const|InstructionTag` | `fx-interface-root-const-instruction-tag-v1` | `test-interface-root-const-instruction-tag` |
| `@zolana/interface|root|type|InstructionTag` | `fx-interface-root-type-instruction-tag-v1` | `test-interface-root-type-instruction-tag` |
| `@zolana/interface|root|interface|DepositInstructionData` | `fx-interface-root-interface-deposit-instruction-data-v1` | `test-interface-root-interface-deposit-instruction-data` |
| `@zolana/interface|root|interface|DepositSplAccounts` | `fx-interface-root-interface-deposit-spl-accounts-v1` | `test-interface-root-interface-deposit-spl-accounts` |
| `@zolana/interface|root|interface|InputUtxo` | `fx-interface-root-interface-input-utxo-v1` | `test-interface-root-interface-input-utxo` |
| `@zolana/interface|root|type|OwnerTag` | `fx-interface-root-type-owner-tag-v1` | `test-interface-root-type-owner-tag` |
| `@zolana/interface|root|interface|TransactOutput` | `fx-interface-root-interface-transact-output-v1` | `test-interface-root-interface-transact-output` |
| `@zolana/interface|root|type|TransactProof` | `fx-interface-root-type-transact-proof-v1` | `test-interface-root-type-transact-proof` |
| `@zolana/interface|root|interface|TransactInstructionData` | `fx-interface-root-interface-transact-instruction-data-v1` | `test-interface-root-interface-transact-instruction-data` |
| `@zolana/interface|root|type|TransactWithdrawal` | `fx-interface-root-type-transact-withdrawal-v1` | `test-interface-root-type-transact-withdrawal` |
| `@zolana/interface|root|interface|ProtocolConfigAccount` | `fx-interface-root-interface-protocol-config-account-v1` | `test-interface-root-interface-protocol-config-account` |
| `@zolana/interface|root|interface|SplAssetCounterAccount` | `fx-interface-root-interface-spl-asset-counter-account-v1` | `test-interface-root-interface-spl-asset-counter-account` |
| `@zolana/interface|root|interface|SplAssetRegistryAccount` | `fx-interface-root-interface-spl-asset-registry-account-v1` | `test-interface-root-interface-spl-asset-registry-account` |
| `@zolana/interface|root|interface|ZoneConfigAccount` | `fx-interface-root-interface-zone-config-account-v1` | `test-interface-root-interface-zone-config-account` |
| `@zolana/interface|root|class|InterfaceError` | `fx-interface-root-class-interface-error-v1` | `test-interface-root-class-interface-error` |
| `@zolana/interface|root|type|InterfaceErrorCode` | `fx-interface-root-type-interface-error-code-v1` | `test-interface-root-type-interface-error-code` |
| `@zolana/interface|root|type|ShieldedPoolErrorCode` | `fx-interface-root-type-shielded-pool-error-code-v1` | `test-interface-root-type-shielded-pool-error-code` |
| `@zolana/interface|root|function|decodeProtocolConfig` | `fx-interface-root-function-decode-protocol-config-v1` | `test-interface-root-function-decode-protocol-config` |
| `@zolana/interface|root|function|decodeSplAssetCounter` | `fx-interface-root-function-decode-spl-asset-counter-v1` | `test-interface-root-function-decode-spl-asset-counter` |
| `@zolana/interface|root|function|decodeSplAssetRegistry` | `fx-interface-root-function-decode-spl-asset-registry-v1` | `test-interface-root-function-decode-spl-asset-registry` |
| `@zolana/interface|root|function|decodeZoneConfig` | `fx-interface-root-function-decode-zone-config-v1` | `test-interface-root-function-decode-zone-config` |
| `@zolana/interface|pda|function|protocolConfigAddress` | `fx-interface-pda-function-protocol-config-address-v1` | `test-interface-pda-function-protocol-config-address` |
| `@zolana/interface|pda|function|solInterfaceAddress` | `fx-interface-pda-function-sol-interface-address-v1` | `test-interface-pda-function-sol-interface-address` |
| `@zolana/interface|pda|function|shieldedPoolCpiAuthorityAddress` | `fx-interface-pda-function-shielded-pool-cpi-authority-address-v1` | `test-interface-pda-function-shielded-pool-cpi-authority-address` |
| `@zolana/interface|pda|function|splAssetCounterAddress` | `fx-interface-pda-function-spl-asset-counter-address-v1` | `test-interface-pda-function-spl-asset-counter-address` |
| `@zolana/interface|pda|function|splAssetRegistryAddress` | `fx-interface-pda-function-spl-asset-registry-address-v1` | `test-interface-pda-function-spl-asset-registry-address` |
| `@zolana/interface|pda|function|splAssetVaultAddress` | `fx-interface-pda-function-spl-asset-vault-address-v1` | `test-interface-pda-function-spl-asset-vault-address` |
| `@zolana/interface|pda|function|zoneConfigAddress` | `fx-interface-pda-function-zone-config-address-v1` | `test-interface-pda-function-zone-config-address` |
| `@zolana/interface|pda|function|associatedTokenAddress` | `fx-interface-pda-function-associated-token-address-v1` | `test-interface-pda-function-associated-token-address` |
| `@zolana/interface|codecs|interface|Codec` | `fx-interface-codecs-interface-codec-v1` | `test-interface-codecs-interface-codec` |
| `@zolana/interface|codecs|const|depositInstructionDataCodec` | `fx-interface-codecs-const-deposit-instruction-data-codec-v1` | `test-interface-codecs-const-deposit-instruction-data-codec` |
| `@zolana/interface|codecs|const|transactInstructionDataCodec` | `fx-interface-codecs-const-transact-instruction-data-codec-v1` | `test-interface-codecs-const-transact-instruction-data-codec` |
| `@zolana/interface|codecs|const|protocolConfigAccountCodec` | `fx-interface-codecs-const-protocol-config-account-codec-v1` | `test-interface-codecs-const-protocol-config-account-codec` |
| `@zolana/interface|codecs|const|splAssetCounterAccountCodec` | `fx-interface-codecs-const-spl-asset-counter-account-codec-v1` | `test-interface-codecs-const-spl-asset-counter-account-codec` |
| `@zolana/interface|codecs|const|splAssetRegistryAccountCodec` | `fx-interface-codecs-const-spl-asset-registry-account-codec-v1` | `test-interface-codecs-const-spl-asset-registry-account-codec` |
| `@zolana/interface|codecs|const|zoneConfigAccountCodec` | `fx-interface-codecs-const-zone-config-account-codec-v1` | `test-interface-codecs-const-zone-config-account-codec` |
| `@zolana/interface|instructions|function|batchUpdateNullifierTreeInstruction` | `fx-interface-instructions-function-batch-update-nullifier-tree-instruction-v1` | `test-interface-instructions-function-batch-update-nullifier-tree-instruction` |
| `@zolana/interface|instructions|function|createAssetCounterInstruction` | `fx-interface-instructions-function-create-asset-counter-instruction-v1` | `test-interface-instructions-function-create-asset-counter-instruction` |
| `@zolana/interface|instructions|function|createAssociatedTokenAccountInstruction` | `fx-interface-instructions-function-create-associated-token-account-instruction-v1` | `test-interface-instructions-function-create-associated-token-account-instruction` |
| `@zolana/interface|instructions|function|createSplInterfaceInstruction` | `fx-interface-instructions-function-create-spl-interface-instruction-v1` | `test-interface-instructions-function-create-spl-interface-instruction` |
| `@zolana/interface|instructions|function|createTreeInstruction` | `fx-interface-instructions-function-create-tree-instruction-v1` | `test-interface-instructions-function-create-tree-instruction` |
| `@zolana/interface|instructions|function|depositInstruction` | `fx-interface-instructions-function-deposit-instruction-v1` | `test-interface-instructions-function-deposit-instruction` |
| `@zolana/interface|instructions|function|transactInstruction` | `fx-interface-instructions-function-transact-instruction-v1` | `test-interface-instructions-function-transact-instruction` |
| `@zolana/interface|instructions|function|createProtocolConfigInstruction` | `fx-interface-instructions-function-create-protocol-config-instruction-v1` | `test-interface-instructions-function-create-protocol-config-instruction` |
| `@zolana/interface|instructions|type|ProtocolConfigUpdate` | `fx-interface-instructions-type-protocol-config-update-v1` | `test-interface-instructions-type-protocol-config-update` |
| `@zolana/interface|instructions|function|updateProtocolConfigInstruction` | `fx-interface-instructions-function-update-protocol-config-instruction-v1` | `test-interface-instructions-function-update-protocol-config-instruction` |
| `@zolana/interface|instructions|function|pauseTreeInstruction` | `fx-interface-instructions-function-pause-tree-instruction-v1` | `test-interface-instructions-function-pause-tree-instruction` |
| `@zolana/interface|instructions|function|createZoneConfigInstruction` | `fx-interface-instructions-function-create-zone-config-instruction-v1` | `test-interface-instructions-function-create-zone-config-instruction` |
| `@zolana/interface|instructions|function|updateZoneConfigInstruction` | `fx-interface-instructions-function-update-zone-config-instruction-v1` | `test-interface-instructions-function-update-zone-config-instruction` |
| `@zolana/interface|instructions|function|updateZoneConfigOwnerInstruction` | `fx-interface-instructions-function-update-zone-config-owner-instruction-v1` | `test-interface-instructions-function-update-zone-config-owner-instruction` |
| `@zolana/interface|instructions|function|zoneDepositInstruction` | `fx-interface-instructions-function-zone-deposit-instruction-v1` | `test-interface-instructions-function-zone-deposit-instruction` |
| `@zolana/interface|instructions|function|zoneTransactInstruction` | `fx-interface-instructions-function-zone-transact-instruction-v1` | `test-interface-instructions-function-zone-transact-instruction` |
| `@zolana/interface|instructions|function|zoneAuthorityTransactInstruction` | `fx-interface-instructions-function-zone-authority-transact-instruction-v1` | `test-interface-instructions-function-zone-authority-transact-instruction` |
| `@zolana/interface|instructions|interface|MergeTransactInstructionData` | `fx-interface-instructions-interface-merge-transact-instruction-data-v1` | `test-interface-instructions-interface-merge-transact-instruction-data` |
| `@zolana/interface|instructions|function|mergeTransactInstruction` | `fx-interface-instructions-function-merge-transact-instruction-v1` | `test-interface-instructions-function-merge-transact-instruction` |
| `@zolana/interface|instructions|function|mergeZoneInstruction` | `fx-interface-instructions-function-merge-zone-instruction-v1` | `test-interface-instructions-function-merge-zone-instruction` |
| `@zolana/keypair|root|type|SignatureType` | `fx-keypair-root-type-signature-type-v1` | `test-keypair-root-type-signature-type` |
| `@zolana/keypair|root|type|ViewTag` | `fx-keypair-root-type-view-tag-v1` | `test-keypair-root-type-view-tag` |
| `@zolana/keypair|root|type|Salt` | `fx-keypair-root-type-salt-v1` | `test-keypair-root-type-salt` |
| `@zolana/keypair|root|type|EcdsaSignature` | `fx-keypair-root-type-ecdsa-signature-v1` | `test-keypair-root-type-ecdsa-signature` |
| `@zolana/keypair|root|class|KeypairError` | `fx-keypair-root-class-keypair-error-v1` | `test-keypair-root-class-keypair-error` |
| `@zolana/keypair|root|type|KeypairErrorCode` | `fx-keypair-root-type-keypair-error-code-v1` | `test-keypair-root-type-keypair-error-code` |
| `@zolana/keypair|root|class|P256PublicKey` | `fx-keypair-root-class-p256-public-key-v1` | `test-keypair-root-class-p256-public-key` |
| `@zolana/keypair|root|class|ShieldedPublicKey` | `fx-keypair-root-class-shielded-public-key-v1` | `test-keypair-root-class-shielded-public-key` |
| `@zolana/keypair|root|class|SigningKey` | `fx-keypair-root-class-signing-key-v1` | `test-keypair-root-class-signing-key` |
| `@zolana/keypair|root|class|NullifierKey` | `fx-keypair-root-class-nullifier-key-v1` | `test-keypair-root-class-nullifier-key` |
| `@zolana/keypair|root|class|ViewingKey` | `fx-keypair-root-class-viewing-key-v1` | `test-keypair-root-class-viewing-key` |
| `@zolana/keypair|root|interface|ShieldedAddress` | `fx-keypair-root-interface-shielded-address-v1` | `test-keypair-root-interface-shielded-address` |
| `@zolana/keypair|root|interface|CompressedShieldedAddress` | `fx-keypair-root-interface-compressed-shielded-address-v1` | `test-keypair-root-interface-compressed-shielded-address` |
| `@zolana/keypair|root|class|ShieldedKeypair` | `fx-keypair-root-class-shielded-keypair-v1` | `test-keypair-root-class-shielded-keypair` |
| `@zolana/keypair|root|interface|ShieldedKeypairLike` | `fx-keypair-root-interface-shielded-keypair-like-v1` | `test-keypair-root-interface-shielded-keypair-like` |
| `@zolana/keypair|root|interface|ViewingKeyLike` | `fx-keypair-root-interface-viewing-key-like-v1` | `test-keypair-root-interface-viewing-key-like` |
| `@zolana/keypair|root|function|randomBlinding` | `fx-keypair-root-function-random-blinding-v1` | `test-keypair-root-function-random-blinding` |
| `@zolana/keypair|root|function|randomSalt` | `fx-keypair-root-function-random-salt-v1` | `test-keypair-root-function-random-salt` |
| `@zolana/keypair|merge|const|MERGE_INFO` | `fx-keypair-merge-const-merge-info-v1` | `test-keypair-merge-const-merge-info` |
| `@zolana/keypair|merge|interface|MergeCiphertextPublicInputs` | `fx-keypair-merge-interface-merge-ciphertext-public-inputs-v1` | `test-keypair-merge-interface-merge-ciphertext-public-inputs` |
| `@zolana/keypair|merge|function|encryptVerifiable` | `fx-keypair-merge-function-encrypt-verifiable-v1` | `test-keypair-merge-function-encrypt-verifiable` |
| `@zolana/keypair|merge|function|decryptVerifiable` | `fx-keypair-merge-function-decrypt-verifiable-v1` | `test-keypair-merge-function-decrypt-verifiable` |
| `@zolana/keypair|merge|function|mergePublicContribution` | `fx-keypair-merge-function-merge-public-contribution-v1` | `test-keypair-merge-function-merge-public-contribution` |
| `@zolana/keypair|merge|function|mergeCiphertextHash` | `fx-keypair-merge-function-merge-ciphertext-hash-v1` | `test-keypair-merge-function-merge-ciphertext-hash` |
| `@zolana/transaction|root|class|TransactionError` | `fx-transaction-root-class-transaction-error-v1` | `test-transaction-root-class-transaction-error` |
| `@zolana/transaction|root|type|TransactionErrorCode` | `fx-transaction-root-type-transaction-error-code-v1` | `test-transaction-root-type-transaction-error-code` |
| `@zolana/transaction|root|type|DataRecord` | `fx-transaction-root-type-data-record-v1` | `test-transaction-root-type-data-record` |
| `@zolana/transaction|root|class|Data` | `fx-transaction-root-class-data-v1` | `test-transaction-root-class-data` |
| `@zolana/transaction|root|type|Blinding` | `fx-transaction-root-type-blinding-v1` | `test-transaction-root-type-blinding` |
| `@zolana/transaction|root|interface|UtxoInit` | `fx-transaction-root-interface-utxo-init-v1` | `test-transaction-root-interface-utxo-init` |
| `@zolana/transaction|root|class|Utxo` | `fx-transaction-root-class-utxo-v1` | `test-transaction-root-class-utxo` |
| `@zolana/transaction|root|class|ProofInputUtxo` | `fx-transaction-root-class-proof-input-utxo-v1` | `test-transaction-root-class-proof-input-utxo` |
| `@zolana/transaction|root|function|deriveBlinding` | `fx-transaction-root-function-derive-blinding-v1` | `test-transaction-root-function-derive-blinding` |
| `@zolana/transaction|root|function|ownerUtxoHash` | `fx-transaction-root-function-owner-utxo-hash-v1` | `test-transaction-root-function-owner-utxo-hash` |
| `@zolana/transaction|root|function|ownerUtxoHash#2` | `fx-transaction-root-function-owner-utxo-hash-overload-2-v1` | `test-transaction-root-function-owner-utxo-hash-overload-2` |
| `@zolana/transaction|root|const|SOL_ASSET_ID` | `fx-transaction-root-const-sol-asset-id-v1` | `test-transaction-root-const-sol-asset-id` |
| `@zolana/transaction|root|const|SOL_MINT` | `fx-transaction-root-const-sol-mint-v1` | `test-transaction-root-const-sol-mint` |
| `@zolana/transaction|root|class|AssetRegistry` | `fx-transaction-root-class-asset-registry-v1` | `test-transaction-root-class-asset-registry` |
| `@zolana/transaction|root|interface|AssetBalance` | `fx-transaction-root-interface-asset-balance-v1` | `test-transaction-root-interface-asset-balance` |
| `@zolana/transaction|root|interface|PrivateTransaction` | `fx-transaction-root-interface-private-transaction-v1` | `test-transaction-root-interface-private-transaction` |
| `@zolana/transaction|root|interface|SyncReport` | `fx-transaction-root-interface-sync-report-v1` | `test-transaction-root-interface-sync-report` |
| `@zolana/transaction|root|interface|WalletUtxo` | `fx-transaction-root-interface-wallet-utxo-v1` | `test-transaction-root-interface-wallet-utxo` |
| `@zolana/transaction|root|class|Wallet` | `fx-transaction-root-class-wallet-v1` | `test-transaction-root-class-wallet` |
| `@zolana/transaction|root|type|WithdrawalTarget` | `fx-transaction-root-type-withdrawal-target-v1` | `test-transaction-root-type-withdrawal-target` |
| `@zolana/transaction|root|interface|ProofOutputUtxo` | `fx-transaction-root-interface-proof-output-utxo-v1` | `test-transaction-root-interface-proof-output-utxo` |
| `@zolana/transaction|root|interface|PreparedTransfer` | `fx-transaction-root-interface-prepared-transfer-v1` | `test-transaction-root-interface-prepared-transfer` |
| `@zolana/transaction|root|class|ConfidentialTransfer` | `fx-transaction-root-class-confidential-transfer-v1` | `test-transaction-root-class-confidential-transfer` |
| `@zolana/transaction|root|interface|PublicAmounts` | `fx-transaction-root-interface-public-amounts-v1` | `test-transaction-root-interface-public-amounts` |
| `@zolana/transaction|root|interface|P256Signature` | `fx-transaction-root-interface-p256-signature-v1` | `test-transaction-root-interface-p256-signature` |
| `@zolana/transaction|root|interface|EncryptedTransfer` | `fx-transaction-root-interface-encrypted-transfer-v1` | `test-transaction-root-interface-encrypted-transfer` |
| `@zolana/transaction|root|interface|SplitBundlePlaintext` | `fx-transaction-root-interface-split-bundle-plaintext-v1` | `test-transaction-root-interface-split-bundle-plaintext` |
| `@zolana/transaction|root|interface|EncryptedSplit` | `fx-transaction-root-interface-encrypted-split-v1` | `test-transaction-root-interface-encrypted-split` |
| `@zolana/transaction|root|interface|WalletSyncMaterial` | `fx-transaction-root-interface-wallet-sync-material-v1` | `test-transaction-root-interface-wallet-sync-material` |
| `@zolana/transaction|root|interface|SppProofInputs` | `fx-transaction-root-interface-spp-proof-inputs-v1` | `test-transaction-root-interface-spp-proof-inputs` |
| `@zolana/transaction|root|interface|InputUtxoContext` | `fx-transaction-root-interface-input-utxo-context-v1` | `test-transaction-root-interface-input-utxo-context` |
| `@zolana/transaction|root|class|PreparedMerge` | `fx-transaction-root-class-prepared-merge-v1` | `test-transaction-root-class-prepared-merge` |
| `@zolana/transaction|root|function|canonicalShape` | `fx-transaction-root-function-canonical-shape-v1` | `test-transaction-root-function-canonical-shape` |
| `@zolana/transaction|root|function|resolveShape` | `fx-transaction-root-function-resolve-shape-v1` | `test-transaction-root-function-resolve-shape` |
| `@zolana/transaction|root|interface|WalletSyncConfig` | `fx-transaction-root-interface-wallet-sync-config-v1` | `test-transaction-root-interface-wallet-sync-config` |
| `@zolana/transaction|root|function|decryptTransactions` | `fx-transaction-root-function-decrypt-transactions-v1` | `test-transaction-root-function-decrypt-transactions` |
| `@zolana/indexer-api|root|const|MIN_PAGE_LIMIT` | `fx-indexer-api-root-const-min-page-limit-v1` | `test-indexer-api-root-const-min-page-limit` |
| `@zolana/indexer-api|root|const|PAGE_LIMIT` | `fx-indexer-api-root-const-page-limit-v1` | `test-indexer-api-root-const-page-limit` |
| `@zolana/indexer-api|root|const|GET_ENCRYPTED_UTXOS_BY_TAGS` | `fx-indexer-api-root-const-get-encrypted-utxos-by-tags-v1` | `test-indexer-api-root-const-get-encrypted-utxos-by-tags` |
| `@zolana/indexer-api|root|const|GET_SHIELDED_TRANSACTIONS_BY_TAGS` | `fx-indexer-api-root-const-get-shielded-transactions-by-tags-v1` | `test-indexer-api-root-const-get-shielded-transactions-by-tags` |
| `@zolana/indexer-api|root|const|GET_MERKLE_PROOFS` | `fx-indexer-api-root-const-get-merkle-proofs-v1` | `test-indexer-api-root-const-get-merkle-proofs` |
| `@zolana/indexer-api|root|const|GET_NON_INCLUSION_PROOFS` | `fx-indexer-api-root-const-get-non-inclusion-proofs-v1` | `test-indexer-api-root-const-get-non-inclusion-proofs` |
| `@zolana/indexer-api|root|const|GET_NULLIFIER_QUEUE_ELEMENTS` | `fx-indexer-api-root-const-get-nullifier-queue-elements-v1` | `test-indexer-api-root-const-get-nullifier-queue-elements` |
| `@zolana/indexer-api|root|type|Base64String` | `fx-indexer-api-root-type-base64-string-v1` | `test-indexer-api-root-type-base64-string` |
| `@zolana/indexer-api|root|type|Hash` | `fx-indexer-api-root-type-hash-v1` | `test-indexer-api-root-type-hash` |
| `@zolana/indexer-api|root|type|Limit` | `fx-indexer-api-root-type-limit-v1` | `test-indexer-api-root-type-limit` |
| `@zolana/indexer-api|root|interface|IndexerContext` | `fx-indexer-api-root-interface-indexer-context-v1` | `test-indexer-api-root-interface-indexer-context` |
| `@zolana/indexer-api|root|interface|GetRingsByTagsRequest` | `fx-indexer-api-root-interface-get-rings-by-tags-request-v1` | `test-indexer-api-root-interface-get-rings-by-tags-request` |
| `@zolana/indexer-api|root|interface|RingsOutputContext` | `fx-indexer-api-root-interface-rings-output-context-v1` | `test-indexer-api-root-interface-rings-output-context` |
| `@zolana/indexer-api|root|interface|RingsOutputSlot` | `fx-indexer-api-root-interface-rings-output-slot-v1` | `test-indexer-api-root-interface-rings-output-slot` |
| `@zolana/indexer-api|root|interface|RingsMessage` | `fx-indexer-api-root-interface-rings-message-v1` | `test-indexer-api-root-interface-rings-message` |
| `@zolana/indexer-api|root|interface|EncryptedUtxoMatch` | `fx-indexer-api-root-interface-encrypted-utxo-match-v1` | `test-indexer-api-root-interface-encrypted-utxo-match` |
| `@zolana/indexer-api|root|interface|GetEncryptedUtxosByTagsResponse` | `fx-indexer-api-root-interface-get-encrypted-utxos-by-tags-response-v1` | `test-indexer-api-root-interface-get-encrypted-utxos-by-tags-response` |
| `@zolana/indexer-api|root|interface|IndexedShieldedTransaction` | `fx-indexer-api-root-interface-indexed-shielded-transaction-v1` | `test-indexer-api-root-interface-indexed-shielded-transaction` |
| `@zolana/indexer-api|root|interface|GetShieldedTransactionsByTagsResponse` | `fx-indexer-api-root-interface-get-shielded-transactions-by-tags-response-v1` | `test-indexer-api-root-interface-get-shielded-transactions-by-tags-response` |
| `@zolana/indexer-api|root|interface|GetMerkleProofsRequest` | `fx-indexer-api-root-interface-get-merkle-proofs-request-v1` | `test-indexer-api-root-interface-get-merkle-proofs-request` |
| `@zolana/indexer-api|root|interface|MerkleProof` | `fx-indexer-api-root-interface-merkle-proof-v1` | `test-indexer-api-root-interface-merkle-proof` |
| `@zolana/indexer-api|root|interface|GetMerkleProofsResponse` | `fx-indexer-api-root-interface-get-merkle-proofs-response-v1` | `test-indexer-api-root-interface-get-merkle-proofs-response` |
| `@zolana/indexer-api|root|interface|GetNonInclusionProofsRequest` | `fx-indexer-api-root-interface-get-non-inclusion-proofs-request-v1` | `test-indexer-api-root-interface-get-non-inclusion-proofs-request` |
| `@zolana/indexer-api|root|interface|NonInclusionProof` | `fx-indexer-api-root-interface-non-inclusion-proof-v1` | `test-indexer-api-root-interface-non-inclusion-proof` |
| `@zolana/indexer-api|root|interface|GetNonInclusionProofsResponse` | `fx-indexer-api-root-interface-get-non-inclusion-proofs-response-v1` | `test-indexer-api-root-interface-get-non-inclusion-proofs-response` |
| `@zolana/indexer-api|root|interface|GetNullifierQueueElementsRequest` | `fx-indexer-api-root-interface-get-nullifier-queue-elements-request-v1` | `test-indexer-api-root-interface-get-nullifier-queue-elements-request` |
| `@zolana/indexer-api|root|interface|NullifierQueueElement` | `fx-indexer-api-root-interface-nullifier-queue-element-v1` | `test-indexer-api-root-interface-nullifier-queue-element` |
| `@zolana/indexer-api|root|interface|GetNullifierQueueElementsResponse` | `fx-indexer-api-root-interface-get-nullifier-queue-elements-response-v1` | `test-indexer-api-root-interface-get-nullifier-queue-elements-response` |
| `@zolana/indexer-api|root|class|IndexerSchemaError` | `fx-indexer-api-root-class-indexer-schema-error-v1` | `test-indexer-api-root-class-indexer-schema-error` |
| `@zolana/indexer-api|root|function|base64String` | `fx-indexer-api-root-function-base64-string-v1` | `test-indexer-api-root-function-base64-string` |
| `@zolana/indexer-api|root|function|hash` | `fx-indexer-api-root-function-hash-v1` | `test-indexer-api-root-function-hash` |
| `@zolana/indexer-api|root|function|hashBytes` | `fx-indexer-api-root-function-hash-bytes-v1` | `test-indexer-api-root-function-hash-bytes` |
| `@zolana/indexer-api|root|function|limit` | `fx-indexer-api-root-function-limit-v1` | `test-indexer-api-root-function-limit` |
| `@zolana/api|root|class|ApiError` | `fx-api-root-class-api-error-v1` | `test-api-root-class-api-error` |
| `@zolana/api|root|interface|ZolanaApiConfig` | `fx-api-root-interface-zolana-api-config-v1` | `test-api-root-interface-zolana-api-config` |
| `@zolana/api|root|class|ZolanaApi` | `fx-api-root-class-zolana-api-v1` | `test-api-root-class-zolana-api` |
| `@zolana/client|root|class|ClientError` | `fx-client-root-class-client-error-v1` | `test-client-root-class-client-error` |
| `@zolana/client|root|interface|IndexerPollConfig` | `fx-client-root-interface-indexer-poll-config-v1` | `test-client-root-interface-indexer-poll-config` |
| `@zolana/client|root|interface|IndexerRpcConfig` | `fx-client-root-interface-indexer-rpc-config-v1` | `test-client-root-interface-indexer-rpc-config` |
| `@zolana/client|root|interface|RpcContext` | `fx-client-root-interface-rpc-context-v1` | `test-client-root-interface-rpc-context` |
| `@zolana/client|root|interface|MerkleContext` | `fx-client-root-interface-merkle-context-v1` | `test-client-root-interface-merkle-context` |
| `@zolana/client|root|interface|MerkleProof` | `fx-client-root-interface-merkle-proof-v1` | `test-client-root-interface-merkle-proof` |
| `@zolana/client|root|interface|NonInclusionProof` | `fx-client-root-interface-non-inclusion-proof-v1` | `test-client-root-interface-non-inclusion-proof` |
| `@zolana/client|root|interface|GetMerkleProofsResponse` | `fx-client-root-interface-get-merkle-proofs-response-v1` | `test-client-root-interface-get-merkle-proofs-response` |
| `@zolana/client|root|interface|GetNonInclusionProofsResponse` | `fx-client-root-interface-get-non-inclusion-proofs-response-v1` | `test-client-root-interface-get-non-inclusion-proofs-response` |
| `@zolana/client|root|interface|SpendProof` | `fx-client-root-interface-spend-proof-v1` | `test-client-root-interface-spend-proof` |
| `@zolana/client|root|interface|Rpc` | `fx-client-root-interface-rpc-v1` | `test-client-root-interface-rpc` |
| `@zolana/client|root|class|SolanaRpc` | `fx-client-root-class-solana-rpc-v1` | `test-client-root-class-solana-rpc` |
| `@zolana/client|root|class|ZolanaIndexer` | `fx-client-root-class-zolana-indexer-v1` | `test-client-root-class-zolana-indexer` |
| `@zolana/client|root|interface|SignedPrivateTransaction` | `fx-client-root-interface-signed-private-transaction-v1` | `test-client-root-interface-signed-private-transaction` |
| `@zolana/client|root|class|ZolanaClient` | `fx-client-root-class-zolana-client-v1` | `test-client-root-class-zolana-client` |
| `@zolana/client|prover|type|Shape` | `fx-client-prover-type-shape-v1` | `test-client-prover-type-shape` |
| `@zolana/client|prover|type|Field` | `fx-client-prover-type-field-v1` | `test-client-prover-type-field` |
| `@zolana/client|prover|type|SpendProof` | `fx-client-prover-type-spend-proof-v1` | `test-client-prover-type-spend-proof` |
| `@zolana/client|prover|interface|TransferInput` | `fx-client-prover-interface-transfer-input-v1` | `test-client-prover-interface-transfer-input` |
| `@zolana/client|prover|interface|TransferOutput` | `fx-client-prover-interface-transfer-output-v1` | `test-client-prover-interface-transfer-output` |
| `@zolana/client|prover|interface|TransferInputs` | `fx-client-prover-interface-transfer-inputs-v1` | `test-client-prover-interface-transfer-inputs` |
| `@zolana/client|prover|interface|TransferP256Inputs` | `fx-client-prover-interface-transfer-p256-inputs-v1` | `test-client-prover-interface-transfer-p256-inputs` |
| `@zolana/client|prover|type|ProverInputs` | `fx-client-prover-type-prover-inputs-v1` | `test-client-prover-type-prover-inputs` |
| `@zolana/client|prover|interface|AssembledTransfer` | `fx-client-prover-interface-assembled-transfer-v1` | `test-client-prover-interface-assembled-transfer` |
| `@zolana/client|prover|interface|Proof` | `fx-client-prover-interface-proof-v1` | `test-client-prover-interface-proof` |
| `@zolana/client|prover|interface|CompressedProof` | `fx-client-prover-interface-compressed-proof-v1` | `test-client-prover-interface-compressed-proof` |
| `@zolana/client|prover|class|ProverClient` | `fx-client-prover-class-prover-client-v1` | `test-client-prover-class-prover-client` |
| `@zolana/client|prover|function|assemble` | `fx-client-prover-function-assemble-v1` | `test-client-prover-function-assemble` |
| `@zolana/client|prover|function|intoProver` | `fx-client-prover-function-into-prover-v1` | `test-client-prover-function-into-prover` |
| `@zolana/client|prover|function|compressProof` | `fx-client-prover-function-compress-proof-v1` | `test-client-prover-function-compress-proof` |
| `@zolana/client|prover|function|canonicalShape` | `fx-client-prover-function-canonical-shape-v1` | `test-client-prover-function-canonical-shape` |
| `@zolana/client|prover|function|resolveShape` | `fx-client-prover-function-resolve-shape-v1` | `test-client-prover-function-resolve-shape` |
| `@zolana/wallet|root|class|WalletError` | `fx-wallet-root-class-wallet-error-v1` | `test-wallet-root-class-wallet-error` |
| `@zolana/wallet|root|interface|ApprovalRequest` | `fx-wallet-root-interface-approval-request-v1` | `test-wallet-root-interface-approval-request` |
| `@zolana/wallet|root|interface|WalletAuthority` | `fx-wallet-root-interface-wallet-authority-v1` | `test-wallet-root-interface-wallet-authority` |
| `@zolana/wallet|root|class|LocalWalletAuthority` | `fx-wallet-root-class-local-wallet-authority-v1` | `test-wallet-root-class-local-wallet-authority` |
| `@zolana/wallet|root|interface|DepositParams` | `fx-wallet-root-interface-deposit-params-v1` | `test-wallet-root-interface-deposit-params` |
| `@zolana/wallet|root|class|Deposit` | `fx-wallet-root-class-deposit-v1` | `test-wallet-root-class-deposit` |
| `@zolana/wallet|root|function|createDeposit` | `fx-wallet-root-function-create-deposit-v1` | `test-wallet-root-function-create-deposit` |
| `@zolana/wallet|root|function|buildDepositTransaction` | `fx-wallet-root-function-build-deposit-transaction-v1` | `test-wallet-root-function-build-deposit-transaction` |
| `@zolana/wallet|root|interface|TransferParams` | `fx-wallet-root-interface-transfer-params-v1` | `test-wallet-root-interface-transfer-params` |
| `@zolana/wallet|root|interface|WithdrawalParams` | `fx-wallet-root-interface-withdrawal-params-v1` | `test-wallet-root-interface-withdrawal-params` |
| `@zolana/wallet|root|class|UnsignedPrivateTransaction` | `fx-wallet-root-class-unsigned-private-transaction-v1` | `test-wallet-root-class-unsigned-private-transaction` |
| `@zolana/wallet|root|type|TransferRecipient` | `fx-wallet-root-type-transfer-recipient-v1` | `test-wallet-root-type-transfer-recipient` |
| `@zolana/wallet|root|interface|CreatedTransfer` | `fx-wallet-root-interface-created-transfer-v1` | `test-wallet-root-interface-created-transfer` |
| `@zolana/wallet|root|interface|CreatedWithdrawal` | `fx-wallet-root-interface-created-withdrawal-v1` | `test-wallet-root-interface-created-withdrawal` |
| `@zolana/wallet|root|function|createTransfer` | `fx-wallet-root-function-create-transfer-v1` | `test-wallet-root-function-create-transfer` |
| `@zolana/wallet|root|function|createWithdrawal` | `fx-wallet-root-function-create-withdrawal-v1` | `test-wallet-root-function-create-withdrawal` |
| `@zolana/wallet|root|interface|SplitParams` | `fx-wallet-root-interface-split-params-v1` | `test-wallet-root-interface-split-params` |
| `@zolana/wallet|root|interface|CreatedSplit` | `fx-wallet-root-interface-created-split-v1` | `test-wallet-root-interface-created-split` |
| `@zolana/wallet|root|function|createSplit` | `fx-wallet-root-function-create-split-v1` | `test-wallet-root-function-create-split` |
| `@zolana/wallet|root|interface|MergeParams` | `fx-wallet-root-interface-merge-params-v1` | `test-wallet-root-interface-merge-params` |
| `@zolana/wallet|root|interface|CreatedMerge` | `fx-wallet-root-interface-created-merge-v1` | `test-wallet-root-interface-created-merge` |
| `@zolana/wallet|root|function|createMerge` | `fx-wallet-root-function-create-merge-v1` | `test-wallet-root-function-create-merge` |
| `@zolana/wallet|root|class|MergeMaterial` | `fx-wallet-root-class-merge-material-v1` | `test-wallet-root-class-merge-material` |
| `@zolana/wallet|root|interface|SubmitMergeTransaction` | `fx-wallet-root-interface-submit-merge-transaction-v1` | `test-wallet-root-interface-submit-merge-transaction` |
| `@zolana/wallet|root|interface|SubmittedMerge` | `fx-wallet-root-interface-submitted-merge-v1` | `test-wallet-root-interface-submitted-merge` |
| `@zolana/wallet|root|function|submitMergeTransaction` | `fx-wallet-root-function-submit-merge-transaction-v1` | `test-wallet-root-function-submit-merge-transaction` |
| `@zolana/wallet|root|function|createAssociatedTokenAccount` | `fx-wallet-root-function-create-associated-token-account-v1` | `test-wallet-root-function-create-associated-token-account` |
| `@zolana/wallet|root|function|buildPrivateTransaction` | `fx-wallet-root-function-build-private-transaction-v1` | `test-wallet-root-function-build-private-transaction` |
| `@zolana/wallet|root|function|signPrivateTransaction` | `fx-wallet-root-function-sign-private-transaction-v1` | `test-wallet-root-function-sign-private-transaction` |
| `@zolana/wallet|root|interface|TransactionSigner` | `fx-wallet-root-interface-transaction-signer-v1` | `test-wallet-root-interface-transaction-signer` |
| `@zolana/wallet|root|interface|SyncWalletConfig` | `fx-wallet-root-interface-sync-wallet-config-v1` | `test-wallet-root-interface-sync-wallet-config` |
| `@zolana/wallet|root|function|syncWallet` | `fx-wallet-root-function-sync-wallet-v1` | `test-wallet-root-function-sync-wallet` |
| `@zolana/wallet|root|function|getPrivateTokenBalances` | `fx-wallet-root-function-get-private-token-balances-v1` | `test-wallet-root-function-get-private-token-balances` |
| `@zolana/wallet|root|function|getPrivateTransactions` | `fx-wallet-root-function-get-private-transactions-v1` | `test-wallet-root-function-get-private-transactions` |
| `@zolana/wallet|root|interface|ResolvedAddress` | `fx-wallet-root-interface-resolved-address-v1` | `test-wallet-root-interface-resolved-address` |
| `@zolana/wallet|root|function|buildRegistrationTransaction` | `fx-wallet-root-function-build-registration-transaction-v1` | `test-wallet-root-function-build-registration-transaction` |
| `@zolana/wallet|root|function|fetchUserRecord` | `fx-wallet-root-function-fetch-user-record-v1` | `test-wallet-root-function-fetch-user-record` |
| `@zolana/wallet|root|function|isWalletRegistered` | `fx-wallet-root-function-is-wallet-registered-v1` | `test-wallet-root-function-is-wallet-registered` |
| `@zolana/wallet|root|function|resolveRegisteredAddress` | `fx-wallet-root-function-resolve-registered-address-v1` | `test-wallet-root-function-resolve-registered-address` |
| `@zolana/merkle-tree|root|interface|Hasher32` | `fx-merkle-tree-root-interface-hasher32-v1` | `test-merkle-tree-root-interface-hasher32` |
| `@zolana/merkle-tree|root|class|MerkleTreeError` | `fx-merkle-tree-root-class-merkle-tree-error-v1` | `test-merkle-tree-root-class-merkle-tree-error` |
| `@zolana/merkle-tree|root|class|IndexedMerkleTreeError` | `fx-merkle-tree-root-class-indexed-merkle-tree-error-v1` | `test-merkle-tree-root-class-indexed-merkle-tree-error` |
| `@zolana/merkle-tree|root|class|MerkleTree` | `fx-merkle-tree-root-class-merkle-tree-v1` | `test-merkle-tree-root-class-merkle-tree` |
| `@zolana/merkle-tree|root|interface|NonInclusionProof` | `fx-merkle-tree-root-interface-non-inclusion-proof-v1` | `test-merkle-tree-root-interface-non-inclusion-proof` |
| `@zolana/merkle-tree|root|class|IndexedMerkleTree` | `fx-merkle-tree-root-class-indexed-merkle-tree-v1` | `test-merkle-tree-root-class-indexed-merkle-tree` |
| `@zolana/smart-account-client|root|const|SMART_ACCOUNT_PROGRAM_ID` | `fx-smart-account-client-root-const-smart-account-program-id-v1` | `test-smart-account-client-root-const-smart-account-program-id` |
| `@zolana/smart-account-client|root|interface|Permissions` | `fx-smart-account-client-root-interface-permissions-v1` | `test-smart-account-client-root-interface-permissions` |
| `@zolana/smart-account-client|root|interface|SmartAccountSigner` | `fx-smart-account-client-root-interface-smart-account-signer-v1` | `test-smart-account-client-root-interface-smart-account-signer` |
| `@zolana/smart-account-client|root|class|SmartAccountClientError` | `fx-smart-account-client-root-class-smart-account-client-error-v1` | `test-smart-account-client-root-class-smart-account-client-error` |
| `@zolana/smart-account-client|root|function|allPermissions` | `fx-smart-account-client-root-function-all-permissions-v1` | `test-smart-account-client-root-function-all-permissions` |
| `@zolana/smart-account-client|root|function|programConfigAddress` | `fx-smart-account-client-root-function-program-config-address-v1` | `test-smart-account-client-root-function-program-config-address` |
| `@zolana/smart-account-client|root|function|treasuryAddress` | `fx-smart-account-client-root-function-treasury-address-v1` | `test-smart-account-client-root-function-treasury-address` |
| `@zolana/smart-account-client|root|function|settingsAddress` | `fx-smart-account-client-root-function-settings-address-v1` | `test-smart-account-client-root-function-settings-address` |
| `@zolana/smart-account-client|root|function|smartAccountAddress` | `fx-smart-account-client-root-function-smart-account-address-v1` | `test-smart-account-client-root-function-smart-account-address` |
| `@zolana/smart-account-client|root|function|createSmartAccountInstruction` | `fx-smart-account-client-root-function-create-smart-account-instruction-v1` | `test-smart-account-client-root-function-create-smart-account-instruction` |
| `@zolana/smart-account-client|root|function|executeSyncInstruction` | `fx-smart-account-client-root-function-execute-sync-instruction-v1` | `test-smart-account-client-root-function-execute-sync-instruction` |
| `@zolana/test-kit|root|class|TestKitError` | `fx-test-kit-root-class-test-kit-error-v1` | `test-test-kit-root-class-test-kit-error` |
| `@zolana/test-kit|root|interface|LocalStack` | `fx-test-kit-root-interface-local-stack-v1` | `test-test-kit-root-interface-local-stack` |
| `@zolana/test-kit|root|function|startLocalStack` | `fx-test-kit-root-function-start-local-stack-v1` | `test-test-kit-root-function-start-local-stack` |
| `@zolana/test-kit|root|function|fixtureBytes` | `fx-test-kit-root-function-fixture-bytes-v1` | `test-test-kit-root-function-fixture-bytes` |
| `@zolana/test-kit|root|function|createTestWallet` | `fx-test-kit-root-function-create-test-wallet-v1` | `test-test-kit-root-function-create-test-wallet` |

Declaration-ledger totals: 263 declarations, 263 fixture IDs, and 263 test IDs.
The package counts are interface 74, keypair 24, transaction 36, indexer-api
33, API transport 3, client 32, wallet 39, Merkle tree 6, smart-account client
11, and private test-kit 5.

The corrected proof shapes change no declaration identity, fixture ID, test ID,
package count, or total. Existing IDs cover distinct package-local contracts:

- `fx-indexer-api-root-interface-non-inclusion-proof-v1` /
  `test-indexer-api-root-interface-non-inclusion-proof` records the exact
  ten-field snake_case JSON object from frozen `zolana-indexer-api`, including
  canonical base58 hashes/address, `u16` tree/root indexes, and `u64` neighbor
  indexes/root sequence. It asserts that `leaf_index` is unknown and that its
  absence is valid.
- `fx-client-root-interface-non-inclusion-proof-v1` /
  `test-client-root-interface-non-inclusion-proof` records the corresponding
  byte-valued client object and asserts no `leafIndex` declaration.
  `fx-client-root-interface-spend-proof-v1` /
  `test-client-root-interface-spend-proof` separately asserts
  `state.leafIndex` and `nullifier.lowElementIndex`.
- `fx-merkle-tree-root-interface-non-inclusion-proof-v1` /
  `test-merkle-tree-root-interface-non-inclusion-proof` records `root`, `value`,
  `leafLowerRangeValue`, `leafHigherRangeValue`, `leafIndex`, `nextIndex`, and
  `merkleProof`; it must not substitute Photon neighbor fields.

The indexer vector is pinned to frozen
[`indexer-api/src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/indexer-api/src/lib.rs);
the client vector and conversion are pinned to frozen
[`rpc.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/rpc.rs)
and
[`indexer.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/indexer.rs);
the reference-tree vector is pinned to frozen
[`indexed.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/merkle-tree/src/indexed.rs).

The corrected keypair signatures do not add or remove top-level declarations,
so the declaration identities, IDs, and totals remain unchanged. Their existing
fixtures and tests must cover the complete corrected declaration:

- `fx-keypair-root-class-viewing-key-v1` /
  `test-keypair-root-class-viewing-key` records recipient/request/shared tag
  arguments, first-nullifier-only transaction viewing-key derivation, the
  recipient and transaction viewing public keys, salt, `u32` slot index,
  ciphertext, and the named merge encryption result.
- `fx-keypair-root-interface-viewing-key-like-v1` /
  `test-keypair-root-interface-viewing-key-like` asserts that
  `transactionViewingKey(firstNullifier)` returns `ViewingKey |
  Promise<ViewingKey>` without a salt argument.
- `fx-keypair-merge-interface-merge-ciphertext-public-inputs-v1` /
  `test-keypair-merge-interface-merge-ciphertext-public-inputs` records the
  transaction viewing public key's low/high limbs and ciphertext hash.
- `fx-keypair-merge-function-encrypt-verifiable-v1`,
  `fx-keypair-merge-function-decrypt-verifiable-v1`, and
  `fx-keypair-merge-function-merge-public-contribution-v1`, with their existing
  test IDs, record the secret/public key arguments, ciphertext, and the named
  `{ ciphertext, txViewingPublicKey }` encryption result.

These vectors call frozen production functions in
[`viewing_key.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/viewing_key.rs)
and
[`merge.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/merge.rs).
Slot-index separation and sender/recipient decryption must reproduce
[`tests/steps/transaction.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/tests/steps/transaction.rs);
view-tag counters and transaction viewing-key derivation must reproduce
[`tests/steps/viewing.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/tests/steps/viewing.rs).

## Lifecycle conformance

The canonical spend fixture records each stage separately:

| Stage | Required comparison |
| --- | --- |
| Create action | `CreatedTransfer` registered/public-withdrawal discriminant or `CreatedWithdrawal`; selected inputs, tree, payer, and settlement target. |
| Unsigned private transaction | wallet-owned intent value and custody-safe metadata; no native signature or secret bytes. |
| Authority encryption and approval | public approval summary, call order, recipient/change slots, salt, viewing public key, and P256 signature only when required. |
| Proof inputs | `SppProofInputs`, public SOL/SPL amounts, input/output hashes, first nullifier, message hash, shape, and optional P256 witness. |
| Indexer paths | one state inclusion and one nullifier non-inclusion proof per real input, in input order, with exact roots, indexes, path heights, and neighbors. |
| Prover | exact circuit and JSON body, parsed uncompressed points/commitments, result error, compressed A/B/C, and optional commitment/PoK. |
| Interface instruction | exact `transactInstruction` accounts, flags, withdrawal suffix, and bytes. Deposit fixtures similarly compare `depositInstruction` fields, accounts, bytes, commitment, and initial viewing-key tag. |
| Native transaction | fee payer, blockhash, instruction order, message bytes, and empty signature slots before custody signing. |
| Native signing/submission | signer receives only the native transaction; returned signature is the one submitted. |
| Confirmation/indexing | Solana confirms that signature; RPC extracts its output tags; Photon returns the same signature and complete tag set before success. |
| Decryption/sync | matching recipient and sender outputs decrypt; unrelated keys do not; sync applies atomically and a repeated sync is a no-op. |

Deposit coverage has independent SOL and SPL vectors. SPL compares source token
account, vault/interface, registry, token program, source decrease, and vault
increase. Spend coverage has registered and unregistered routing, SOL and SPL
withdrawals, external balances, and exact private change.

The interface vector `fx-interface-root-const-instruction-tag-v1` and test
`test-interface-root-const-instruction-tag` assert the 18 frozen numeric tags:
`transact`, `deposit`, `zoneTransact`, `zoneAuthorityTransact`,
`createSplInterface`, `createTree`, `createProtocolConfig`,
`updateProtocolConfig`, `pauseTree`, `createZoneConfig`,
`updateZoneConfigOwner`, `updateZoneConfig`, `mergeTransact`,
`zoneMergeTransact`, `emitEvent`, `zoneDeposit`, `createAssetCounter`, and
`batchUpdateNullifierTree`.

Transaction-wire vectors assert the corrected declarations exactly:
`InputUtxo.nullifierHash`, `nullifierTreeRootIndex`, `utxoTreeRootIndex`,
`treeIndex`, and `eddsaSignerIndex`; the three `OwnerTag` variants;
`TransactOutput.ownerTag` and optional `data`; `relayerFee` as validated `u16`
`number`; messages as `{ viewTag, data }`; and P256 compressed commitment and
proof-of-knowledge (`commitmentPok`) as 32-byte points. No test may use the removed
`nullifier`/single-`rootIndex`, output `viewTag`/`payload`, `bigint` relayer
fee, or 64-byte compressed commitment shapes.

## Differential and cross-package tests

For each fixture, decode through public constructors, call the public or named
conformance entry point, compare logical values and bytes, and assert the
package error class/code/details for failures. Decode Rust bytes in TypeScript
and TypeScript bytes in Rust for account data, transaction codecs, prover
JSON/result/compression, instruction data, indexer JSON, smart-account payloads,
and wallet snapshots.

Required cross-tests:

- `depositInstructionDataCodec` and `depositInstruction` consume the same
  fields produced by `Deposit`; account metas and bytes match frozen Rust.
- `PreparedTransfer.finalize` output feeds `assemble`/`intoProver` without
  copied proof math; both boundaries produce identical prover inputs.
- `ProverClient.prove` request JSON and result parse match Rust, and
  `compressProof().toTransactProof()` matches `transactInstructionDataCodec`.
- `@zolana/indexer-api` serializes requests and validates decoded responses;
  `@zolana/api` sends those exact requests and returns those schema-owned
  values for the five methods. Mutation tests reject unknown fields, malformed
  base58/base64, invalid limits, and mismatched JSON-RPC envelopes.
- `ZolanaIndexer` conversion preserves addresses, signatures, bytes, paths,
  root indexes, pagination, and nullifier neighbors. Its non-inclusion
  conversion accepts the exact ten-field JSON proof, copies each hash/path
  item to `Bytes32`, includes no `leafIndex`, and leaves the schema-owned input
  unaliased.
- smart-account PDA and create/execute vectors compare exact bytes and metas;
  duplicate inner accounts union writable/signer privileges, inner indexes
  remain stable, the vault outer signer bit is cleared, and count/data/payload
  overflow is rejected before truncation.
- the fixture generator records an `(input, rust_error_variant)` pair for each
  malformed input in the keypair, transaction, and client rejection corpora, and
  a TypeScript test asserts the mapped code for each pair. Without it the
  mapping between a Rust variant and its TypeScript code exists only in prose
  ([G5-3](production-readiness-issues.md#g5-3-no-cross-language-error-mapping-fixture-medium)).
  The pairs consume the code-per-variant table that
  [G5-2](production-readiness-issues.md#g5-2-the-keypair-error-taxonomy-is-collapsed-relative-to-rust-high)
  produces, so a collapsed code cannot satisfy the assertion.

## Independent E2E suites

Action-level and instruction-level E2Es use separate test files, entry points,
fresh wallets, and isolated local stacks. They may share only service startup,
funding, mint creation, and read-only assertion utilities.

Action E2Es may import wallet actions. They may not import raw instruction
fixtures, `ConfidentialTransfer`, `assemble`, `intoProver`, or invoke an
instruction E2E helper. Required cases:

- SOL and SPL deposits;
- registered private transfer;
- unregistered SOL and SPL transfer routing to explicit public withdrawal;
- SOL and SPL withdrawal;
- `createSplit` with exact output count, per-output amount, encrypted bundle,
  resulting UTXOs, and idempotent repeated sync
  (`fx-workflow-action-split-v1`, `e2e-action-split`);
- `createMerge` and `submitMergeTransaction` with selected inputs, merged
  amount, submitted signature/output hash, spent inputs, one merged output,
  and repeated sync (`fx-workflow-action-merge-v1`,
  `e2e-action-merge-submit`);
- `createAssociatedTokenAccount` on a missing ATA and again on the existing ATA
  without duplicate creation or balance change
  (`fx-workflow-action-ata-idempotent-v1`, `e2e-action-ata-idempotent`);
- `buildPrivateTransaction` followed by an external signer/HSM stub;
- `signPrivateTransaction` with `LocalWalletAuthority`;
- authority rejection before proof/submission;
- abort and timeout at registry, prover, RPC, confirmation, and sync boundaries;
- delayed Photon appearance after Solana confirmation;
- confirmation retry and repeated wallet sync without duplicate UTXO/history;
- final recipient decryption and exact sender/recipient/private/public deltas.

Instruction E2Es may import transaction, prover, interface, RPC, indexer, and
native adapter APIs. They may not import or call `createDeposit`,
`buildDepositTransaction`, `createTransfer`, `createWithdrawal`,
`buildPrivateTransaction`, or `signPrivateTransaction`. Required cases:

- raw SOL and SPL deposit field derivation, initial viewing-key tag, exact
  instruction accounts/bytes, unsigned native transaction, submit, index, and
  decrypt;
- registered `ConfidentialTransfer`, spend conversion, encryption/approval,
  state and non-inclusion proofs, `assemble`/prover/compression, exact transact
  accounts/bytes, submit, nullifier/output state, recipient and sender decrypt;
- separate raw SOL and SPL withdrawal cases with exact settlement suffix and
  external balance deltas;
- wrong path order/height/root, incomplete proof sets, mismatched withdrawal
  accounts, wrong CPI authority/vault/ATA/token program, malformed proof, and
  authority rejection.

Four instruction workflow vectors are mandatory and independently countable:

- `fx-workflow-instruction-deposit-v1` /
  `e2e-instruction-deposit-wire` asserts tag `deposit`, SOL and SPL account
  flags/order, exact bytes, decoded deposit fields, and initial viewing-key tag.
- `fx-workflow-instruction-transfer-v1` /
  `e2e-instruction-transfer-wire` asserts tag `transact`, exact account
  flags/order and bytes, corrected input/output/message fields, proof rail, and
  recipient/change tags.
- `fx-workflow-instruction-withdraw-sol-v1` /
  `e2e-instruction-withdraw-sol-wire` asserts tag `transact`, exact SOL
  settlement suffix, signed public amount, corrected wire fields, and bytes.
- `fx-workflow-instruction-withdraw-spl-v1` /
  `e2e-instruction-withdraw-spl-wire` asserts tag `transact`, exact CPI
  authority/vault/recipient/ATA/token-program suffix, one public SPL asset,
  corrected wire fields, and bytes.

Each suite asserts its own Solana program and Photon confirmation. Passing one suite
cannot satisfy the other.

## Failure, lag, and runtime matrix

Remote tests cover DNS/connect failure, abort, timeout, HTTP 4xx/5xx with empty,
text, JSON, and oversized bodies, JSON-RPC errors, successful invalid schemas,
retry classification, and bounded redacted diagnostics. Transaction submission
is not blindly retried after an unknown outcome.

Indexer-lag tests make Solana confirmation succeed while Photon omits part or
the complete expected tag set. `confirmPrivateTransaction` must continue
polling until the
same signature/tag set appears or return a typed timeout containing only safe
metadata. A response for another signature must not satisfy confirmation.

Browser-capable packages run unit/vector tests and a packed-consumer
bundle in Chromium. `@zolana/keypair`, transaction encryption/decryption,
indexer schema, API transport, client transport/prover conversion, wallet
authority/sync, interface, Merkle tree, and smart-account builders run without
`Buffer`, `process`, `require`, `node:*`, filesystem, or injected polyfills.
Node 20 and 22 run the package tests. Private `@zolana/test-kit` is Node-only.

The implementation and this requirement disagree, and the script is what
changes. `sdk-libs/ts/config/browser-check.mjs` greps sources for Node globals
and bundles the entry points with esbuild, so a runtime dependency on
`crypto.subtle`, a `SharedArrayBuffer` assumption, or a `BigInt64Array` gap
passes it. Executing the keypair and transaction vector suites in headless
Chromium is the gate; the static scan stays as a cheap pre-filter beside it. The
Web Crypto surfaces the packages require are named in a list a consumer can read
before choosing a browser target
([G9-4](production-readiness-issues.md#g9-4-browser-support-is-checked-statically-not-in-a-browser-medium)).

## Property and mutation gates

Mandatory properties include codec round trips; sign/verify; encrypt/decrypt;
tag agreement and direction separation; deterministic hashes/nullifiers;
per-asset conservation; shape padding order; distinct dummy commitments;
Merkle path verification; indexed-tree neighbor ordering; schema
serialize/validate stability; smart-account privilege union; wallet sync
idempotence and page-partition equivalence; sequential/worker equality; and no
state mutation after tamper, abort, or partial-page failure.

Mutation tests must kill changes to lengths, endianness, tags, option/vector
prefixes, proof point signs, BSB22 presence, account order/flags, smart-account
indexes/counts, indexer field names, signature/tag confirmation matching, and
SOL/SPL settlement variants.

Aliasing is a separate obligation from the mutation set. For each public
accessor that receives or returns secret-adjacent bytes, one test mutates the
buffer the caller holds and asserts the object's internal state is unchanged.
`copyBytes` on a return path is the implementation, not the evidence: the audit
is the set of accessors, not the set of `copyBytes` call sites
([G6-2](production-readiness-issues.md#g6-2-defensive-copy-discipline-is-not-uniformly-verified-medium)).
[PKP-04](proof-and-key-parity.md#pkp-04-enforce-capability-and-secret-boundaries)
K8 extends the same test shape to the secret-bearing constructors.

Proof tamper coverage is owned by
[PKP-06](proof-and-key-parity.md#pkp-06-add-native-verification-certification).
Its matrix holds one negative case per public input and per proof component,
and each case asserts a named typed rejection rather than any failure
([G4-3](production-readiness-issues.md#g4-3-adversarial-and-tamper-coverage-is-thin-medium)).
That assertion needs the G5-2 code split first, since a matrix cannot name a
rejection while several causes share one code.

## Commands and release evidence

Implementation packets add deterministic repository commands with these
stable responsibilities:

```text
npm run check
npm run test:unit
npm run test:vectors
npm run test:property
npm run test:cross
npm run test:browser
npm run test:prover
npm run test:e2e:actions
npm run test:e2e:instructions
npm run test:inventory
npm run api:check
npm run pack:check
```

## Continuous integration tiers

No workflow under `.github/workflows/` runs these commands, and the aggregate
`check` script runs nine of them. The suites `check` skips are `test:vectors`,
`test:property`, `test:cross`, `test:prover`, `test:browser`,
`test:e2e:actions`, `test:e2e:instructions`, `fixtures:check`, `pack:check`, and
`lint:packages`, which are the ones that carry the parity argument. So "check
passes" reads as "the port agrees with Rust" and means something narrower
([G9-2](production-readiness-issues.md#g9-2-the-aggregate-check-script-omits-most-certification-gates-blocker)).

Three tiers replace that split. Each command belongs to exactly one tier, and
the tier a command sits in is the promise made when it passes.

| Tier | Runs on | Contains |
| --- | --- | --- |
| Commit | a local pre-commit hook and the pull-request job | `build`, `typecheck`, `lint`, `lint:packages`, `format:check`, `test:unit`, `test:inventory`, `test:exports`, `test:dependencies`, `api:check` |
| Merge | the pull-request workflow, blocking merge | the commit tier plus `test:vectors`, `test:property`, `test:cross`, `test:prover`, `test:browser`, `fixtures:check`, `pack:check` |
| Release | the release workflow and the phase-4 gate evaluation | the merge tier plus `test:e2e:actions` and `test:e2e:instructions` |

The aggregate script named `check` runs the commit tier. Either it is renamed to
match that scope or it grows to the merge tier; a script whose name outruns its
contents is the defect
([G9-2](production-readiness-issues.md#g9-2-the-aggregate-check-script-omits-most-certification-gates-blocker)).

A pull-request workflow runs the merge tier. Until one exists, nothing stops a
merge that breaks the build, the types, the lint, the tests, or fixture
agreement, and each gate in the planning documents is a manual step whose result
a reviewer cannot reproduce
([G9-1](production-readiness-issues.md#g9-1-no-workflow-runs-the-typescript-suite-blocker)).
The prover tier needs the pinned local prover and the proving-key cache keyed on
the lockfile hash, which `rust.yml` already sets up and the TypeScript job
reuses.

`format:check` selects files by glob with explicit ignores rather than the
hand-maintained path list it uses now, and the globs cover `planning/`. A list
that enumerates packages and single report files leaves a new package or
document unformatted until someone remembers to extend it
([G9-3](production-readiness-issues.md#g9-3-formatcheck-covers-a-hand-maintained-file-list-medium)).

## Post-parity cryptographic certification

The commands above, the 118-row review, specification-authority decisions, and
the package, browser, fixture, and E2E gates must pass before
[PKP-00 through PKP-08](proof-and-key-parity.md#implementation-work-packets)
start. The PKP phase adds proof and key evidence to the existing fixtures and
tests. It does not create another inventory or replace checklist verdicts.

No complete proof or key-handling parity claim may rely on request snapshots,
proof parsing, or TypeScript-only tests. Certification requires the
release-targeted native Rust verifier to accept TypeScript-produced proof
artifacts and requires real TypeScript prove, submit, verify, index, decrypt,
and sync flows against the same-revision local stack.

Local services use `ZOLANA_LOCALNET_URL`, `ZOLANA_INDEXER_URL`,
`ZOLANA_PROVER_URL`, and one `ZOLANA_PORT_OFFSET`; tests use readiness
deadlines, clean up only services they start, do not fall back to devnet, and
verify proving-key checksums.

Release evidence contains the fixture manifest and clean regeneration, the
182-row inventory-to-packet/test report, API reports, package tarball
checksums/provenance, unit/vector/property/mutation summaries, browser results,
indexer schema/transport cross-tests, smart-account vectors, prover matrix,
both independent E2E suites, and the documented deliberate deviations.
