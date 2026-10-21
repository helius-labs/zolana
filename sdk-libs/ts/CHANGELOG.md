# Changelog

## 0.5.0-alpha — unreleased

Proofs go encrypted to an attested Nitro Enclave prover by default, the devnet
enclave the SDK pins for a Helius devnet RPC URL, and any other remote prover
must attest to that pin unless the caller opts out. One private transfer can
pay several recipients, a transaction can reserve an address with a
non-inclusion proof instead of spending a UTXO, and paying a transaction's fee
no longer authorizes a spend. Viewing keys and ring auditors move to X25519,
and the auditor of an anonymous ring reads its hidden senders, inputs and
recipients. A ring policy bounds each transfer's outflow per mint, and member
registries hold list membership and escrowed keys. A merge publishes its
output's amount and mint encrypted for the owner with the scheme the owner's
registry record names, so wallet sync recovers a default merge output from the
merge transaction alone.

Breaking

- `Prover` and `RingMergeClient` require `proveCustomRingMergeAnonymous` → a custom `Prover` implements it, `ZolanaClient` already does.
- `AuditedMergeRecord.nullifier` is absent for a merge of an anonymous ring, which carries the disclosed spent commitments in `inputCommitments` instead → read the nullifier only when it is set.
- `SignatureType` no longer includes `"p256"`, and `SigningKey.generate` and `ShieldedKeypair.generate` accept only `"ed25519"` → derive PDA owners from their program and keep `P256ReaderKey` for passkey audit access.
- `@heliuslabs/zolana/ring` leaves circuit codecs, registry proof helpers and policy primitives in `@heliuslabs/zolana/ring/advanced` → import those low-level helpers from the advanced subpath.
- Ring transfer proving rejects absent or mismatched default-ring output markers with `CLIENT_OUTPUT_OWNER_MARKER_MISMATCH` before indexer or prover calls. Keep the confidential marker and the actual recipient owner tag on exits. Ordinary recipient ciphertext remains unproved.
- Ring merges preserve the common committed `ringDataHash`. Mixed input hashes or a different explicit output hash fail with `TRANSACTION_MERGE_RING_DATA_MISMATCH`. An omitted output hash inherits the inputs.

- `RingRpc` requires commitment-checked `outputOpenings`, and `AuditedRingTransaction.outputContexts` identifies every disclosed slot → read authoritative values from openings and treat `outputs` as optional recipient delivery metadata. Recovery reads both data hashes from disclosure and leaves recovered `utxo.data` empty. Read optional delivery metadata through audit outputs. Remove `resolveOutputHashes` from `RingRecoveryParams`.
- `TransactionOrigin` requires `confirmedTransaction` → custom adapters must bind indexed ciphertext, commitments, nullifiers and output positions to the exact confirmed SPP transfer, deposit or merge. Only another ring's event returns no match. A transfer with missing mandatory auditor disclosure now fails explicitly.
- Ring transfer builders select full-policy proofs for nineteen ordinary capacities, up to 16×4 and 24×2. The 24×2 audit message proves only its two published output openings, so a fully populated measured transaction fits 4,096 bytes. Anonymous key and audit catalogs now cover fourteen capacities, up to 6×4 and 12×2. They keep every hidden input in the proved disclosure. Builders use smaller proofs when registry records share an eight-leaf subtree and check transaction size before proving → deploy the matching ring program and serve all keys from this release.
- `CustomRingPolicyProofRequest.shape` sizes the input, output and subject witnesses, `registrySubtree` chooses shared paths, and `CustomRingTransferParams.transaction` includes extra signers and setup instructions in the size check → use `RING_POLICY_SUPPORTED_SHAPES` and pass all planned transaction additions before proving.
- Auditor key envelopes use a two-hash Poseidon KDF. Previous envelope ciphertexts do not open with this release's auditor client → rotate the ring prover and auditor client together.

- Asset rules use authenticated mint records in the own or curator registry. The inline eight-mint allowlist is removed. `inlineAssets` and `inlineLimits` now serve only per-mint amount guards. Scalar owner guards reject mixed-mint transfers. Replace inline asset rules with list rules and populate the mint records before transferring.

- `RingMemberRegistryReader` replaces key-registry reads with `getRingMemberRecord` and `getRingMemberRegistryRoot`, authenticated at height 20 with list bits and escrow keys → migrate custom indexer adapters and use this release's program, indexer and prover together.
- `CustomRingPolicyProofRequest` uses thirteen `subjects`, thirteen `foreignSubjects`, an own `memberRegistryRoot` even with escrow off, and one `foreignRoot`, while deposit proofs use `members` and `ctHashes` → replace entry-answer witnesses and old key-only records in custom provers.
- `RingPolicyConfig.sources` uses `registry` addresses, zero for the own registry and at most one curator registry, and asset rules read registry lists → re-pin policies under version 10 and replace curator namespace addresses.
- `buildRingListWriteTransaction` updates member records, and the old namespace list readers, entry codecs and entry-proof builders are removed → use `fetchRingMemberRecord` for authenticated list bits and `buildRingMemberUpdateTransaction` for batches of up to sixteen members.
- Key-registry types, PDA helpers, constants and error names use `MemberRegistry`/`MEMBER_REGISTRY` naming and the PDA seed is `members` → migrate imports and initialize the new registry before registration, list writes or policy transfers.

- `ViewingKey`, shielded addresses and custom-ring auditor envelopes use X25519
  keys for every transfer and ring deposit, old auditor envelopes are
  unsupported, and `DST_VIEW_ROOT_P_CONST` is no longer exported → create a new
  auditor configuration with `X25519Keypair`/`X25519PublicKey`, migrate P-256
  viewing keys and historical wallet data, and drop the
  `DST_VIEW_ROOT_P_CONST` import.
- `encryptTransactionViewingSecret` and `openAuditOutputDisclosure` mask the
  auditor output disclosure with a new keystream, and `auditPublicInputHash`
  and `policyPublicInputHash` commit to it with a new hash and to the ring
  mode, so a ring proof or auditor message of the previous release does not
  verify or open → prove and audit with the ring program and prover of this
  release.
- `SigningKey` and `ShieldedPublicKey` accept only Ed25519 ownership and PDA public keys → migrate P-256-owned notes and registry records before upgrading, use `P256ReaderKey` from `@heliuslabs/zolana/ring` for passkey audit access.
- `UserRecord` and `RegistryRecord` drop `ownerP256`, and `getRegisterInstructionAsync`, `decodeUserRecordAccount` and `fetchUserRecord` write and read the registry record without a P-256 owner key → register again on a registry program built from this version, a record in the earlier layout fails with `WALLET_INVALID_USER_RECORD`.
- `MergeTransactInstructionData` drops `eddsaOwner` → remove it from merge data you build and send merge instructions built by this version, the program refuses the earlier layout.
- `openRingDepositOpening` requires a `ConfirmedDeposit` → obtain it from the confirmed audited transaction or `RpcTransactionOrigin.confirmedDeposits`, and supply `depositSource` when recovery uses a custom confirmation provider.
- Custom-ring auditor envelopes use X25519 keys → create a new auditor configuration with `X25519Keypair`/`X25519PublicKey` before using this version.
- `ViewingKey` and shielded addresses use X25519 for new transfers and ring deposits → migrate P-256 viewing keys and historical wallet data before using this version.
- `DST_VIEW_ROOT_P_CONST` is no longer exported from `@heliuslabs/zolana/keypair` → drop the import, X25519 viewing keys derive their view root without it.
- `ProverClient` and `ZolanaClient` now require a remote prover other than the
  Helius gateway to attest to `defaultTeePolicy()` and encrypt every call to
  it, and `ZolanaClient` given a Helius devnet RPC URL and no `proverUrl`
  proves through `DEFAULT_TEE_PROVER_ENDPOINT` with
  `proofDataSource: "client"` and refuses `"prover"` → pass `tee: false` to `ProverClient` or
  `proverTee: false` to `ZolanaClient` for a prover you run, or a policy of its
  own, and set `proverUrl` to keep another prover.
- `PROVING_KEY_SHA256S` pins rotated custom ring proving keys and the RingEd25519
  transfer keys and drops `custom_ring_compressed_policy.key`, so
  `ProverClient` rejects a ring proof from a prover on the previous keys with
  `CLIENT_PROVING_KEY_MISMATCH` → prove against the prover of this release.
- `RingErrorCode` adds `RING_AUDIT_NONCANONICAL_KEY`, `RING_OUTFLOW_CAP_EXCEEDED`
  and `RING_OUTFLOW_OVERFLOW`, and loses `RING_VELOCITY_CAP_EXCEEDED`,
  `RING_VELOCITY_OVERFLOW`, `RING_VELOCITY_DISABLED`, `RING_SPEND_COUNTERS_UNKNOWN`,
  `RING_SPEND_RECORD_INVALID`, `RING_SPEND_RECORD_LINEAGE_BROKEN`,
  `RING_SPEND_RECORD_MISSING`, `RING_SPEND_WINDOW_INVALID` and the never raised
  `RING_RESERVED_AUDITOR_KEY`, while `ClientErrorCode` loses
  `CLIENT_SPEND_RECORD_OUT_OF_SYNC` → update exhaustive switches.
- `ringTransactInstruction` and `ringDelegateTransactInstruction` encode the
  new ring program layout, which carries no window index and no spend window
  accounts and which a ring program built for an earlier release rejects →
  deploy the ring program of this release.
- `RuleTable`, `RuleTableInput`, `EncodedRuleTable`, `RingPolicyConfig` and
  `CustomRingPolicyProofRequest` replace `windowSlots` and `velocity` with
  `limits`, one `CustomRingOutflowLimit` of `asset`, `cap` and `cosignAbove`
  per mint, `RING_POLICY_VERSION` is 9, `RING_POLICY_CONFIG_SIZE` shrinks by
  eight bytes and `outflowLimitsOff` replaces `velocityProofInputOff` → rename
  the fields, a table pinned under the previous release hashes differently and
  needs a re-pin.
- Spend records, spend counters and spend windows are gone:
  `prepareRingSpendRegistration`, `buildRingSpendRegistrationTransaction`,
  `createRingSpendRegistrationSubmission`, `readRingVelocityState`,
  `readRingSpendRecord`, `currentRingSpendRecord`, `registerRingSpendInstruction`,
  `setRingSpendWindowInstruction`, `clearRingSpendWindowInstruction`,
  `fetchRingSpendWindow`, `decodeRingSpendWindow`, `ringSpendWindowAddress`,
  `ZolanaClient.getRingSpendRecord`, `proveCustomRingCompressedPolicy`, the
  `SpendRecord` and `SpendCounters` codecs, the `spendRecords` field of
  `AuditedRingTransaction` and `DecryptedRingTransaction`,
  `RingTransactionSubmission.windowChanged`, `RingSubmissionAttempt.window` and
  `RingSubmissionWindowChanged` no longer exist → drop them, a table's `limits`
  bound each transfer on its own, and the co-signer signs a transfer above
  `cosignAbove`.
- Approval handlers receive a new `multiTransfer` intent for a transfer with
  several payments → handle it, or refuse it explicitly.
- Ring deposit audit capsules carry a `RING_DEPOSIT_OPENING_LENGTH` (96) byte
  opening that also discloses the Ed25519 owner key of an anonymous ring
  deposit, `RingDepositOpening` takes it as `ownerKey` and
  `openRingDepositOpening` returns it → re-prove audited deposits with this
  version, a capsule sealed by an earlier version no longer decodes.
- `setRingPolicyRulesInstruction` and `buildRingSetPolicyRulesTransaction` now
  pass the ring config as the second account, which the ring program of this
  release requires → rebuild the instruction with this version.
- `MAX_MERGE_INPUTS` is 52 and `MAX_RING_MERGE_INPUTS` is 50 and the widest merge takes 52 notes instead of 54 →
  select at most 52 notes per merge, and at most 50 on a custom ring. Extra accounts can lower
  the custom-ring limit. The builder checks the complete transaction size before proving.
- `MergeTransactInstructionData` carries `outputCiphertextSalt` and
  `outputCiphertext`, and `Merge` and `PreparedMerge` require the encrypted
  output → build merges with `Merge.fromKeypair` or the client's merge flow, or
  pass the wallet's `mergeOutputKey` answer as `Merge`'s `outputKey`.
- `DeriveRequest` has a `mergeOutputKey` kind → a custom `ShieldedKeys` answers
  it with `mergeOutputKey(nullifierKey, firstNullifier)`.
- `transactInstruction` (`getTransactInstructionAsync`) and
  `buildUnsignedTransaction` require `ownerSigners`, the Ed25519 input owners
  in first-input order, the fee payer too when it owns an input → pass the
  input owners, or `[]` when no Ed25519 owner spends.
- `KeypairErrorCode` drops `KEYPAIR_ZERO_SCALAR`, X25519 viewing keys are clamped and cannot be zero → remove it from exhaustive matches.
- `KeypairErrorCode` drops `KEYPAIR_INVALID_PREHASH_LENGTH` with P-256 signing → remove it from exhaustive matches.
- `CircuitId` kinds `ringEddsa` and `ringEddsaCached` are now `confidentialRingEddsa` and `confidentialRingEddsaCached` → rename them in matches and hand-built instruction data, the encoded bytes are unchanged.
- `MAX_MERGE_INPUTS` is 52 and the widest merge takes 52 notes instead of 54 →
  select at most 52 notes per merge, and at most 51 on a custom ring.
- `MergeTransactInstructionData` contains `outputEncryption`, a
  `MergeOutputEncryption` tagged with its scheme, `Merge` and `PreparedMerge`
  require the encrypted output (`MergeOutputCiphertext` from
  `@heliuslabs/zolana/transaction`), and `MergeInputs` and
  `PreparedMergeInputs` replace `asset` with required `mintChunks` and
  `outputCiphertextSalt` → build merges with `Merge.fromKeypair` or the
  client's merge flow, or pass the wallet's `mergeOutputKey` answer as
  `Merge`'s `outputKey`, the mint's two field chunks and the output
  ciphertext salt.
- `UserRecord`, `RegistryRecord` and `getUserRecords` records contain
  `mergeEncryption`, a `MergeEncryptionScheme`, in place of `mergingEnabled`;
  `buildSetMergingEnabledTransaction`, `getSetMergingEnabledInstructionAsync`
  and `WALLET_BUILD_SET_MERGING_ENABLED` are
  `buildSetMergeEncryptionTransaction`,
  `getSetMergeEncryptionInstructionAsync` and
  `WALLET_BUILD_SET_MERGE_ENCRYPTION`, which take a `scheme` and refuse an
  unsupported one with `WALLET_INVALID_MERGE_ENCRYPTION_SCHEME`;
  `ShieldedPoolError.MergeDisabled` (7017) is `MergeEncryptionSchemeMismatch`,
  returned for a merge whose scheme differs from the owner's registered
  scheme, a disabled record included; and `WALLET_MERGE_DISABLED` is
  `WALLET_MERGE_ENCRYPTION_SCHEME_UNSUPPORTED` for a disabled or unsupported
  scheme → opt in with `MergeEncryptionScheme.PoseidonCtrV1`, out with
  `MergeEncryptionScheme.Disabled`, and update error matches to the new names.
- `DeriveRequest` has a `mergeOutputKey` kind and `ShieldedKeys.derive` transfers
  ownership of its returned buffers → answer with
  `mergeOutputKey(nullifierKey, firstNullifier)` and return fresh buffers that
  the caller can wipe.
- `transactInstruction` (`getTransactInstructionAsync`) and
  `buildUnsignedTransaction` require `ownerSigners`, the Ed25519 and PDA owners
  of inputs and of outputs that carry data in first-occurrence order, the fee
  payer too when it is one of them, and `RingEntryTransitionInput` and
  `RingEntryTransitionProofInputs` no longer take `payer` → pass those owners,
  or `[]` when there are none, and drop `payer`.
- `MergeInputs` and `PreparedMergeInputs` replace `asset` with required
  `mintChunks` and `outputCiphertextSalt` → pass the mint's two field chunks
  and the merge output ciphertext salt, or use the SDK's merge builders.
- `ProverClient` requires rotated confidential, ring and anonymous ring
  transfer keys and both merge key sets, replacing the 54-input merge keys
  with 52-input keys → deploy the matching prover key set before upgrading.
- `buildDepositTransaction` now reads the chain for an SPL deposit and, when
  the mint has no vault, adds its creation paid for by the depositor, failing
  with `WALLET_PROTOCOL_CONFIG_NOT_FOUND` when the chain has no protocol config
  and `WALLET_SPL_INTERFACE_CREATION_RESTRICTED` when the config does not let
  the depositor create the vault, and accepts `setupInstructions`, which it
  places before every other instruction → pass `createSplInterface: false` to
  keep building the deposit alone.
- Ring merge proofs bind the ring's anonymous flag beside the member registry root, and `ringMergeInstruction` writes the disclosure option ahead of the merge body → deploy this release's shielded-pool program, ring program and merge keys together.
- `serializeWallet` writes version 5 snapshots with `pendingNotes` → upgrade snapshot readers before saving, versions 2 to 4 stay readable.

Added

- `/zolana/client` exports `CustomRingMergeAnonymousProofRequest` and `CustomRingMergeSlot`, the request `Prover.proveCustomRingMergeAnonymous` takes to prove an anonymous ring merge, and `RingMergeRegistryProof`, the registry proof `MergeAssembler.proveMerge` takes.
- `buildRingMergeTransaction` merges notes in an anonymous ring from a `nullifierKey`, opening the member record without an escrowed key and proving the auditor disclosure of the merged note, and refuses a merge wider than 24 inputs with `RING_ANONYMOUS_MERGE_TOO_WIDE` and a missing key with `RING_ANONYMOUS_NULLIFIER_KEY_REQUIRED`.
- `syncWallet` given `anonymousRing: AnonymousRingState` and keys with `ringViewTags` walks the recipient's inbox, pair, deposit and change streams of an anonymous ring by exact tags, stores the scheme-9 notes whose commitments match, and returns `SyncReport.anonymousRing` with the notes, the new counterparties, the next index per stream and the addresses under spam.
- `RingTagKeys` extends `ShieldedKeys` with `ringViewTags`, answered by `LocalShieldedKeys` and `LocalKeys`, and `RingTagRequest` names one inbox, pair, deposit or change tag.
- `decryptTransactions` takes `anonymous: AnonymousTagRoutes` and opens a scheme-9 slot only under the key its tag is routed to, with `DECRYPTIONS_PER_INDEX` openings per tag.
- `TagStream.firstFreeIndex` and `occupiedIndices` read a tag stream in `DEFAULT_TAG_WINDOW` sized windows against the indexer, an output nobody can open still occupies its index.
- `auditRingMerges` returns `disclosed`, every merge of an anonymous ring opened from the disclosure its ring program verified, with the owner key, the output opening and the spent commitments in `RingMergeOpening`; `openRingMergeDisclosure`, `ringMergeAnonymousPublicInputHash` and `mergeDisclosureFieldCount` expose the same opening and statement, and `ringMergeInstruction` takes the `RingMergeDisclosure` an anonymous ring requires. An anonymous ring merges at most 24 notes, a 52-slot merge with its disclosure does not fit a transaction.
- `WalletErrorCode` adds `WALLET_TAG_STREAM_EXHAUSTED` for a tag stream with no free index below 2^64.
- `RingAddress` and `RingPaymentRequest` encode and parse the `zolana:` payment request a ring member shares off chain, with its checksum, amount, mint and label, and `InboxSecret.viewTag` gives a payer the tag of each first payment to that address.
- `ViewingKey.inboxSecret`, `pairKey`, `pairSendViewTag`, `ringChangeViewTag` and `ringBlindingSeed` derive the inbox secret, the per-recipient pseudonym, the pair and change view tags and the blinding seed of an anonymous ring payment, and `senderViewTag`, `sendSharedViewTag` and `recipientSharedViewTag` derive the counter and pair tags Rust wallets already scan.
- `encodeRingAnonymous` and `decodeRingAnonymous` read and write `RingAnonymousOutputPlaintext`, the 104-byte opening `assetAddress`, `amount`, canonical `blinding` and `pairU` a recipient recomputes its commitment from, and `ringAnonymousBodyHash` gives the statement element of a published body.
- `ViewingKey.sealAnonymousOutput` and `openAnonymousOutput` run the proven scheme-9 body cipher, keyed by `recipientStreamSecret` from the transaction key, the recipient viewing key, the salt and the slot, and `DecryptRequest.label` accepts `"ringAnonymous"`.
- `encryptAnonymousRingTransfer` seals every slot of an anonymous ring transfer from a `RingAddress` per real output, seals an exit to the default ring under its owner with `assets`, pads the other slots with random bodies and tags in the same framing, refuses records, memos and compact padding, and returns the auditor message, the prover delivery inputs and the body hashes.
- `proveAnonymousRingTransfer` and `buildAnonymousRingTransferTransaction` prove and build a transfer on an anonymous ring from an `AnonymousPreparedTransfer`, whose `prepare(transfer, payments)` builds each `AnonymousRingPayment` output from its `RingAddress` so the output carries that address's own first-payment or paired tag, may exit to the default ring, carries the outflow limits and the co-signer they demand, and refuses a shape, slot, tag or public signer the ring program refuses with a named `RingErrorCode` before any prover call.
- `proveAnonymousRingTransfer` and `buildAnonymousRingTransferTransaction` read every withdrawal destination before any prover call, reading a Token-2022 account with extensions the way the program does, and refuse one the program refuses or one that names the hidden owner with `RING_ANONYMOUS_EXIT_LINKS_OWNER`, `RING_ANONYMOUS_EXIT_ACCOUNT_HAS_DATA`, `RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_INVALID`, `RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_ON_CURVE` or `RING_ANONYMOUS_EXIT_TOKEN_ACCOUNT_SHARED`.
- `ShieldedPoolError` names `AnonymousExitDestinationsDiffer` (7084), `AnonymousExitTokenAccountShared` (7085), `AnonymousExitAccountHasData` (7086) and `AnonymousExitTokenAccountOnCurve` (7087), the program's refusals of an anonymous withdrawal whose legs name two keys, whose token account has a delegate or a close authority, whose SOL recipient is not a system account without data, or whose token account sits at a keypair address.
- `AnonymousSpendSigner` signs the hidden owner's `ringSpendMessage` for the proof, and `signingKeySpendSigner` and `messageSignerSpendSigner` adapt a `SigningKey` or a wallet's kit message signer.
- `ZolanaClient.proveAnonymousRingTransact` proves the anonymous SPP spend from an `AnonymousRingTransactProofInput`, `ProverInputs` carries its `AnonymousEddsaAuthorization`, and `CircuitId` encodes the `"anonymousRingEddsa"` selector with its proof commitment like Rust.
- `AnonymousRingTransactProofInput.exitTokenOwner` names the owner of an SPL withdrawal's token account, the key the proof binds for the withdrawal, and `ZolanaClient.proveAnonymousRingTransact` fails with `CLIENT_ANONYMOUS_EXIT_TOKEN_OWNER_MISMATCH` when it is set without an SPL withdrawal or left out beside one, and with `CLIENT_ANONYMOUS_EXIT_DESTINATIONS_DIFFER` when the withdrawals name two keys.
- `CustomRingBaseProofRequest.anonymous` and `CustomRingPolicyProofRequest.anonymous` send the hidden identities, with a zero viewing key for an exit slot, and the proven `delivery` bodies of an anonymous ring, and `ANONYMOUS_RING_SHAPES` lists the shapes its proofs cover.
- `AnonymousTagAllocator` assigns one inbox, pair or change tag per output slot over a `TagStream`, taking the lowest index free in history and in the transaction itself, and `AnonymousRingDestination` names where each slot goes.
- `recoverAnonymousRing` scans every scheme-9 slot of a ring's confirmed history through a stated head under every viewing key the wallet holds, and fails with `WALLET_RECOVERY_INCOMPLETE` on a page limit or an incomplete response, with `WALLET_RECOVERY_BEHIND_HEAD` when the indexer has not reached the head, with `WALLET_RECOVERY_FOREIGN_ROW` on a returned row that names another ring or none, and with `WALLET_RECOVERY_MALFORMED_SLOT` on a ring transaction slot that lacks its transaction viewing key, its salt or a body of the exact length.
- `SyncReport.pendingAssets` holds commitment-verified anonymous notes whose mint the registry does not know, `Wallet.pendingNotes` keeps them with their full opening across syncs and saves, `resolvePendingNotes` admits each one whose mint is now registered without a rescan and reports it spent when the wallet already holds its nullifier, `syncWallet` commits with pending notes held and resolves them after its registry backfill, `AnonymousRingReport.badPairHints` names stored notes whose pair hint is no X25519 key, and `AnonymousRingReport.malformedSlots` lists each ring transaction slot a tag sync skipped because the ring program refuses it, as a `MalformedAnonymousSlot` with its signature, slot index, view tag and `AnonymousSlotDefect`.
- `AuditedRingTransaction.payloadErrors` and `DecryptedRingTransaction.payloadErrors` list an `OutputPayloadError` for each slot whose recipient payload gave no output and a `pairHint` for an opened ring note whose pair hint is unusable, which keeps its output, and `RingRpc.getDecryptedTransactions` reads every kind the Rust ring rpc writes.
- `auditRingTransaction` and `auditRing` with `mode: "anonymous"` rebuild an exit's commitment from its disclosed opening and report an exit body that does not match it in `payloadErrors`.
- `AnonymousOutputOpening` is a `padding`, `ring` or `exit` slot by `kind`, a `ring` slot carries its `AnonymousOutputOwner` and the `viewingPublicKey` that opens its proven body, an `exit` slot discloses its `amount`, `asset` and `blinding`, an anonymous audit disclosure takes five values per output, and `openAnonymousAuditDisclosure` refuses an owner whose `identityTag` is not `SOLANA_OWNER_TAG`.
- `auditPublicInputHash` and `policyPublicInputHash` accept `anonymous: true` to bind anonymous statements, matching the Go and Rust transcripts.
- `CustomRingBasePublicInput.outputBodyHashes` binds the published scheme-9 bodies, `auditPublicInputHash` and `policyPublicInputHash` chain thirteen base elements, a ring that is not anonymous chains one zero per output.
- `RingRpc.getDecryptedTransactions` returns hidden senders, inputs and
  recipients in `anonymous` for authorized anonymous-ring audit readers, each
  recipient bound to the owner commitment of its slot in `outputOpenings`,
  which holds the slot's amount and mint, and
  `openAnonymousAuditDisclosure`, `auditDisclosureLength`,
  `anonymousAuditDisclosureShape` and `isDummyAnonymousOutput` open and size
  the auditor disclosure of an anonymous ring.
- `buildMultiTransferTransaction(params)` pays up to fifteen recipients of
  one asset in one private transfer, each a `TransferPayment` in order (a
  single payment stays a `transfer` intent), accepts a `feePayer` other than
  the wallet owner like `buildTransferTransaction`, and refuses an empty,
  longer than fifteen or malformed payment list with
  `WALLET_INVALID_PAYMENT_COUNT` or `WALLET_INVALID_PAYMENT`.
- `ShieldedPoolError` names three new program rejections: `TreeFeeTooHigh` for a
  tree fee per nullifier above the program's cap, `TreeCreationMismatch` for a
  tree creation step that differs from the step that started it, and
  `NonCanonicalMergeCiphertext` for a merge ciphertext element outside the
  BN254 field.
- `DEFAULT_TEE_PROVER_ENDPOINT` is the pinned deployment's prover URL, for a
  client that names its prover, and `ProverClient.hasIndexedRoute` says
  whether the prover reads proof data from its own indexer, false for the
  Helius gateway and `DEFAULT_TEE_PROVER_ENDPOINT`.
- `RingProgramError` names `unexpectedMemberRegistryRoot`, `unexpectedApproval`,
  `invalidSettlementAccounts`, `tooManyPublicLegs`, `invalidAuditedDeposit`,
  `invalidDepositData`, `memberBatchOrder`, `memberBatchTooLarge` and `memberRecordMismatch`, and `ShieldedPoolError`
  names `RingEd25519OutputOwnerTag`, the refusals of this release's programs.
- `RingProgramError.missingFundingSigner` rejects an unsigned depositor or payer before the ring signs its SPP call.
- `ProofInputUtxo.address(owner, seed, treeId)` reserves an address of an
  Ed25519 or PDA owner with a non-inclusion proof and no spent UTXO, which only
  the default confidential transfer proves; `isAddress()`,
  `requiresInclusion()`, `validateAddress()`, `addressNullifier` and the
  constructor's `address` option read and build such an input, and
  `createInputUtxo` and `InputUtxo` take its `addressNullifier`.
- `TransactionErrorCode` adds `TRANSACTION_ADDRESS_INPUT_ZERO_OWNER`,
  `TRANSACTION_ADDRESS_INPUT_NONCANONICAL_SEED`,
  `TRANSACTION_ADDRESS_INPUT_NONEMPTY_FIELD`,
  `TRANSACTION_ADDRESS_INPUT_COMPACT`, `TRANSACTION_ADDRESS_INPUT_CACHED`,
  `TRANSACTION_ADDRESS_INPUT_NULLIFIER_PUBLIC_KEY_MISMATCH`,
  `TRANSACTION_ADDRESS_INPUT_NULLIFIER_MISMATCH` and
  `TRANSACTION_NOT_ADDRESS_INPUT` for an invalid address input, and
  `ClientErrorCode` adds `CLIENT_ADDRESS_INPUT_UNSUPPORTED` for an address
  input on the ring authority or merge rail and `CLIENT_INVALID_ADDRESS_INPUT` for a prover
  request that proves an address as another kind of slot.
- `transactCpiAccounts(input)` returns the `transactInstruction` accounts with
  a program's signing PDAs after the owner signers,
  `encodeTransactInstructionData(data)` returns the `transact` instruction
  data without its leading `InstructionTag.transact` byte, which a program
  prepends when it forwards the data through a CPI, and `TransactAccountsInput`
  names their input, all from `@heliuslabs/zolana/interface`.
- `SettlementTransfer`, the leg type of `ExternalData.interfaceTransfers`, is
  exported from `@heliuslabs/zolana/transaction`; `bytes16`, `bytes31`,
  `bytes32`, `bytes33`, `bytes34` and `bytes64` copy a `Uint8Array` into the
  matching fixed-length type and refuse any other length with
  `KEYPAIR_INVALID_LENGTH`; and `ShieldedPublicKey.fromPda` and
  `ShieldedAddress.forPda` also take the PDA as an `Address`.

Changed

- `auditRing`, `auditRingMerges` and ring member recovery fail with `RING_SCAN_FRONTIER_MISSING` when the indexer's last page names neither a next cursor nor a scan frontier, where they reported a complete scan.
- `proveCustomRingTransfer` on an anonymous ring fails with `RING_ANONYMOUS_SIGNER_REQUIRED` and the delegate rail with `RING_ANONYMOUS_REFUSED`, prove those transfers with `proveAnonymousRingTransfer`.
- `AuditedRingTransaction` and `DecryptedRingTransaction` replace `undecryptableSlots` with `payloadErrors` → read the slot index from each entry and its `kind`.
- `AnonymousNote.pairPublicKey` and `AnonymousRingNote.pairPublicKey` are optional, a note stays stored when its pair hint is unusable.
- `syncWallet` opens every output under a spammed inbox index and still reports the address in `addressesUnderAttack`.
- `RingDelegateTransferParams.compactPadding` lets ordinary and recovered delegate builders omit unused public slots, revealing actual counts and allowing the exact 2×3 policy proof when the registry paths share a subtree, while the default keeps padded counts.

- `ProverClient` validates custom-ring proving keys against the regenerated circuit keys, including the member-update key.
- `defaultTeePolicy()` now returns the pinned devnet enclave's measurements
  and encryption key instead of throwing.
- Merge decryption rejects non-canonical ciphertext with
  `TRANSACTION_NON_CANONICAL_MERGE_CIPHERTEXT`.
- Transfers, withdrawals, splits and custom ring transfers list an input owner
  who also pays as an owner signer, and a fee payer that owns no input no
  longer appears in their proofs.

Fixed

- `proveAnonymousRingTransfer` treated every output owned by the sender's signing key as change, so a payment to the sender's own `RingAddress` published a change tag and a payment to an address with another viewing key failed with `TRANSACTION_ANONYMOUS_SLOT_MISMATCH`, now each `AnonymousRingPayment` takes its address's inbox or pair tag and is sealed to that address's viewing key, and only an unpaid output owned by the sender's full address is change.
- `syncWallet` aborted on an anonymous note whose pair hint is a low-order X25519 key, now the note is kept and the hint is reported in `badPairHints`. `auditRingTransaction` reports the same hint as a `pairHint` payload error. It also checked every output against tree 0, so a merge into another tree failed with `TRANSACTION_MERGE_OUTPUT_UNDECRYPTABLE` or was dropped, now each output is checked against its indexed tree id.
- `syncWallet` failed with `CLIENT_INVALID_RPC_RESPONSE` on any indexed transaction whose published viewing key is not a valid X25519 key, now such a transaction is read without a viewing key and its outputs count as undecryptable, as do outputs under a small-order transaction key.
- `RingRpc` rejects incomplete, repeated or oversized signed audit pages instead of silently treating them as complete.
- `auditRingMerges` now surfaces registry read failures instead of reporting members as merely unavailable.
- `RingProgramError.missingOwnerSigner` reports an owner account that did not sign before the ring forwards a transfer, and public deposit sources must also sign before the ring PDA signs for SPP.
- `RingRpc.getDecryptedTransactions` now includes the SPP event index on opened and skipped records, so separate ring events in one Solana transaction have distinct identities.
- `auditRing` now recognizes a terminal scan at the page limit even when Photon also returns a row cursor, so `recoverRingMemberNotes` does not report a complete history as incomplete, and invalid page limits fail instead of returning an empty audit.

- `syncWallet` and custom ring recovery could not recover a merge output
  without every input, and `syncWallet` committed past an unreadable owned
  merge; both now recover merge outputs from valid ciphertext alone,
  `syncWallet` rejects an unreadable owned merge with cause
  `TRANSACTION_MERGE_OUTPUT_UNDECRYPTABLE` while preserving wallet state and
  cursors, and `Merge.fromKeypair`, wallet merge building, wallet sync and ring
  recovery wipe temporary merge output keys on both success and failure.

- `recoverRingMemberNotes` reconstructs notes from proved auditor openings even when recipient ciphertext is missing, misleading or addressed to another viewing key, and unresolved assets remain explicit.
- `RingTransactionSubmission` retries proofs invalidated by either the own or curator registry history and retains pending state when a registry read fails.

- `recoverTransactionViewingKey`, `auditRingTransaction`, `auditRing` and
  `recoverRingMemberNotes` read output disclosures under an alias of the
  recovered transaction viewing key and rejected the auditor message of an
  anonymous ring, and `decodeRingProgramConfig` threw on one; an alias now
  fails with `RING_AUDIT_NONCANONICAL_KEY`, the audit functions take
  `mode: "anonymous"` and report hidden senders, inputs and recipients in
  `anonymous`, and the config decodes with `mode`.
- `ZolanaClient.assembleAuthorizedPrivateTransaction` did not list the owner
  of an output that carries data as a transaction signer, and
  `ZolanaClient.proveTransact` left that owner out of the proof's signer
  vector, so the shielded pool rejected the proof; that owner now signs after
  the input owners.
- `ConfidentialTransfer` encoded the padding slots of a self-paid transfer
  differently from the sender's change, so an observer could tell them apart, and padding now uses the same encoding as change.

## 0.4.1-alpha — 2026-10-08

A client pointed at a Helius RPC URL reaches the shielded-pool indexer and
prover through the Helius gateway's `/v1/zolana` routes. On the gateway,
proofs fetch their Merkle data on the client and go to the prover's key-less
path. A Nitro Enclave prover can be held to one encryption key, and a
sponsor can pay the fee of a private transfer, withdrawal, or split. Nullifier
trees append 4,999 nullifiers per proof, which shrinks a tree account to two
creation instructions.

Breaking

- `TransactionErrorCode` no longer includes `TRANSACTION_ED25519_PAYER_MISMATCH`,
  since a fee payer other than the owner is now accepted → remove it from
  exhaustive switches.
- `NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE` is 4999 (was 250) and
  `NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE` is 24,995 (was 25,000), so
  `NULLIFIER_TREE_ROOT_HISTORY_CAPACITY` is 5, `TREE_ACCOUNT_SIZE` is 18,608
  and `TREE_CREATION_STEP_COUNT` is 2 → point the client at a deployment
  created with this release, since tree accounts of the previous layout no
  longer decode.
- `PROVING_KEY_SHA256S` pins `batch_address-append_40_4999.key` in place of
  `batch_address-append_40_250.key` → run a prover with the matching key set.

Added

- `AwsNitroPolicy.hpkePublicKey` optionally pins the prover's encryption key, and
  `proverTee` then refuses an attestation that offers any other key.
- `buildTransferTransaction`, `buildWithdrawalTransaction` and
  `buildSplitTransaction` accept a `feePayer` other than the wallet owner and
  return a transaction the owner co-signs, and `transactInstruction` takes
  `ownerSigners` to list those co-signers.

Changed

- `ZolanaClient` given only a Helius RPC URL such as
  `https://devnet.helius-rpc.com/?api-key=…` now sends indexer and prover
  calls to that host's `/v1/zolana` path instead of its root.
- `ZolanaClient` with its prover on a Helius RPC host's `/v1/zolana` URL defaults to
  `proofDataSource: "client"` and refuses `"prover"`, and `ProverClient` on such
  a URL posts every proof to `/v1/zolana/prove` and polls
  `/v1/zolana/prove/status`.

Fixed

- `syncWallet` ignored the `requireSlot` and `poll` of the client's
  `indexerConfig` and now applies them, exposed as `SyncClient.indexerConfig`,
  whenever `SyncWalletConfig.requireSlot` or `retry` is unset.

## 0.4.0-alpha — 2026-10-07

SDK proofs fetch their Merkle data on the prover by default, which removes the
client's indexer round trip before each proof, and the client route stays
available. Transfers prove on a grid of up to 49 inputs and 16 outputs, merges
take up to 54 notes in one transaction, wallet sync recovers the output of
such a merge, and transfers can leave their unused slots out of the
transaction at the cost of revealing the real counts, which every merge now
does.
Registration never replaces an owner's published keys, and replacing them is
its own transaction. The private transaction hash ignores padding and no longer
covers the external data, which P-256 owners now sign alongside it.

Breaking

- `ZolanaClient` now defaults to `proofDataSource: "prover"` for transfers,
  merges, caches, ring policy proofs and escrowed deposit audits,
  `MergeAssembler.proveMerge` no longer takes `indexer`, `MergeClient`,
  `PrivateTransactionClient`, `RingDepositClient`, `RingTransferClient`,
  `RingDelegateProofClient`, `RingMergeClient`, `PolicyAnswerInput` and
  `openRingEscrowedKeys` require `proofDataSource`, and `RingMergeClient`
  requires `proveMerge` in place of `getInputMerkleProofs` and
  `getNonInclusionProofs` → configure `PROVER_INDEXER_URL` on the prover or
  select `proofDataSource: "client"` to keep SDK fetching, add the field to
  custom client implementations and `openRingEscrowedKeys` calls, drop
  `indexer` from `proveMerge` calls, and implement `proveMerge` in a custom
  `RingMergeClient` and `IndexedProofAuthority.proveIndexed` in remote key
  holders.
- `ClientErrorCode` gains `CLIENT_PROVER_INDEXER_UNCONFIGURED` and
  `CLIENT_INDEXER_PROOF_DATA_NOT_READY` → handle both in exhaustive switches.
- `buildRegistrationTransaction` rejects with `WALLET_BUILD_REGISTRATION` and
  `causeCode` `WALLET_USER_RECORD_KEYS_MISMATCH` when the owner's record holds
  other keys, where it used to replace the viewing key and send the owner's
  payments to the new one → call `buildKeyUpdateTransaction` to replace the
  viewing key on purpose.
- `WalletErrorCode` gains `WALLET_BUILD_KEY_UPDATE` and
  `WALLET_USER_RECORD_KEYS_MISMATCH` → handle both in exhaustive switches.
- `CLIENT_INVALID_FIELD` and `CLIENT_INVALID_INTEGER` no longer copy the
  rejected value, a nullifier secret included, into `details` or the error's
  JSON, and their `ClientErrorDetailsMap` types drop `value` → read
  `details.field` to name the rejected input and drop `value` when
  constructing either error.
- `ClientErrorCode` gains `CLIENT_PROVER_TEE_ATTESTATION` and
  `CLIENT_PROVER_TEE_ENCRYPTION`, each naming the failed check in
  `details.check` → handle both in exhaustive switches.
- `MERGE_INPUTS` is removed from `@heliuslabs/zolana/transaction` → import
  `MERGE_INPUT_COUNT`, the 24-input default, or `MAX_MERGE_INPUTS` from
  `@heliuslabs/zolana/interface`.
- `SPP_SUPPORTED_SHAPES` lists 38 shapes of 1 to 49 inputs and 2, 4, 8 or 16
  outputs in proving-cost order, `selectSppShape` and transfers take the
  cheapest one that fits, and the 1x1, 2x3, 3x3, 4x3 and 5x3 transfer shapes,
  the 8 and 36 input merges and the 1x1 and 3x3 ring authority shapes are
  gone, so a declared removed shape fails with `TRANSACTION_UNSUPPORTED_SHAPE`,
  a ring authority transfer of one or three slots proves the 2x2 or 4x4 shape,
  and a ring list entry write or spend registration proves the 1x2 shape →
  declare a listed shape and prove against the program and prover of this
  release.
- `MAX_CACHE_WRITES` is 16, so `bindCacheWrite`, `validCacheWrites` and a
  cached `CircuitId` take 16 write slots and a cached selector encodes to 40
  bytes → pass `NO_CACHE_WRITES` or 16 entries and build cache writes with
  this release.
- `ProverClient` and `ZolanaClient` send each proof to the path of its proving
  key, `/prove/<key>` or `/prove/<key>/indexed`, and poll a queued one at
  `/prove/<key>/status`, so a gateway can route and price each key apart, and
  a prover that predates these paths answers 404 → upgrade the prover before
  the SDK.
- `privateTxHash` no longer takes `externalDataHash` and skips zero entries in
  its input, output and address chains, so padding no longer changes it,
  `SppProofInputs.messageHash()` returns a new digest that also covers the
  external data and a transfer's cache write, and `CustomRingPolicyProofRequest` drops `externalDataHash` and
  takes a zero `addressChain` for a transfer that creates no address → drop
  `externalDataHash` from hand-built hash inputs and policy requests, sign
  again, and prove against the program and prover of this release.
- `PreparedTransfer.withInputTreeLast`, `TRANSACTION_INPUTS_NOT_GROUPED_BY_TREE`,
  `CLIENT_INPUTS_NOT_GROUPED_BY_TREE` and
  `ShieldedPoolError.InputsNotGroupedByTree` are removed, leaving code 7063
  unused, because a transfer may now spend inputs from different trees in any
  order, a padding input that names a tree no real input uses fails with
  `CLIENT_INPUT_TREE_UNRESOLVED`, and `SppProofInputs` refuses a real input or
  output that follows a padding slot with `TRANSACTION_REAL_SLOT_AFTER_DUMMY` →
  drop the calls and the handling of the removed codes, handle the new ones and
  place padding after every real slot.
- `TransactionErrorCode` gains `TRANSACTION_CACHED_OUTPUT_WITHOUT_WRITE_CACHE`,
  `TRANSACTION_DUPLICATE_CACHE_WRITE_SLOT` and `TRANSACTION_UNUSED_WRITE_CACHE`,
  which `SppProofInputs.messageHash()` throws for a cache write the program
  would reject → handle them in exhaustive switches.
- `TransactionErrorCode` gains `TRANSACTION_SLOT_AFTER_COMPACT_PADDING`, which
  `SppProofInputs` and `PreparedMerge` throw for a slot after compact padding,
  and `ShieldedPoolError` gains
  `ZeroInputNullifier` and `ZeroOutputUtxoHash` → handle them in exhaustive
  switches.
- `ProofOutputUtxo` requires `isCompact()`, which the outputs
  `createProofOutput` returns provide → add it to custom `ProofOutputUtxo`
  implementations, returning `true` only for compact padding.
- `PROVING_KEY_SHA256S` pins rotated transfer, merge and custom ring policy
  proving keys, so `ProverClient` rejects a proof from a prover on the previous
  keys with `CLIENT_PROVING_KEY_MISMATCH` → prove against the prover of this
  release.
- `ConfidentialTransfer.withCompactChange`, `ChangeLayout`,
  `PreparedTransfer.changeLayout` and `RING_PADDED_CHANGE` are removed because
  `ConfidentialTransfer.prepare` places only the change outputs it keeps first,
  SPL before SOL, with the recipients right after them, and
  `SENDER_SLOT_COUNT` is now the maximum number of change outputs rather than
  the recipients' first slot → drop the calls and the handling of the removed
  code, and read the change output count from
  `PreparedTransfer.senderOutputCount`.
- `anonymousSenderUtxos`, `plaintextTransferUtxos`, `anonymousSenderFromUtxos`
  and `plaintextTransferFromUtxos` put the SOL change at slot 0 when there is
  no SPL change and the recipients right after the change outputs present, and
  `plaintextTransferFromUtxos` takes its UTXOs in slot order from slot 0 and
  refuses any other order with `TRANSACTION_INVALID_OUTPUT_POSITION`, so a
  bundle built by an earlier release without an SPL change no longer recovers
  its outputs → build transfers and their bundles with this release.
- `PreparedTransfer.withAppendedSlot` requires `recordSlot`, the output slot
  the appended record takes, and refuses a slot before the transfer's outputs
  or past the shape with `TRANSACTION_UNSUPPORTED_SHAPE` → pass the number of
  the transfer's own outputs.

Added

- `ZolanaClientConfig.proofDataSource` accepts `"prover"` to fetch transfer and
  merge proof data on the prover, with `LocalKeys.proveIndexed` or a remote
  `IndexedProofAuthority` completing the request, a prover without an indexer
  failing with `CLIENT_PROVER_INDEXER_UNCONFIGURED`, and an output owner
  without an escrowed key failing with `CLIENT_KEY_REGISTRY_MEMBER_UNREGISTERED`
  naming `details.member`, which ring builders report as
  `RING_UNREGISTERED_OUTPUT_KEY` as with `"client"`, while
  `buildTransferTransaction`, `buildWithdrawalTransaction`,
  `buildSplitTransaction`, `buildMergeTransaction` and the ring transaction
  builders wait out `CLIENT_INDEXER_PROOF_DATA_NOT_READY` up to the retry
  bound instead of failing.
- `ZolanaClient.getUserRecords(owners)` and the `UserRecordReader` port read
  the registry records of up to 100 owners from the indexer in one request,
  returning a `UserRecordsLookup` with one `RegistryRecord` or `null` per
  owner in request order.
- `buildKeyUpdateTransaction(input)` replaces the viewing key published for an
  owner, returns `undefined` when the record already holds the address, and
  rejects a missing record and a changed nullifier key.
- `ConfidentialTransfer.compact` pads unused slots with compact padding, which
  the transaction leaves out and which costs no nullifier account, queue entry
  or tree leaf but reveals the real input and output counts, while each compact
  slot still takes a non-inclusion proof for the nullifier it derives.
- `ProofInputUtxo.compact` creates one compact padding input, which names the
  first input tree, carries its derived nullifier in `nullifier()` and 0 in the
  new `ProofInputUtxo.publishedNullifier()`, `ProofOutputInit.compact` makes
  `createProofOutput` return a compact padding output,
  `ProofInputUtxo.isCompact()`, `ProofOutputUtxo.isCompact()` and
  `ProofOutputUtxo.compact` tell compact padding from a random dummy, and
  `PreparedTransfer.compactPadding` is `true` for a transfer that
  `ConfidentialTransfer.compact` prepared.
- `IndexedProofLookup` names an `IndexedProofInputs` lookup entry, whose
  `nullifier` carries the derived nullifier of a compact slot for the prover to
  fetch and is `null` for every other slot.
- Wallet sync recovers the output of a compact merge, which publishes only the
  nullifiers it sends.
- `Merge` and the named `inputs` of `buildMergeTransaction` take up to
  `MAX_MERGE_INPUTS` (54) notes in one transaction, padded to the 8-input
  proof, above 8 to the 24-input proof or above 24 to the 54-input proof, and
  `buildRingMergeTransaction` and `createRingMergeSubmission` take
  `maxInputs`, 24 by default and at most 54.
- `ZolanaClientConfig.proverTee` takes a `TeePolicy` and sends every prover
  call, encrypted, only to a prover whose attestation matches it, an Intel TDX
  VM on Phala dstack under a `DstackTdxPolicy` or an AWS Nitro Enclave under an
  `AwsNitroPolicy` that pins its PCR0 to PCR2.
  Concurrent calls share one attestation. It takes up to three attempts after a
  transport failure, a 503, or a 429. It waits out the `Retry-After` of a 429,
  in seconds or as an IMF-fixdate. It re-attests and resends once when a Nitro
  enclave lost its key.
- `teePolicyFromJson` parses a policy that names its `platform` and refuses
  unknown fields, and `ZolanaClient.attestProver` returns the verified
  `AttestedProver` with its `platform`, HPKE key, `imageId` (the dstack compose
  hash or the Nitro PCR0) and, on dstack, `tcbStatus`.
  `defaultTeePolicy()` rejects with `CLIENT_PROVER_TEE_ATTESTATION` and
  `details.check` `no_default_deployment` when the release has no deployment pin.
  This release requires an explicit policy.

Changed

- `Merge`, `Merge.fromKeypair`, `buildMergeTransaction`,
  `buildRingMergeTransaction` and `createRingMergeSubmission` fill a merge's
  unused slots with compact padding where they used random dummies, so a
  merge reveals its real input count, sends no nullifier for an unused slot,
  and a ring merge of up to 53 notes fits one transaction, while `Merge` still
  takes one `dummyNullifiers` entry per padded slot.
- UTXO selection for transfers, withdrawals, merges and splits skips
  zero-amount UTXOs.
- `buildTransferTransaction` and `buildWithdrawalTransaction` select up to 40
  UTXOs where they stopped at 5, the most that always fit one transaction, and
  still refuse a wider cover with `WALLET_TOO_MANY_INPUTS`, merge first.
- `buildMergeTransaction` without named inputs sweeps up to 24, and
  `emptyCachedInputFields` and `cachedInputFields` accept up to 49 inputs where
  they stopped at the 36 cache slots.
- `getMergeTransactInstructionAsync` accepts from one to `MAX_MERGE_INPUTS`
  nullifiers, the counts a compact merge sends, where it took only 8 or 36.

Fixed

- A proof a prover of this release refused with `429` could be refused again
  on retry, `ZolanaClient` now asks that prover to queue the retried proof.
- Wallet sync skipped the output of a merge with more than eight inputs, such
  as one the Rust SDK built, and the merged note now appears in the wallet.
- `ZolanaClient.proveMerge` could throw an error other than `ClientError`, and
  every `ZolanaClient` proving method now throws a `ClientError`.
- `proveCustomRingTransfer` on a ring with a spend window put padding before
  the spend record, which the transaction proof refuses, and now places the
  record after the spent UTXOs and before the padding inputs, and fills a
  spare output slot before the record output with a zero-amount copy of the
  sender's change, else of the last output, so that slot adds no subject to
  the ring's rules.
- `buildWithdrawalTransaction` failed with `WALLET_BUILD_WITHDRAWAL` when an
  owner who also pays the fee withdrew the whole balance of an SPL mint, and
  now builds that withdrawal with a zero-amount SOL change output.
- A custom-ring transfer that padded an output slot, such as a
  `buildRingWithdrawalTransaction` that keeps change and is paid for by its
  owner, built a proof the prover refuses, and its padding now stays in the
  ring as Rust's does.
- A custom-ring transfer on a ring with a spend window could exceed the
  4,096-byte transaction limit or be refused with `RING_BUILD_TRANSFER`, as a
  transfer to two recipients with change was, and the proof shape now holds
  the real inputs and outputs plus the spend record, which follows the real
  outputs with compact padding after it that the transaction leaves out.

Dependencies

- `@hpke/core` ^1.9.0 (new).
- `@peculiar/asn1-schema` ^2.10.0 (new).
- `@peculiar/asn1-x509` ^2.10.0 (new).
- `@phala/dcap-qvl` ^0.6.5 (new).
- `cborg` ^6.1.3 (new).

## 0.3.1-alpha — 2026-09-29

Reading a ring transaction's instruction groups requires a version 1
transaction. The user-registry instructions are exported for callers who
compose their own transactions, and a registration that would change the
nullifier key fails before any transaction is built.

Breaking

- `confirmedInstructionGroups` rejects a transaction that loaded accounts from
  an address lookup table → pass a version 1 transaction, which lists every
  account in the message.

Added

- `getRegisterInstructionAsync` and `getSetMergingEnabledInstructionAsync`
  from `@heliuslabs/zolana/instructions` build the user-registry instructions
  for an Ed25519 owner and derive the owner's record, so one transaction can
  register a wallet and enable merging. `getUserRecordAddress` from
  `@heliuslabs/zolana/addresses` returns that record's address.

Fixed

- `buildRegistrationTransaction` built a key update the user-registry program
  rejects when the wallet's nullifier key differs from the published record,
  it now throws `WALLET_BUILD_REGISTRATION` with cause
  `WALLET_USER_RECORD_NULLIFIER_KEY_MISMATCH` before building anything → a
  wallet with a new nullifier key registers under a new owner address.

## 0.3.0-alpha — 2026-09-29

A ring gains a scoped co-signer, a permanent delegate that moves and
recovers member notes from escrowed nullifier keys, public spend windows,
private per-window velocity caps kept in compressed spend records, and
optional deposit audit. Ring list entries and spend records may live in any
tree, ring notes merge in one transaction, and ring submissions save each
signed attempt before broadcast and resolve it after a restart. Ring
instructions, proof requests and the policy hash change shape, so rings,
programs and prover keys of 0.2.0-alpha need their counterparts from this
release. A merge can write its output into a cache account, and a transfer can
spend it from there before the tree holds it.

Breaking

- `buildRegistrationTransaction` adds the `payer` account the user-registry
  program now requires for a first registration → rebuild any unsigned
  registration transaction an earlier release built, the program rejects it.
- `ringDepositInstruction` is no longer exported from
  `@heliuslabs/zolana/interface`, and it and `ringTransactInstruction` add the
  co-signer, spend window, deposit audit and key registry accounts, with
  `ringTransactInstruction` taking `approvalRequired` → import it from
  `@heliuslabs/zolana/ring` and rebuild ring transactions with this release.
- `RingPolicyConfig.entriesTree` and `entriesTreeId` are `addressTree` and
  `addressTreeId`, ring transact instructions and `ProvenRingTransfer` use
  `inputTrees` and a `RingTransactPolicy` in place of the input tree,
  `entriesTree`, `hasPolicy` and the root indexes, `ringTransactAccounts`
  takes `inputTrees` in place of `inputTree`, policy proof requests and
  `policyPublicInputHash` take `treeSlots` and `addressTreeId`, entry
  instructions take `inputTree` and `outputTree`, entry readers take a
  `resolveTreeId` such as `ringTreeIdResolver`, and
  `RING_ENTRIES_TREE_INVALID` is `RING_POLICY_TREE_INVALID` → rename the
  fields and pass the proven `inputTrees` and `policy` through.
- `buildRingDepositTransaction` takes a `RingDepositClient` with
  `proveCustomRingDeposit` and `getRingKeyRegistryEntry` and wraps each
  recipient ciphertext in an audit capsule → supply both methods and pass
  `customRingDepositPayload` as the wallet sync `depositPayloadDecoder`.
- `RING_POLICY_VERSION` is 7 (was 4), `RingPolicyConfig` and `RuleTable` carry
  `windowSlots` and `velocity`, `ringPolicyHash` covers both, and
  `buildRuleTable` refuses a window without rows → deploy a fresh policy ring
  and pass `windowSlots: 0n` and `velocity: []` for a table without amount
  controls.
- `customRingPublicInputHash` is renamed `policyPublicInputHash` and also
  takes the ring id, namespace owner, window and approval inputs,
  `AUDITOR_MESSAGE_LENGTH` grows, `CustomRingBasePublicInput`,
  `CustomRingBaseProofRequest` and `CustomRingPolicyProofRequest` require the
  transaction `salt` and output openings, and `encryptCustomRingTransfer`
  requires `outputTreeId` → call `policyPublicInputHash` for a policy ring and
  `auditPublicInputHash` for an audit-only ring, size parsers with the
  constant, pass the salt, openings and destination tree id, and run the
  prover and program of this release.
- `RingTransferClient` also needs `getSlot`, `getRingSpendRecord`,
  `getRingKeyRegistryEntry` and `proveCustomRingCompressedPolicy`,
  `ProvenRingTransfer` returns `approvalRequired`, `PolicyAnswers` requires
  `revocationTargets`, every `Prover` implements `proveCustomRingDeposit`,
  `proveRingAuthorityTransact`, `proveCustomRingDelegatePolicy`,
  `proveCustomRingCompressedPolicy` and `proveCustomRingRegisterKey`, and
  `proveRingTransact` takes a `RingProvingConfig` → implement each method,
  return the revoked hashes from a custom policy answer provider, put indexer
  settings under `indexer`, and pass `outputTree` when the destination differs
  from the client tree.
- `TransactionOrigin.ringInvoked` takes `eventIndex` between `signature` and
  `ring`, `SignatureType`, `ProverInputs["circuit"]`, `TransactionIntent`,
  `TransactionErrorCode` and `RingErrorCode` gain variants, and
  `RingErrorCode` drops `RING_ENTRIES_TREE_REQUIRED` → pass the indexed
  event's position and handle `"pda"`, `"transferRingAuthority"`,
  `"ringDelegate"`, `"ringMerge"` and the new codes in exhaustive switches.
- `serializeWallet` writes version 4 snapshots with `pendingSubmissions` and a
  nullable `SerializedNoteReservation.expiresAtMs` → upgrade snapshot readers
  before saving and treat `null` as no local expiry, versions 2 and 3 stay
  readable.
- Every `ProverClient` prove method rejects a proof from a prover that does not
  report its proving key with `CLIENT_PROVING_KEY_MISSING`, or reports another
  key than the SDK's verifying key pins with `CLIENT_PROVING_KEY_MISMATCH`, and
  refuses a shape without a verifying key with `CLIENT_PROVER_INPUT` before any
  request → prove against a prover from this release.
- `Prover` requires `checkProverProvingKeys` → implement it in a custom `Prover`.

- `getMergeTransactInstructionAsync` merges prove against the owner's
  registered nullifier key and end their data with an optional `cacheSlot`,
  every transfer public-input hash except the ring-authority one ends with the
  cache selection that `TransferInputs.cacheTreeId`, `cacheReadHashChain`,
  `cacheReadHashes`, `cacheIsCached` and `cacheReadIndex` carry, `CircuitId`
  gains `confidentialEddsaCached` and `ringEddsaCached`, and
  `ShieldedPoolError` adds the cache errors at 7066–7077 with 7072 unused →
  reprove pending merges and transfers with the program and prover of this
  release, set the five fields on a hand-built `TransferInputs`, and handle
  the new variants in exhaustive switches.
- `UtxoData`, `DepositEntry.utxoData` and `RingDepositEntry.dataHash` are
  removed, so a deposit output never carries application data → attach data
  to a UTXO through a proven transaction instead.

Added

- `buildRegistrationTransaction({ payer })` lets a sponsor fund the record's
  rent and pay the transaction fee; the owner still signs and may hold 0 SOL.
- `setRingCoSignerInstruction` and `clearRingCoSignerInstruction` set and close
  a ring's co-signer, a second Solana key that must sign the transfers,
  deposits or withdrawals in its scope, every ring builder takes `cosigner`
  and refuses a missing one with `RING_COSIGNER_REQUIRED` before proving, and
  `setRingSpendWindowInstruction` and `clearRingSpendWindowInstruction` cap a
  mint's public deposits and withdrawals per fixed window of slots, and
  `fetchRingSpendWindow` reads the cap.
- `setRingDelegateInstruction` names a policy ring's permanent delegate,
  `buildRingDelegateTransferTransaction` moves a member's ring notes with
  change back to the member, and `recoverRingMemberNotes` with
  `buildRingDelegateRecoveredTransaction` moves a member's unspent notes using
  the auditor's viewing key, without the member's wallet.
- A named delegate turns on key escrow, read from
  `RingProgramConfig.keyEscrow`, after which transfers, delegate moves and
  deposits refuse an output key not registered for its owner with
  `RING_UNREGISTERED_OUTPUT_KEY` before proving, only spend records owned by
  the ring's namespace keep the zero nullifier key, so a P-256 owner or a
  zero-key address cannot receive on such a ring, every deposit is audited,
  and `openRingEscrowedKeys` runs the same check for a custom builder.
- `buildRingSpendRegistrationTransaction` registers a sender's spend record on
  a windowed ring, `ZolanaClient.getRingSpendRecord` reads a member's current
  record and reports projection lag as `CLIENT_SPEND_RECORD_OUT_OF_SYNC`,
  `proveCustomRingTransfer` charges each transfer against the ring's
  private per-window velocity caps and refuses an overspend with
  `RING_VELOCITY_CAP_EXCEEDED`, `readRingVelocityState` reads the sender's
  counters, `auditRingTransaction` reports them as `AuditedRingSpendRecord`,
  and `PreparedTransfer.withInputTreeLast` orders a transfer's inputs so the
  spend record's tree runs last.
- `createRingKeyRegistryRootInstruction` creates a ring's member key
  registry, `buildRingKeyRegistrationTransaction` seals a member's nullifier
  key to the ring auditor for `fetchRingSealedKey` and `openRingSealedKey` to
  read back, and `registeredKeyHash`, `keyRegistryLeaf`,
  `keyRegistryRootFromProof` and `verifyKeyRegistryInsert` recompute registry
  leaves and roots for a custom prover.
- `initializeRingConfigInstructions` takes `depositAudit`,
  `setRingDepositAuditInstruction` toggles it, `buildRingDepositTransaction`
  then proves auditor-readable openings for up to eight deposits, and
  `GetByTagsRequest.ringProgramId` scopes a scan to one ring, deposits to
  unknown recipients included.
- `buildRingMergeTransaction` and `createRingMergeSubmission` consolidate up to
  eight ring notes of one owner and asset.
- `createRingTransferSubmission` and its exit, withdrawal, delegate and
  registration counterparts return a `RingTransactionSubmission` that retries
  a stale key registry root or window failure and keeps the spent notes
  reserved until the broadcast settles, `sendPersisted` saves each signed
  attempt before broadcast, `reconcileRingSubmissions` resolves saved
  signatures after a restart without paying twice, and `savePersistedWallet`
  saves wallet state on the sync queue.
- `ZolanaClient.checkProverProvingKeys` and `ProverClient.checkProvingKeys` check
  a prover's proving keys against the SDK's verifying keys before the first
  proof, return a `ProvingKeyReport` with one `ProvingKeyCheck` per key, and
  throw `CLIENT_PROVER_PROVING_KEYS_MISMATCH` naming every key whose digest
  differs.

- `createCacheInstruction` opens a cache account at
  `getCacheAddress(rentSponsor, nonce)` that `closeCacheInstruction` closes
  with its rent returned to the sponsor and `decodeCache` reads,
  `ZolanaClient.proveMerge` takes a `MergeCacheTarget` to write the merged
  output into a slot, `ProofInputUtxo.withCacheSlot`,
  `ProofOutputUtxo.withCacheSlot`, `SppProofInputs.withReadCache` and
  `withWriteCache` let `proveTransact` and `proveRingTransact` spend a cached
  output and write outputs to any slot, publishing `NO_UTXO_ROOT` for a tree
  read only from the cache, `transactInstruction` and `ringTransactAccounts`
  take the accounts as `TransactCacheAccounts`, `cachedInputFields`,
  `emptyCachedInputFields` and `bindCacheWrite` compute the same values for a
  custom prover, and a selection the program would reject fails before any
  request with an error naming the input or output index, while
  `ringTransactInstruction` refuses a cached circuit, which custom rings do not
  accept, with `RING_CACHE_UNSUPPORTED`.

Fixed

- `buildRingTransferTransaction` bound output commitments to the wrong tree on
  a client with a nonzero tree id, each output now commits to the selected
  destination tree.
- `deployRingProgram` could upgrade a ring to a program that cannot load its
  `RingPolicyConfig` or abort on a transient signature status failure, and
  `RingProgramBinary.bytes` handed out its internal buffer, the upgrade is now
  refused with `RING_POLICY_CONFIG_INCOMPATIBLE` before any transaction is
  sent, a transient failure retries the deploy step, and the accessors return
  copies.

## 0.2.0-alpha — 2026-09-21

Custom rings come in two tiers, an audit-only ring proves the auditor
encryption alone and a policy ring proves its rule table over a dedicated
entries tree, and a ring transfer can land its outputs in a tree other than
the one it spends from.
A tree derives from its id instead of one fixed address, holds its own fee
schedule, and takes four instructions in one transaction to create. Every
spent nullifier gets its own account, and the transact, merge, and ring
builders take one nullifier account per input. Registering a ring and admitting
it are now two separate steps with two different signers. The proof system changed underneath: owner identities carry a signing
algorithm tag, every UTXO commits to the tree it lives in, and one private
blinding seed per proof derives every output blinding and the private
transaction hash blinding. Every builder now returns a version 1 transaction,
which holds 4,096 bytes instead of 1,232, carries its compute budget and
priority fee in the message itself, and uses no address lookup tables. Wallet
builders can send value across multiple trees.

Breaking

- `SHIELDED_POOL_PROGRAM_ID` is `sppU489D7A4U1exNo1oeMGZtLEofq3a6o2fR7UeoWB6`, and
  `SOL_INTERFACE`, `SHIELDED_POOL_CPI_AUTHORITY` and every tree address derive
  from it, while `InstructionTag` renumbers every tag → point at a deployment of
  the matching program and re-read any address or tag byte you cached.
- `ShieldedPoolError` and `decodeShieldedPoolError` use consecutive codes
  7000–7065 matching the program, remove retired names, and include tree-context
  errors → replace hardcoded codes with the exported constants and use this SDK
  with the matching program version.
- `MAX_INPUT_TREES` limits each transact to two input trees → split inputs from
  three or more trees across separate transactions.
- `ringTransactAccounts` requires `treeContexts`, and both it and
  `transactInstruction` reject multiple contexts or nonzero input tree indexes
  with `INTERFACE_INVALID_SHAPE` → pass the instruction's contexts and keep
  these single-tree builders' inputs on `inputTree`.
- `transactInstruction` and `ringTransactAccounts` place input trees after
  `payer`, `output_tree`, SPP, System Program, and the optional ring config,
  immediately before nullifier PDAs → update manual account lists and CPI
  callers to the same order.
- Every builder returns a version 1 transaction and `TRANSACTION_SIZE_LIMIT` is
  4096 (was 1232) → send through an RPC and a validator that accept version 1,
  which Agave does from 4.2, and read transactions back with
  `maxSupportedTransactionVersion: 1`.
- `priorityFeeLamports` replaces `computeUnitPriceMicroLamports` on
  `ZolanaClientConfig`, `deployRingProgram`, and every ring builder, and it buys
  priority for the whole transaction → pass the total lamports to pay instead of
  a price per compute unit.
- `buildRingLookupTableTransaction`, `fetchRingLookupTable`,
  `ringLookupTableAddresses`, `RingLookupTable`, `RingLookupTableClient`,
  `RingLookupTableReader` and the `RING_BUILD_LOOKUP_TABLE`,
  `RING_LOOKUP_TABLE_INCOMPLETE`, `RING_LOOKUP_TABLE_NOT_FOUND` and
  `RING_LOOKUP_TABLE_NOT_READY` codes are removed, and `buildRingEntryTransaction`,
  `buildRingTransferTransaction`, `buildRingExitTransaction` and
  `buildRingWithdrawalTransaction` no longer take `lookupTable` → a version 1
  transaction reads no lookup table, so drop the table and the parameter.
- A transaction budgets zero compute units for what it does not name, so every
  builder names one and `ZolanaClientConfig.computeUnitLimit` defaults to
  450,000 (was 300,000) and is refused above 1,400,000 → lower it when you send
  only small shapes, because the requested units, not the consumed ones, price
  the priority fee.
- `ShieldedPublicKey.ownerProofInputHash()` hashes a signing algorithm tag
  ahead of the key, so every owner hash, compressed address, UTXO hash, and
  nullifier differs from earlier releases → state and addresses produced before
  this release no longer verify; derive addresses again and sync wallets from
  an empty state.
- `Utxo.hash`, `Utxo.proofInput`, `ProofOutputUtxo.hash`, and the object form of
  `ownerUtxoHash` take the raw id of the tree the UTXO lives in, and
  `ProofInputUtxo` carries `treeId` → pass `DEFAULT_TREE_ID` (0), the value
  every builder, wallet, and client path defaults to.
- `deriveBlinding` is removed; every transact output, padding included, is
  blinded with `transactOutputBlinding(firstNullifier, outputBlindingSeed(firstNullifier, blindingSeed), slot)`
  and the seed-disclosing bundles carry the derived output seed, so
  `anonymousSenderUtxos`, `plaintextTransferUtxos`, `splitBundleUtxos`, and
  their `*FromUtxos` counterparts take the transaction's first nullifier →
  read `nullifiers[0]` of the indexed transaction and pass it along.
- `privateTxHash` takes `blinding` and `addressNullifiers` (was
  `addressHashes`), `createEncryptedTransaction` takes `outputTreeId` and
  `privateTxBlinding`, and `SppProofInputs` requires `blindingSeed` and
  `outputTreeId` while exposing `firstNullifier`, `outputBlindingSeed`,
  `privateTxBlinding`, and `privateTxHash` → callers that hash a transaction
  themselves supply the blinding; `messageHash` is unchanged in meaning.
- `ConfidentialTransfer`, `ConfidentialSplit`, and `Merge` gain
  `withOutputTreeId`, `Merge` takes the output tree id as a third constructor
  argument, `PreparedTransfer`, `PreparedSplit`, and `PreparedMerge` expose
  `inputTreeIds` or `inputTreeId` beside `outputTreeId`, and `PreparedTransfer`
  and `PreparedSplit` expose the seed material the prover needs → a merge or
  split input set spanning two trees is refused with
  `TRANSACTION_INPUT_TREE_MISMATCH`.
- A padding output's published owner tag names a non-payer input owner or a
  real output's owner and is always inline, and a self-paid transfer with no
  change and no recipient keeps a real zero-amount SOL change output → expect
  `PreparedTransfer.outputs` to hold an owned zero-amount output in that case,
  and `TRANSACTION_NO_DUMMY_OWNER_TAG_PARTICIPANT` when a transfer would
  otherwise name nobody.
- `ZolanaClientConfig.treeId` selects the pool tree (default 0) and `tree`, when
  given, must derive from it; `ZolanaClient.treeId` is exposed, proving rejects
  proof inputs built for another tree with `CLIENT_TREE_ID_MISMATCH`, a merge
  is refused with the same code when its output tree is not its input tree,
  `AssembledTransfer.rootIndexes` reports the first input tree's root positions,
  and the prover request carries `treeSlots`, `outputTreeId`, and `blindingSeed`
  → run a prover from this release.
- `TransactInstructionData` carries one `TreeContext` per input tree in place of
  `utxoTreeRootIndex` and `nullifierTreeRootIndex`, every `InputUtxo` names its
  context with `treeIndex`, `SppProofInputs.inputTreeIds()` and
  `PreparedTransfer.inputTreeIds` list the up to two trees one spend may draw
  from, `inputTreeSlots` takes those trees as an array, and the transfer prover
  request replaces `allowDummyInputs` with `inputFlags`, the dummy-input policy
  in bit 0 and input `i`'s three-bit tree index at bits `1 + 3i` → order inputs
  so each tree owns one contiguous run, pass `treeContexts` in that order and
  `[slot]` to `inputTreeSlots`, and run a program and prover from this release;
  merge keeps its single input tree and its root position pair.
- `TREE_ACCOUNT_SIZE` is 40,080, so a tree account created by an earlier
  release is not read as a tree → create the pool tree with this release.
- `externalDataHash` takes the transact fields as the instruction encodes
  them (`ExternalDataHashInput` extends the new `TransactExternalData`), with
  `outputs` carrying their `OwnerTag`, one `resolvedOwnerTags` entry per
  output, and one `settlementAccounts` pair `{ asset, user }` per interface
  transfer (the new `SettlementAccounts` type), the `ResolvedInterfaceTransfer`
  and `ResolvedOutput` types are
  gone, and `transactInstruction` lays its data out as `expiryUnixTs`,
  `txViewingPk`, `salt`, `interfaceTransfers`, `dataHash`, `ringDataHash`,
  `outputs`, `messages`, then `privateTxHash`, `circuit`, `proof`, `inputs`,
  and an `spl` `SettlementTransfer` no longer carries `splTokenInterface`
  → pass `SOL_INTERFACE` and the user's SOL account for a SOL leg, the mint
  and the token account for an SPL leg, drop `splTokenInterface` from SPL
  legs, read transact payloads in the new order, and run a program and prover
  from this release.

- `@solana/kit` now requires ^8.3.0 → upgrade the peer dependency from 7.x.
- `extendProgramInstruction` uses the extension supported by Agave 4.2 → pass
  `payer` and remove the `authority` argument; upgrading still requires the
  upgrade authority.
- Policy rule tables now carry one `inlineLimit` per inline asset and policy
  prover requests carry the padded `inlineLimits` fields → recreate policy
  config accounts and include the limits in custom prover integrations.
- Custom-ring prover requests use the circuit types `custom-ring-base` and
  `custom-ring-policy` in place of the `audit` and `transfer` variants → rename
  request types and prover methods to their `Base` or `Policy` forms.
- `createRingConfigInstruction` takes `hasPolicy` and `RingProgramConfig`
  reports it → pass `true` for a ring that enforces compiled rules and `false`
  for an audit-only ring.
- `ringTransactInstruction` takes `stateRootIndex` and `nullifierRootIndex`,
  a policy ring also needs `entriesTree`, and `hasPolicy: false` drops the
  policy accounts → forward the fields of `ProvenRingTransfer`, a policy ring
  without its entries tree is refused with `RING_ENTRIES_TREE_REQUIRED`.
- `initSppRingConfigInstruction` takes `hasPolicy` and adds the policy config
  account for a policy ring → pass the value given to
  `createRingConfigInstruction`, a policy ring registers only after its policy
  config exists.
- `Prover.proveRingTransact` resolves to `ProvenRingTransact`, the instruction
  data beside the `RingTransactRoots` the ring statement binds, and `Prover`
  gains `proveCustomRingBase` and `proveTransferInputs` over caller-assembled
  `TransferInputs` → read `.data` where the instruction data was used and add
  both methods to a custom prover.
- `RingTransferClient` reads entries and their proofs through
  `getEncryptedUtxosByTags`, `getShieldedTransactionsByNullifiers`,
  `getMerkleProofs` and `getNonInclusionProofs` → add the four methods to a
  custom client.
- `customRingPublicInputHash` takes `policyHash`, `stateRoot`,
  `nullifierRoot` and `entriesTreeId` → use `auditPublicInputHash` for the
  audit statement alone.
- Ring registration is permissionless and produces a config that authorizes
  nothing, and governance admits it separately with
  `getSetRingActivationInstructionAsync` → a ring is live only after its
  activation transaction lands, and the payer of the registration no longer
  needs to be the pool's ring authority.
- `RingConfigAccount` and `RegisteredRing` gain `activated`, and
  `decodeRingConfig` reads a 69-byte account → a config account written before
  this release no longer decodes, and a caller choosing a deposit target should
  filter on `activated` as deliberately as on `paused`.
- `getUpdateRingConfigInstructionAsync` no longer carries
  `ringAuthorityTransactIsEnabled`, which only the pool's ring authority can
  set → move that flag to `getSetRingActivationInstructionAsync`, which also
  turns a ring on and off.
- `ProtocolConfigAccount.ringCreationIsPermissionless` and the
  `ProtocolConfigUpdate` field `ringCreationPermissionless` are
  `ringActivationIsPermissionless` and `ringActivationPermissionless` → rename,
  and read the flag as deciding whether a new ring is born activated rather
  than who may register one.

- State-tree root history retains one final root per updated slot in a dense
  500-entry cyclic buffer. Its cursor, length, and capacity are native `u16`s,
  and it stores the latest update slot as a `u64`, making pre-release
  30,344-byte tree accounts incompatible → deploy fresh 40,080-byte trees
  and reindex Photon as one coordinated upgrade.
- `DEFAULT_TREE_ADDRESS` is removed and a tree derives from its id → call
  `getTreeAddress(0)` for the default tree, which is not the address the
  removed constant held.
- `addressTreeParams` and `AddressTreeParams` are `nullifierTreeParams` and
  `NullifierTreeParams`, without the `rootHistoryCapacity` member → rename, and
  read `NULLIFIER_TREE_ROOT_HISTORY_CAPACITY` for the capacity.
- `ADDRESS_TREE_HEIGHT`, `ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE`,
  `ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE`, and
  `ADDRESS_TREE_ROOT_HISTORY_CAPACITY` are removed → read
  `NULLIFIER_TREE_HEIGHT`, `NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE`,
  `NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE`, and
  `NULLIFIER_TREE_ROOT_HISTORY_CAPACITY`.
- `foresterFeePerQueueElement(zkpBatchSize)` and
  `FORESTER_REIMBURSEMENT_LAMPORTS` are removed → `defaultTreeFees(zkpBatchSize)`
  returns the `TreeFeeSchedule` a tree is created with, and
  `DEFAULT_APPEND_REIMBURSEMENT_LAMPORTS` and
  `DEFAULT_CLOSE_REIMBURSEMENT_LAMPORTS` hold the per-batch reimbursements it
  covers.
- `getCreateTreeInstructionAsync` is `getCreateTreeInstructionsAsync`, takes a
  `payer`, a `treeId`, and an optional `fees` instead of a tree address, and
  returns the `TREE_CREATION_STEP_COUNT` identical instructions that allocate
  the account → send all of them in one transaction, and pass the protocol
  config's `nextTreeId` as the `treeId`.
- `transactInstruction`, `mergeTransactInstruction`, and `ringTransactAccounts`
  are async and include one writable nullifier account per spent input → await
  them, pass the spent `inputs` to `ringTransactAccounts`, and rename
  `getTransactInstruction` and `getMergeTransactInstruction` to
  `getTransactInstructionAsync` and `getMergeTransactInstructionAsync`.
- `getCreateProtocolConfigInstructionAsync` requires `feeAuthority` and
  `ProtocolConfigUpdate` gains a `feeAuthority` field → pass the address allowed
  to set tree fees and claim tree lamports, and update exhaustive matches.
- `decodeProtocolConfig` reads a 166-byte account and returns `feeAuthority` and
  `nextTreeId` → a config account written before this release no longer decodes.
- `DepositEntry` and `AssetDeposit` drop their `blinding` member and
  `getDepositInstructionAsync` no longer encodes it → stop passing a blinding,
  because the shielded pool now derives it from the tree and the leaf index the
  output lands at, and an entry that still encodes one no longer decodes.
- The `Deposit` a deposit builder returns drops its `utxoHash` member → read the
  deposited UTXO from the indexer after the deposit lands, since the blinding,
  and therefore the hash, depend on the leaf index assigned when the transaction
  executes.
- `TransactProof.b`, `CompressedProof.b`, and the merge instruction `proof.b`
  are the 128-byte uncompressed G2 point (was the 64-byte compressed encoding),
  so `encodeTransactInstructionData` and `encodeMergeTransactInstructionData`
  write 64 more bytes and a hand-built 64-byte `b` is refused → pass the
  `compressProof` result through unchanged, it now keeps the point the prover
  returned; `toCustomRingProof()` still compresses `b`.
- `TransferInputs.publicInputHash`, the public-input hash of a merge proof, and
  the `publicInputHash` of `ringEntryTransitionInputs` fold their nullifier
  list, output hash list, output owner list, and the public-input list itself
  three elements per Poseidon call (was one), and the signer slots of a shape
  are the payer plus one per input up to the transaction address budget
  (unchanged for every shape this package builds) → run a program and prover
  from this release, a proof or public-input hash produced by an earlier
  release no longer verifies.
- `InputUtxo` is only the `nullifierHash`, and `TransactInstructionData` and
  `MergeTransactInstructionData` carry one `utxoTreeRootIndex` and
  `nullifierTreeRootIndex` pair after the inputs (was one pair per input, and
  `utxoTreeRootIndexes` / `nullifierTreeRootIndexes` arrays on the merge data),
  so `encodeTransactInstructionData` writes 4 fewer bytes per input and
  `encodeMergeTransactInstructionData` 30 fewer → set the pair once on the
  instruction data; the `MergeAssembly` exposes the same two scalars.
- `privateTxHash`, `SppProofInputs.privateTxHash()`, and the private
  transaction hash of a merge proof fold their input list, output list, and
  address nullifier list three elements per Poseidon call (was one) → prove
  with this release's prover, a private transaction hash or ring proof request
  produced by an earlier release no longer matches its proof.

Added

- `Bytes128` is exported as the type of the `b` proof point.

- `proveCustomRingTransfer` proves the tier the ring config selects and, for
  a policy ring, the rule table over the list entries the rules name, and
  `ProvenRingTransfer` reports `hasPolicy`, `outputTree`, `stateRootIndex`,
  and `nullifierRootIndex`, with `entriesTree` when `hasPolicy` is true. A
  transfer no entry admits is refused with `RING_POLICY_RULE_UNSATISFIED`, a
  shape the policy cannot answer with `RING_POLICY_SHAPE_UNSUPPORTED`, an
  unknown inline asset with `RING_POLICY_ASSET_UNSUPPORTED` and an
  incomplete proof set with `RING_ENTRY_PROOF_INCOMPLETE`, all before any
  prover call.
- `buildRingTransferTransaction`, `buildRingEntryTransaction`,
  `buildRingExitTransaction`, and `buildRingWithdrawalTransaction` accept
  `outputTree` for the outputs. A policy ring binds the roots of its entries
  tree, proofs read under two roots are refused with
  `RING_POLICY_ROOT_MISMATCH` and an unreadable tree with
  `RING_ENTRIES_TREE_INVALID`.
- `provePolicyAnswers` resolves the list entries a policy ring's rules name
  into the answers and roots a ring transfer proves, and
  `readRingEntryLineages` reads the live version of many entries in one walk.
- `fetchRingPolicyConfig` and `decodeRingPolicyConfig` read a policy ring's
  `RingPolicyConfig` with its rule table hash, entries tree and its
  `entriesTreeId`,
  `RingPolicySource` list, rule rows and inline assets with their counts, and
  `generation` with its `generationSlot`, `ringPolicyConfigAddress` and
  `ringPolicyNamespaceAddress` derive its two accounts, and a missing or
  malformed account is `RING_POLICY_CONFIG_NOT_FOUND` or
  `RING_POLICY_CONFIG_INVALID`.
- `ZolanaClient.proveCustomRingBase` proves the audit statement from a
  `CustomRingBaseProofRequest`.
- `setRingPausedInstruction` pauses or resumes a ring under its own authority,
  the shielded pool refuses the ring's transactions while it is paused, and
  `RING_SET_PAUSED_COMPUTE_UNIT_LIMIT` is its compute budget.
- `ringOpenings` derives the `RingOpenings` a `CustomRingPolicyProofRequest` carries
  from `SppProofInputs`, `ringNamespaceOwnerHash` derives the owner hash of a
  list namespace, and `disabledRuleAnswer` fills an unused rule slot.
- `decodeRuleTable` and `decodeRule` read the rule rows of a
  `RingPolicyConfig` as `Rule` values with their `ListId` lists, and a row or
  table the circuit cannot enforce is `RING_RULE_TABLE_INVALID` with the Rust
  reason, `referencedLists` names the lists a table consults, and
  `fetchRingConfigs` reads a ring's config with its policy config when the
  ring has one.
- `buildRuleTable`, `encodeRule` and `encodeRuleTable` compile a `RuleTable`
  and encode its rows, `ruleAlternatives` orders the lists a rule consults,
  `listWriter` names who writes a list, `encodeListEntry` writes an
  entry's published bytes, and a list id outside `LIST_IDS` is refused with
  `RING_RULE_TABLE_INVALID` in a rule, a list write, an entry seed and a
  source change.
- `ringPolicyHash` computes the hash a policy config pins from a `RuleTable`,
  its source owners (`policySourceOwners`) and `RING_POLICY_VERSION`,
  `verifiedRuleTable` returns the stored table only when it reproduces that
  hash, else `RING_POLICY_HASH_MISMATCH`, and a referenced list without a
  source is `RING_POLICY_SOURCE_INVALID`.
- `buildRingCreatePolicyTransaction`, `buildRingSetPolicyRulesTransaction`
  and `buildRingSetPolicySourceTransaction` pin, replace and re-source a
  ring's rule table, `createRingPolicyInstruction`,
  `setRingPolicyRulesInstruction` and `setRingPolicySourceInstruction` build
  the instructions with `RingSharedSource` curators, the create and rules
  builders refuse an audit-only ring with `RING_POLICY_TIER_MISMATCH`, and a
  curator on another entries tree, without the list, or named twice for one
  list is refused with `RING_POLICY_SOURCE_INVALID` before the transaction is
  compiled.
- `deployRingProgram` deploys or upgrades a ring program with the given
  signers, resumes an interrupted upload from its buffer, reads the chain
  before it repeats a step whose confirmation was lost, reports a binary
  already on chain as `present`, names the buffer a failed deploy leaves in
  the `RING_DEPLOY_PROGRAM` details, and refuses a foreign or renounced
  upgrade authority with `RING_PROGRAM_AUTHORITY_MISMATCH` or
  `RING_PROGRAM_IMMUTABLE`, an address another program owns with
  `RING_PROGRAM_ADDRESS_OCCUPIED`, a short payer with
  `RING_PROGRAM_UNDERFUNDED`, a wrong program keypair on a first deploy with
  `RING_PROGRAM_KEYPAIR_INVALID`, a foreign or corrupt buffer with
  `RING_PROGRAM_BUFFER_INVALID`, a `concurrency` or `attempts` that is not a
  positive integer with `RING_DEPLOY_OPTIONS_INVALID`, and a program that
  stays unusable with `RING_PROGRAM_NOT_USABLE`.
- `RingProgramBinary.parse` checks and hashes a program binary and refuses
  one without an ELF header with `RING_PROGRAM_BINARY_INVALID`,
  `fetchRingProgramData` reads a deployed program's upgrade authority,
  capacity and deploy slot as `RingProgramData`, `verifyRingProgram` refuses
  a missing or different deployed binary with `RING_PROGRAM_NOT_DEPLOYED` or
  `RING_PROGRAM_MISMATCH`, `setUpgradeAuthorityInstruction` hands the program
  over or renounces it, and `closeBufferInstruction` reclaims a buffer's
  rent.
- `buildRingListWriteTransaction` adds or clears one list entry as a
  `RingListWrite`, or reports an entry already in that state, and refuses a
  curator-served list with `RING_LIST_SHARED` and a payer the list does not
  admit with `RING_LIST_WRITER_UNAUTHORIZED`.
- `proveRingEntryTransition` and `ringEntryTransitionInputs` prove one entry
  transition from a `ListEntryDraft` and return the `ListEntry` with the
  blinding the pool derives for it as a `RingEntryTransition`,
  `createRingEntryInstruction` and `updateRingEntryInstruction` build its
  instruction, and an unreadable entries tree or proof is
  `RING_ENTRIES_TREE_INVALID` or `RING_ENTRY_PROOF_INCOMPLETE`.
- `readRingEntry` and `readRingEntries` walk a namespace's entry lineages
  through the indexer and return each live `ListEntry` with the transaction
  that wrote it, `decodeListEntry` reads a published entry with its
  `blinding`, `memberOfTag`, `memberOfIdentity` and `memberOfAsset` derive a
  `Member`, `RingListNamespace` derives entry addresses and hashes under the
  entries tree id, and a lineage whose spender carries no next version is
  `RING_ENTRY_LINEAGE_BROKEN`.
- `getSetRingActivationInstructionAsync` admits a ring, contains one it no
  longer trusts, and owns its authority-transact rail. The pool's ring authority
  signs it directly, so no governance signature reaches the ring program.
- `ShieldedPoolError` names errors for deposit and SPL interface
  validation, the nullifier account lifecycle (`NullifierAlreadyQueued`,
  `InsufficientNullifierPdaRent`, `NullifierPdaNotClosable`,
  `InvalidNullifierPda`), tree ids and fees (`InvalidTreeId`, `TreeIdOverflow`,
  `InvalidReimbursementRecipient`, `NoClaimableTreeLamports`,
  `RingNotActivated`), and six
  `NonCanonical*` codes the program returns before touching any account when an
  instruction-data hash is not a canonical BN254 field element.
- `InstructionTag.setRingActivation` (21).
- `InstructionTag.closeNullifierPdas` (18), `InstructionTag.setTreeFees` (19),
  and `InstructionTag.claimTreeLamports` (20): the forester closes spent
  nullifier accounts, and the fee authority writes a tree's fee schedule and
  moves the tree's lamports above its rent, fee balance, and nullifier working
  capital to a recipient.
- `getTreeAddress(treeId)` derives a tree, and
  `getNullifierPdaAddress(tree, nullifier)` derives the account the pool creates
  for a spent nullifier.
- `nullifierPdaAccounts(inputTree, nullifiers)`, exported as
  `getNullifierPdaAccountsAsync`, returns the writable nullifier accounts a
  transact instruction takes, one per input in the same order.
- `getSetTreeFeesInstructionAsync({ authority, tree, fees })` writes a tree's
  `TreeFeeSchedule`, signed by the fee authority.
- `decodeTreeFees(account)` reads a tree's `TreeFees`, its schedule and its
  accrued balance. `encodeTreeFeeSchedule` and `decodeTreeFeeSchedule` convert
  the schedule alone, `TREE_FEES_OFFSET` and `TREE_FEE_BALANCE_OFFSET` locate
  both in the account, `decodeTreeHeadRoots(account)` reads the tree's
  `TreeHeadRoots` with their history indices and refuses malformed histories or
  zero roots, the `UTXO_ROOT_HISTORY_*` and `NULLIFIER_ROOT_HISTORY_*` constants
  locate both histories, `UTXO_SUBTREES_LEN_OFFSET` locates the stored tree
  height, and `CreateTreeData` names the create-tree payload.
- `depositBlinding(tree, leafIndex)` recomputes the blinding the shielded pool
  derives for a deposit output, so a caller that does not want to trust an
  indexer can verify a deposited UTXO against the tree and leaf index alone.
  Reading the indexed UTXO remains the normal way to spend a deposit.
- `solanaOwnerIdentity`, `p256OwnerIdentity`, `outputBlindingSeed`,
  `transactOutputBlinding`, `privateTxBlinding`, `mergePrivateTxBlinding`,
  `treeIdField`, `treeSlotHash`, `treeSlotsHashChain`, `inputTreeSlots`,
  `INPUT_TREES`, and `DEFAULT_TREE_ID` expose the proof derivations a reader or
  an integrating program recomputes.
- `ClientError` adds `CLIENT_INPUT_TREE_ROOT_MISMATCH`,
  `CLIENT_NULLIFIER_ROOT_MISMATCH`, `CLIENT_OUTPUT_BLINDING_MISMATCH`, and
  `CLIENT_TREE_ID_MISMATCH`; `TransactionError` adds
  `TRANSACTION_INPUT_TREE_MISMATCH`, `TRANSACTION_INVALID_TREE_ID`, and
  `TRANSACTION_NO_DUMMY_OWNER_TAG_PARTICIPANT`, all raised before a proof
  request leaves the client.

Changed

- `NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE` is 25,000, so
  `NULLIFIER_TREE_ROOT_HISTORY_CAPACITY` is 100. The state tree retains one
  final root for each of the latest 500 slots that updated it, exported as
  `STATE_ROOT_HISTORY_CAPACITY`. A root cannot be overwritten until 500 later
  slots update the tree: about 100 seconds at the 200 ms target slot time, and
  longer when slots contain no update. `TREE_ACCOUNT_SIZE` is 39,952,
  `TREE_CREATION_STEP_COUNT` is 4 at a `TREE_ALLOCATION_STEP` of 10,240 bytes,
  `STATE_ROOT_OFFSET` is 80, and `PROTOCOL_CONFIG_SIZE` is 166.
- A built transaction carries its compute unit limit, a 64 MiB loaded accounts
  data size limit and its priority fee in the message header, so it holds no
  compute budget instruction and its instruction list is the setup and payload
  instructions alone.
- A relayed ring exit, which pays its fee from one account and carries the UTXO
  owner as a second signer, fits the transaction it did not fit before.
- `RingTransferClient` no longer requires `solanaRpc` and `commitment`, the ring
  transfer builders read what they need through the ports they already took.
- `DEFAULT_APPEND_REIMBURSEMENT_LAMPORTS` and
  `DEFAULT_CLOSE_REIMBURSEMENT_LAMPORTS` are 0, so `defaultTreeFees` returns an
  all-zero schedule at every batch size and a transact pays no per-nullifier fee
  into the tree it spends from.

Fixed

- `ZolanaClient` accepts Photon tree metadata while rejecting invalid tree IDs and tree addresses that disagree with them.

- `decryptTransactions` rejects malformed key-holder batches with
  `TRANSACTION_KEYS_BATCH_MISMATCH`, destroys returned transaction keys, and
  leaves wallet state unchanged on failure.
- `buildMergeTransaction` rejects malformed derivation batches with
  `code: "WALLET_BUILD_MERGE"` and `causeCode: "WALLET_KEYS_BATCH_MISMATCH"`,
  releasing the inputs it reserved.
- `PreparedMerge.dummyNullifiers()` returns independent buffers so modifying
  a returned value cannot change the prepared merge.
- `LocalKeys.proveMerge` rejects incomplete inputs for another wallet with
  `CLIENT_MERGE_NULLIFIER_KEY_MISMATCH` before contacting the prover.
- Wallet transaction builders reject entries outside the default tree instead
  of pairing their stored nullifiers with default-tree commitments, and
  `ProofInputUtxo.withTreeId` reports `TRANSACTION_INPUT_TREE_MISMATCH` for real inputs.
- `deployRingProgram` splits uploads into writes the loader accepts and packs
  them into v1 transactions; `writeBufferInstruction` rejects payloads above
  1,216 bytes with `RING_PROGRAM_WRITE_TOO_LARGE`.
- `decodeRingPolicyConfig` returns the stored per-asset limits without reversing their bytes.
- A deposit could be given a blinding that already belonged to another deposit,
  which produced a duplicate UTXO hash and nullifier and left the second UTXO
  unspendable; the shielded pool now derives every deposit blinding from the
  tree and the leaf index, so each deposit is unique.

Dependencies

- `@solana-program/address-lookup-table` removed (was ^0.13.0).
- `@solana-program/compute-budget` removed (was ^0.17.0).
- `@solana-program/token` ^0.16.1 (was ^0.15.0).
- `@solana-program/system` ^0.14.1 (new).

## 0.1.6-alpha — 2026-09-03

The wallet authority is replaced by a key interface a remote holder can
answer: `WalletKeys` exposes the derivations a wallet needs and proving,
never a long-lived secret, and every build and sync takes it. Proof inputs
carry the nullifier instead of the nullifier key, so a transaction is
prepared and encrypted without the spending secret in the process. Wallet
replay keeps merge outputs when their inputs arrive in the same sync.

Breaking

- `WalletAuthority`, `KeypairWalletAuthority`, `ClientEd25519WalletAuthority`,
  `SpendAuthority`, `SpendSession`, `SyncAuthority`, `SyncWalletAuthority`, and
  `WalletSyncMaterial` are removed → build
  `LocalKeys.fromKeypair(keypair, client.proofService)`, or from a browser
  wallet's signature
  `LocalKeys.fromDerivationSeed({ solanaPublicKey, derivationSeed }, client.proofService)`,
  and pass it as `keys`.
- `buildTransferTransaction`, `buildWithdrawalTransaction`,
  `buildSplitTransaction`, `buildMergeTransaction`, `buildRingEntryTransaction`,
  `buildRingTransferTransaction`, `buildRingExitTransaction`, and
  `buildRingWithdrawalTransaction` take `keys: WalletKeys` and an optional
  `approve: ApprovalHandler` instead of `authority` → pass the keys, and move
  a `requestUserApproval` implementation into `approve`, which receives the
  same `ApprovalRequest` and returns `approveIntent(request.intent)`; builds
  without `approve` are approved unattended, and a P256 owner's
  `solanaPublicKey` and registry record are the fee payer's.
- `syncWallet`, `syncPersistedWallet`, and `decryptTransactions` take
  `keys: ShieldedKeys` instead of `authority` → pass `LocalKeys` or
  `LocalShieldedKeys.fromKeypair(keypair)`; keys for another wallet fail with
  `TRANSACTION_KEYS_IDENTITY_MISMATCH` before any indexer query.
- `ProofInputUtxo` carries `nullifierPublicKey` and the derived nullifier
  instead of a `NullifierKey`, its constructor takes
  `{ utxo, nullifierPublicKey, nullifier, dataHash?, ringDataHash? }`, and
  `destroy()` is removed → build inputs with
  `ProofInputUtxo.fromKeypair(utxo, keypair, hashes?)` or the new
  `ProofInputUtxo.fromNullifierKey(utxo, key, hashes?)`; wallet entries
  already hold their nullifier.
- `ZolanaClient.proveTransact(proofInputs, keys, config?)`,
  `proveRingTransact(proofInputs, ringProgramId, keys, config?)`,
  `proveMerge({ prepared, keys })`, and
  `assembleAuthorizedPrivateTransaction({ authorized, feePayer, keys })`
  require a `ProofAuthority`, and `MergeMaterialInput` is removed with its
  `CLIENT_INVALID_MERGE_MATERIAL` code → pass the same `keys` object; a value
  that cannot prove fails with `CLIENT_INVALID_PROOF_AUTHORITY`.
- `proveCustomRingTransfer` takes `keys: WalletKeys` instead of `session` →
  pass the keys.
- `ProverInputs` input slots and `MergeInputs` carry the nullifier secret only
  once a `ProofAuthority` fills it in → a prover call whose own real input still
  lacks it fails with `CLIENT_MISSING_NULLIFIER_SECRET`.
- `TRANSACTION_WALLET_AUTHORITY_MISMATCH` is renamed
  `TRANSACTION_KEYS_IDENTITY_MISMATCH`, what the check compares → match the new
  code.

Added

- `ShieldedKeys` (`address`, `viewingPublicKeys`, `decrypt`, `derive`,
  `transactionKeys`) and `ProofAuthority` (`prove`, `proveMerge`) describe a
  wallet's privacy roles as batched functions, `WalletKeys` is both, and a
  remote key holder implements them to drive every build and sync; every
  method receives the `RequestContext` the sync or build was called with, so
  the holder's round trip stops when the caller's signal fires.
- `LocalKeys` and `LocalShieldedKeys` answer those interfaces from keys held
  in-process, with `fromKeypair`,
  `fromKeys({ address, viewingKeys, nullifierKey })` for a wallet holding
  retired viewing keys, and `fromDerivationSeed`, which verifies the seed is
  the wallet's signature and fails otherwise with
  `TRANSACTION_INVALID_DERIVATION_SEED`.
- `ZolanaClient.proofService` is the prover behind the client, what
  `LocalKeys` forwards completed proof inputs to.
- `encryptConfidentialTransfer`, `encryptCustomRingTransfer`,
  `encryptAnonymousTransfer`, and `encryptSplit` seal a prepared transaction
  under the per-transaction key `ShieldedKeys.transactionKeys` returns.
- `approveUnattended` is the default `ApprovalHandler`, and `checkKeysIdentity`
  refuses keys that do not describe a wallet's address.
- `proverRequestBody(inputs)` and `mergeProverRequestBody(inputs)` return the
  prover's request body with `null` in every nullifier secret slot a key
  holder has yet to fill, for a remote `ProofAuthority` to send it.
- `DecryptRequest`, `DeriveRequest`, `TransactionKeyRequest`, `DecryptLabel`,
  `ProofService`, `ProverInputs`, `MergeInputs`, `TransferInputs`,
  `TransferInput`, `TransferOutput`, `CircuitUtxo`, `Field`, and
  `ProverRequestBody` are exported for key holder implementations.
- `ViewingKey.clone()` and `NullifierKey.clone()` return an independent copy of
  a key, so a holder can lend one without exposing the secret bytes.
- `keyedWalletSnapshotCipher(identity, key)` seals wallet snapshots in the
  `walletSnapshotCipher` envelope under an AES-GCM key the caller supplies,
  and `walletSnapshotKey(secret)` derives that key from 32 bytes a key holder
  handed out, for a wallet whose viewing secret never enters the process.

Changed

- `CLIENT_PROVER_HTTP` carries the prover's own error code and message in
  `details.reason` when the prover sent them, so a refused proof says whether
  the circuit is unknown, a field is malformed, or a key is missing.
- A sync asks the key holder for every ciphertext, nullifier, and
  per-transaction key it needs in one batch per method and per dependency
  round, as many rounds as the merges in the batch chain, and a sync or merge
  fails with `TRANSACTION_KEYS_BATCH_MISMATCH`, `WALLET_KEYS_BATCH_MISMATCH`,
  or `TRANSACTION_KEYS_UNRESOLVED` when a holder does not answer in full.
- `buildRingEntryTransaction`, `buildRingTransferTransaction`, and
  `buildRingExitTransaction` use UTXO terminology in approval summaries, while
  version 3 `SerializedWalletState` reservation field names remain unchanged.

Fixed

- `decryptTransactions` no longer omits a merge when its inputs arrive in the
  same sync because merge dependencies resolve before wallet commit.
- `walletSnapshotCipher` and `keyedWalletSnapshotCipher` seal snapshots of any
  size in a browser: the ciphertext is base64-encoded in chunks instead of
  spreading every byte into one `String.fromCharCode` call, which overflowed
  the stack past roughly a hundred kilobytes and surfaced as `WALLET_SNAPSHOT`
  with a `RangeError` cause.
- A private-transaction row is identified by its transaction, slot and index.
  Re-recording it, as a sync does when a transaction it saw earlier is decoded
  again with the wallet's change now known, replaces the row; before, a row
  whose amount, kind or counterparty differed was kept beside the stale one and
  `privateTransactions()` listed the same transfer twice.

## 0.1.5-alpha — 2026-09-01

Wallet sync is atomic, and serialized wallets carry the cursors needed to
resume after a restart. Keys granted by a wallet authority live only
inside scoped sessions that wipe them when the callback settles. Ring
entry is explicit, and asset amounts have one metadata and conversion API.

Breaking

- `WalletAuthority` grants keys only inside scoped sessions,
  `withSpendSession` replaces `spendNullifierKey()` and the four
  `encrypt*` methods, `withSyncSession` replaces `syncMaterial()` and
  `viewingKeys()`, and the lent keys are wiped when the callback settles →
  wrap existing key use in the matching session callback, the session
  object passes to `decryptTransactions` unchanged.
- `proveCustomRingTransfer` takes the encryption capability of an open
  spend session instead of a whole authority → call it inside
  `withSpendSession` and pass the session.
- `serializeWallet` writes `SerializedWalletState` version 3 with sync
  cursors → state saved by version 2 still loads, and its first sync
  rescans history once.
- Private transfers and withdrawals spend the largest notes first and at
  most five notes → a balance that covers only with more notes is
  refused with `WALLET_TOO_MANY_INPUTS`, merge first.
- A wrapped wallet or ring error surfaces the outer operation code instead
  of the inner code → match on `causeCode` for the inner reason, selection
  and balance codes included.
- A build reserves its selected notes for two minutes, concurrent builds
  on one wallet cannot spend the same note → rebuild an unsent transaction
  after the reservation expires, a failed build releases its notes at
  once, and `WALLET_NOTE_RESERVED` refuses a named input another build
  holds.
- `HasherWasmError` is removed, hashing failures surface through
  `KeypairError`, `ClientError`, and the transaction codes → stop matching
  on the class, `createZolanaClient` and every async build, sync, and
  decrypt entry load the hasher themselves, an explicit
  `initializePoseidon()` stays necessary only before synchronous hashing
  such as key derivation.
- `RingRpc` exposes its transport configuration through `RingRpcOptions` and
  throws `RING_RPC_CONFIG` for an endpoint with plain HTTP,
  credentials, or a fragment unless `allowInsecureHttp` admits HTTP,
  accepts only responses declaring a JSON content type, caps them at 4
  MiB, times out after 30 seconds, does not follow redirects, and
  reports a server error without its
  text → pass `allowInsecureHttp: true` for localnet URLs, set
  `content-type: application/json` on mocked responses, and match on
  `rpcCode` in the details.
- `requestUserApproval` receives a `TransactionIntent` beside the summary
  and returns an `IntentApproval` bound to its hash → a custom authority
  returns `approveIntent(request.intent)` after showing the intent, and
  an approval for a different intent fails the build with
  `WALLET_INTENT_MISMATCH` or `RING_INTENT_MISMATCH`.

Added

- `buildRingEntryTransaction(params)` moves an exact amount from default
  notes into the caller's custom ring, leaves excess input value in the
  default pool, and records the boundary move as a `ringEntry` self transfer.
- `fetchAssetMetadata`, `AssetMetadataCache`, `formatAmount`, and
  `parseAmount` provide mint decimals and exact raw unit conversion for SOL,
  SPL Token, and Token-2022 assets.
- `SpendAuthority`, `SyncAuthority`, and `SpendSession` are exported,
  `syncWallet` accepts any `SyncAuthority`, one method instead of ten for
  a custom scan-only authority.
- `deserializeWallet` restores sync cursors, a restarted wallet resumes
  `syncWallet` where it stopped instead of replaying the full history.
- `syncPersistedWallet` syncs and saves the wallet snapshot to a
  `WalletStateStore` in one call, saves only after a successful sync and
  inside the wallet's sync queue so overlapping calls cannot store a stale
  snapshot, and reports a failed save as `WALLET_PERSIST` while the previous
  stored snapshot stays valid.
- `syncPersistedWallet` requires a `WalletStateCipher` and stores only sealed
  snapshots → seal with the shipped `walletSnapshotCipher(keypair)` and
  restore through `loadPersistedWallet`, a tampered snapshot or one sealed
  for another wallet is refused with `WALLET_SNAPSHOT`.
- `AuthorizedPrivateTransaction` is an opaque capability minted only after
  approval. It carries the proof material and SDK-generated setup instructions
  outside the public object shape. The client rebinds every output, settlement,
  and withdrawal account to the approved intent before proving. A counterfeit,
  drifted authorization, extra intent field, or caller-supplied setup
  instruction fails before compilation.
- `fetchSplAssetRegistrations` and `backfillAssetRegistry` fail on an
  unsupported or partial program scan instead of returning an empty registry,
  an empty result now means the pool has no SPL registrations.
- `RingRpc.readSigned` and `RingRpc.createAuditorKeySigned` normalize an exact
  copy of every signed request before network access. Malformed reader keys
  stay in the ring error taxonomy, and a timestamp past the safe integer range
  is refused instead of losing precision.
- `WalletStateStore.save` must replace the stored snapshot atomically or
  leave it unchanged, the retry after a failed save depends on it.
- `SyncWalletInput` names the `syncWallet` argument shape, and
  `SyncPersistedWalletResult` carries the sync report beside the saved
  snapshot.
- `RingTransferTransactionParams.computeUnitPriceMicroLamports` and
  `RingWithdrawalTransactionParams.computeUnitPriceMicroLamports` set a
  priority fee on ring transactions.
- `MERGE_TRANSACT_COMPUTE_UNIT_LIMIT` is exported, and merge transactions
  honor the client's `computeUnitPriceMicroLamports`.
- `RING_SELECTED_BALANCE_OVERFLOW` refuses a ring selection whose eligible
  balance passes the u64 ceiling.
- `ErrorEnvelope` names the `toJSON` shape of `WalletError`, `RingError`,
  `InterfaceError`, and `KeypairError`, and `causeCodes` lists the wrapped
  operation chain outermost first.
- `SerializedCursor`, `SerializedSyncCursors`, and `SerializedNoteReservation`
  expose resume points and active note holds in `SerializedWalletState`, a
  restored wallet resumes scans and blocks spending reserved notes.
- `ChainReader`, `BlockhashProvider`, `IndexerReader`, `ProofReader`,
  `Prover`, `TransactionConfirmer`, and `KitRpcAccess` name the client's
  capabilities, `ZolanaClient` implements them all, and a consumer can
  depend on only the one it uses.
- `SyncClient` is exported, `syncWallet` needs only the three indexer
  reads and kit access only for a wallet holding a mint the registry
  cannot resolve.
- `TransactionAssembler`, `MergeAssembler`, and `TreeContext` name the
  client's assembly capabilities, `DepositClient`, `MergeClient`,
  `PrivateTransactionClient`, `RingTransferClient`, `RingLookupTableClient`,
  `RingLookupTableReader`, and `RingAuditReader` name the accepted capability
  sets, and any object with those members serves in place of `ZolanaClient`.
- `AuthorizedPrivateTransaction`, `assembleAuthorizedPrivateTransaction`,
  and `assembleAuthorizedMergeTransaction` are part of the published
  types, and the emitted declarations compile under
  `skipLibCheck: false`.
- Every `RingRpc` method accepts a `RequestContext`, its signal and
  timeout reach the transport, and integers above the safe range decode
  exactly.
- `TransactionIntent` binds recipient, amount, asset, and the ring
  boundary crossing, the SDK revalidates outputs and settlements against
  the approved intent before a transaction compiles, and the client
  refuses proven data that drifts from it with `CLIENT_INTENT_MISMATCH`.

Changed

- Two `syncWallet` calls on one `Wallet` run one after the other, and a
  sync overtaken by another writer fails with
  `TRANSACTION_WALLET_STATE_STALE` instead of overwriting the newer state.
- `syncWallet` derives its key material once per run instead of up to five
  times.
- Every builder compiles through one shared path with the packet-size
  check built in, a compile failure in any build surfaces
  `CLIENT_TRANSACTION_ASSEMBLY`.
- Every rail selects notes through one selector with the rail's own
  ordering and caps, and `WALLET_INSUFFICIENT_BALANCE` reports the full
  spendable balance instead of a partial running sum.
- `WalletError`, `RingError`, and `InterfaceError` strip secret-named keys
  and non-primitive values from details and keep their cause out of
  serialization.

Fixed

- A sync holding an asset the registry could not resolve still committed
  its cursors and skipped the unstored note for good, it now fails with
  `WALLET_UNRESOLVED_ASSET` and the next sync re-reads the same pages.
- `RingRpc` returned unchecked response strings as typed addresses and
  signatures, every such field is now validated and a malformed one is
  refused with `RING_RPC`.
- A sync that failed partway had advanced its resume cursors past rows it
  never stored, losing those notes for good, rows and cursors now commit
  together and a failed sync leaves the wallet untouched.
- A private transfer, withdrawal, or split kept its spend key and every
  per-input key copy in memory after building, all of them are wiped once
  the transaction is assembled or the build fails.
- Every encryption minted a per-transaction viewing key and kept it in
  memory, each rail wipes it once the envelope is built, in both shipped
  authorities and in the keypair `sign()` paths.
- Outbound history decryption minted per-transaction viewing keys and
  kept them, each is wiped before the next transaction is read.
- `buildMergeTransaction` kept the sync material it minted and every
  per-input key copy in memory after building, all of them are wiped once
  the transaction is assembled or the build fails.
- `decryptToBalances` minted a viewing and a nullifier key and kept both in
  memory, they are wiped before it returns.
- `KeypairWalletAuthority.fromDerivationSeed` left the secrets derived
  from the seed unwiped after building its keys, they are wiped before it
  returns.
- `buildRingWithdrawalTransaction` omitted the recipient ATA creation that
  plain withdrawals include, SPL withdrawals now create a missing ATA in
  the same transaction.

## 0.1.4-alpha — 2026-08-29

Value moves both ways between the default pool and a custom ring, pool
notes fund the way in and an exit builder brings holdings back out.
Balances split between pool and ring holdings, rings pay out SPL tokens,
and the proof carries a signer slot for every note owner. The builders
refuse what cannot land, zero amounts and relayed transactions over the
packet size.

Breaking

- `Wallet.balances()` and `Wallet.balance(mint)` no longer count notes
  locked to a custom ring → call `Wallet.ringBalances()` for ring holdings.

Added

- `buildRingExitTransaction(params)` moves value out of a custom ring back
  into the default pool, and spends only ring notes so every exit it builds
  is a real exit.
- `RingTransferTransactionParams.inputs` picks the notes that fund a ring
  transfer, `"default"` funds it from pool notes alone (the way into a
  ring), `"ring-or-default"` mixes both.
- `proveCustomRingTransfer` refuses a tree other than the client's with the
  `RING_TREE_MISMATCH` error instead of building a proof that cannot
  verify.
- `ProofInputUtxo.destroy()` wipes the input's secret key copy, and the
  ring builders wipe their copies once the transaction is built.
- `buildRingWithdrawalTransaction` pays SPL tokens out to the recipient's
  token account, `splTokenProgram` selects the token program.
- `ProvenRingTransfer.ownerSigners` lists the extra signers a ring
  transaction needs when a spent note belongs to someone other than the
  fee payer.
- `ringSettlementStatics()` returns the settlement accounts a new ring
  lookup table carries, tables made before this keep working.
- `AssetRegistry.register(assetId, mint)` and `Wallet.ensureAsset` bind a
  token id to its mint once and refuse a conflicting binding.
- `fetchSplAssetRegistrations(rpc)` reads every SPL token registered with
  the pool.

Changed

- Ring transfers and withdrawals pick the largest notes first and only
  notes on the client's tree, a fragmented balance covers with the fewest
  inputs and selection never throws `RING_MULTIPLE_INPUT_TREES`.
- The approval prompt names the token, the ring, and on an entry the full
  default-note value that becomes ring bound, change included.
- A ring transfer whose fee payer is not the note owner is no longer
  refused upfront with `TRANSACTION_ED25519_PAYER_MISMATCH`, the owner
  co-signs the built transaction, and a relayed transaction, today larger
  than a Solana packet, is refused at build with
  `INTERFACE_TRANSACTION_TOO_LARGE`.

Fixed

- A zero-amount ring transfer selected a note and moved its whole value
  into the ring as change, the ring builders refuse zero with
  `RING_ZERO_AMOUNT`.
- `auditRing` stopped on a token registered after the auditor's wallet was
  made, it reloads the registry from the chain once and continues.

## 0.1.3-alpha — 2026-08-28

Wallets run behind a remote signer, the SDK holds only the derived
privacy keys and the signer approves the finished transaction. Sync
resumes where it stopped instead of rescanning the history.

Breaking

- `LocalWalletAuthority` is renamed `KeypairWalletAuthority` → rename the
  import, constructors and methods are unchanged.

Added

- `ClientEd25519WalletAuthority` runs a wallet whose Solana key stays in a
  remote signer, the SDK holds only the derived privacy keys and the remote
  signer authorizes the finished transaction (#267).
- The output decoders (`decodeConfidential`, `decodeAnonymousRecipient`,
  `decodeAnonymousSender`, `decodePlaintextTransfer`, `decodeSplitBundle`,
  `decodeSplitEncrypted`, `decodeProofless`) read decrypted outputs for
  callers that decrypt outside the wallet (#271).
- `listRegisteredRings(rpc)` lists every custom ring registered with the
  pool (#275).
- `ED25519_SEED_LEN` and `P256_SEED_LEN` give the exact derivation-seed
  length each key type expects, a wrong length raises
  `KEYPAIR_INVALID_DERIVATION_SEED`.
- `RingConfigAccount.paused` reports a halted ring, every operational ring
  instruction is refused while it is set.

Changed

- `syncWallet` resumes an interrupted scan where it stopped instead of
  rereading the whole history, pinned by the wallet sync tests (#267).
- Wallet sync labels a transfer addressed only to your own wallet
  `selfTransfer` and updates a re-observed transaction row in place instead
  of duplicating it, pinned by the wallet sync tests (#267).

## 0.1.2-alpha — 2026-08-26

Custom rings arrive, compartments of the shielded pool with their own
program, their own auditor, and controlled read access. Every `zone` name
in the API becomes `ring`, and the new `ring` import path carries ring
deposits, transfers, withdrawals, auditing, and the ring service client.

Breaking

- Every `zone` name in the API is `ring` (`decodeRingConfig`,
  `RingConfigAccount`, the `ringProgramId` and `ringDataHash` fields, error
  names like `InvalidRingConfig`) → rename at every use, numeric error
  codes keep their values (#258).
- `SerializedWalletState` moves to `version: 2` with the renamed fields →
  wallets serialized by 0.1.1 do not load, serialize again from a synced
  wallet.
- `WalletAuthority` requires `encryptCustomRingTransfer` and
  `ViewingKeyLike` requires `decryptRingDeposit` → only custom
  implementations are affected, the shipped classes carry both.

Added

- The `ring` import path brings custom rings, pools with their own auditor:
  `buildRingDepositTransaction`, `buildRingTransferTransaction`,
  `buildRingWithdrawalTransaction`, `buildRingLookupTableTransaction`, and
  `proveCustomRingTransfer` (#258).
- `RingRpc` reads a ring's service with signed requests, on-chain reader
  grants (`grantReadAccessInstruction`, `revokeReadAccessInstruction`), and
  passkey readers (`createPasskey`).
- `auditRing` and `auditRingTransaction` let a ring's auditor decrypt and
  attribute every transaction in the ring.
- `ZolanaClient` gains ring proving and health calls (`proveRingTransact`,
  `proveCustomRing`, `proverHealth`) and program-account reads
  (`getProgramAccounts`).
- `ConfidentialTransfer` binds a transfer to a ring (`withRingProgramId`),
  drops unused change slots (`withCompactChange`), and sends a note back to
  the default pool (`sendDefaultRing`).
- A wallet runs from a derivation seed without holding a Solana signing key
  (`LocalWalletAuthority.fromDerivationSeed`,
  `ViewingKey.fromDerivationSeed`).
- `fetchViewingKeyOwners` maps every registered viewing key to its owner,
  and `fetchTransactionSlots` reads a transaction's outputs without a
  viewing key.
- Tag queries report `scannedThrough`, the point a resumed scan continues
  from.

Dependencies

- `@solana-program/address-lookup-table` ^0.13.0 (new).

## 0.1.1-alpha — 2026-08-19

Key derivation aligns with the Rust SDK, both privacy keys expand from a
seed one deterministic wallet signature produces, and keys from the
removed constructors differ. The indexer and prover wire names change
with it, the services and the SDK must update together.

Breaking

- The indexer and prover wire names are camelCase → run the indexer and
  prover from the same revision as the SDK (#229).
- Both privacy keys expand from `SigningKey.derivationSeed()`, matching the
  Rust SDK, and the old constructors (`ShieldedKeypair.fromEd25519`,
  `.fromKeys`, `ViewingKey.fromSeed`, `NullifierKey.fromSigningKey`) are
  removed → derive with `ShieldedKeypair.fromKeypair(signing)`, keys made
  by the removed constructors differ (#231).
- `SigningKey.fromBytes` is renamed `SigningKey.fromP256Bytes` → rename.
- The merge-encryption helpers `mergeViewTag`, `encryptVerifiable`, and
  `decryptVerifiable` are removed → `symmetricApply` is the cipher behind
  them.
- `hashField` and `ShieldedPublicKey.hash()`/`.ownerPublicKeyField()` are
  removed → `ShieldedPublicKey.ownerProofInputHash()`.
- `KeypairErrorCode` drops `KEYPAIR_FIELD_ELEMENT_TOO_LONG` and
  `KEYPAIR_INFO_TOO_LONG` and adds `KEYPAIR_DERIVATION_INPUT` → update
  exhaustive matches.

Added

- `ed25519DerivationMessage(signerPublicKey)` and
  `isDerivationInput(message)` give a browser wallet the exact message that
  derives the privacy keys, and detect it before signing anything else.
- Nullifier queries report `scannedThrough`, the point a resumed scan
  continues from.

Changed

- `syncWallet` asks the nullifier stream about unspent notes only and
  resumes it from `scannedThrough`, pinned by the wallet sync tests (#220).

## 0.1.0-alpha — 2026-08-17

First release, a TypeScript SDK for the Zolana shielded pool. One client
connects Solana, the indexer, and the prover, and the package covers the
full private flow, deposits, transfers, splits, merges, withdrawals, and
wallet sync.

Added

- First release of `@heliuslabs/zolana`, the TypeScript SDK for the Zolana
  shielded pool, ESM, Node >= 24, peer `@solana/kit` ^7.0.0 (#170).
- `createZolanaClient` connects Solana, the indexer, and the prover in one
  client that reads accounts, queries private transactions, and proves
  transfers and merges.
- The `keypair` path derives and manages the shielded key material
  (`ShieldedKeypair`, `ViewingKey`, `NullifierKey`).
- The `transaction` path holds wallet state and the proof-input builders
  (`Wallet`, `ConfidentialTransfer`, `ConfidentialSplit`, `Merge`).
- The `wallet` path builds the user flows, deposit, transfer, split, merge,
  withdrawal, and registration, and syncs a wallet from the chain
  (`syncWallet`).
- The `interface` path carries the program ids, account decoders,
  instruction builders, and every wire type.
- The `instructions` and `addresses` paths give kit-style instruction
  builders and PDA getters.
