# Changelog

## 0.1.6-alpha — unreleased

Custom rings come in two tiers, an audit-only ring proves the auditor
encryption alone and a policy ring proves its rule table over a dedicated
entries tree, and a ring transfer can land its outputs in a tree other than
the one it spends from. Wallet replay keeps merge outputs when their inputs
arrive in the same sync, and selection and approval text use UTXO terminology
without changing version 3 snapshot keys.
A tree derives from its id instead of one fixed address, holds its own fee
schedule, and takes four instructions in one transaction to create. Every
spent nullifier gets its own account, and the transact, merge, and ring
builders take one nullifier account per input. Registering a ring and admitting
it are now two separate steps with two different signers. The proof system changed underneath: owner identities carry a signing
algorithm tag, every UTXO commits to the tree it lives in, and one private
blinding seed per proof derives every output blinding and the private
transaction hash blinding.

Breaking

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
  `inputTreeId` and `outputTreeId`, and `PreparedTransfer` and `PreparedSplit`
  expose the seed material the prover needs → an input set spanning two trees
  is refused with `TRANSACTION_INPUT_TREE_MISMATCH`.
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
  every input of an instruction carries one root position pair
  (`AssembledTransfer.rootIndexes`), and the prover request carries `treeSlots`,
  `outputTreeId`, and `blindingSeed` → run a prover from this release.
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
- `extendProgramInstruction` uses the checked extension on Agave 4.0.2 → pass
  the upgrade `authority` alongside `payer`.
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
- `buildRingLookupTableTransaction` reads the tier and a policy ring's entries
  tree from the chain, accepts `outputTree`, and needs `getAccount` on
  `RingLookupTableClient`, `fetchRingLookupTable` and
  `ringLookupTableAddresses` take the trees as `RingTransactTrees`, and the
  fetch refuses a table extended in the current slot with
  `RING_LOOKUP_TABLE_NOT_READY` → rebuild a policy ring's table, one built by
  an earlier version is refused with `RING_LOOKUP_TABLE_INCOMPLETE`, pass a
  `ProvenRingTransfer` as the `trees` of the fetch, and wait one slot after
  the extension before the first transfer.
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
  30,344-byte tree accounts incompatible → deploy fresh 39,952-byte trees
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
- `ShieldedPoolError` adds codes 7029 to 7064: deposit and SPL interface
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
- `buildRingEntryTransaction`, `buildRingTransferTransaction`, and
  `buildRingExitTransaction` use UTXO terminology in approval summaries, while
  version 3 `SerializedWalletState` reservation field names remain unchanged.
- `RingLookupTableReader` is `KitRpcAccess` alone, `fetchRingLookupTable` no
  longer reads `client.tree`.

Fixed

- `decodeRingPolicyConfig` returns the stored per-asset limits without reversing their bytes.
- `decryptTransactions` no longer omits a merge when its inputs arrive in the
  same sync because merge dependencies resolve before wallet commit.
- A deposit could be given a blinding that already belonged to another deposit,
  which produced a duplicate UTXO hash and nullifier and left the second UTXO
  unspendable; the shielded pool now derives every deposit blinding from the
  tree and the leaf index, so each deposit is unique.

Dependencies

- `@solana-program/address-lookup-table` ^0.14.1 (was ^0.13.0).
- `@solana-program/compute-budget` ^0.18.1 (was ^0.17.0).
- `@solana-program/token` ^0.16.1 (was ^0.15.0).
- `@solana-program/system` ^0.14.1 (new).

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
  `proveCustomRingPolicy`, `proverHealth`) and program-account reads
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
