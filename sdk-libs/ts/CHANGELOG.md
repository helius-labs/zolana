# Changelog

## 0.1.5-alpha — unreleased

Wallet sync is atomic, a sync that fails partway changes nothing and the
next sync re-reads what the failed one fetched. Serialized wallets carry
their resume cursors, a restarted wallet continues where it stopped
instead of rescanning history. Keys granted by a wallet authority live
only inside scoped sessions that wipe them when the callback settles.

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
- `RingRpc` throws `RING_RPC_CONFIG` for an endpoint with plain HTTP,
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
- Serialized wallets carry their reservations, a restored wallet still
  holds notes an in-flight transaction spends.
- `ChainReader`, `BlockhashProvider`, `IndexerReader`, `ProofReader`,
  `Prover`, `TransactionConfirmer`, and `KitRpcAccess` name the client's
  capabilities, `ZolanaClient` implements them all, and a consumer can
  depend on only the one it uses.
- `SyncClient` is exported, `syncWallet` needs only the three indexer
  reads and kit access only for a wallet holding a mint the registry
  cannot resolve.
- `TransactionAssembler`, `MergeAssembler`, and `TreeContext` name the
  client's assembly capabilities, `DepositClient`, `MergeClient`,
  `PrivateTransactionClient`, `RingTransferClient`, and `RingAuditReader`
  name what each build accepts, and any object with those members serves
  in place of `ZolanaClient`.
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

## 0.1.4-alpha — unreleased

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
