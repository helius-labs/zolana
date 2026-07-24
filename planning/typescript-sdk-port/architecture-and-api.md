# Architecture and API contract

All package claims use frozen Rust revision
`43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f` (`43fde8e4`). The Rust crate
roots and manifests, not the checked-out worktree, define this graph.

## Dependency graph

```text
@zolana/transaction ──→ @zolana/interface
        │              @zolana/keypair
        │
@zolana/client ───────→ @zolana/transaction
        │              @zolana/interface
        │              @zolana/keypair
        └─────────────→ @zolana/api ──→ @zolana/indexer-api

@zolana/wallet ───────→ @zolana/client
                       @zolana/transaction
                       @zolana/interface
                       @zolana/keypair

@zolana/merkle-tree → hash/indexed-array primitives only
@zolana/smart-account-client → Solana primitives only
@zolana/test-kit (private) → any production package needed by tests
```

An arrow points from importer to dependency. Vertically listed dependencies
share the preceding package's arrow. A package may also depend on audited
third-party primitives needed for its responsibility. No
production package may import `@zolana/test-kit` or another package's `src`
path. Root and subpath exports are explicit; wildcard re-exports are forbidden.

## Package contracts

### `@zolana/interface`

- **Rust source:** [`program-libs/interface/Cargo.toml`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/Cargo.toml)
  and [`src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/lib.rs).
- **Allowed production dependencies:** Solana address/instruction primitives,
  byte-layout and Borsh codecs, and the protocol's event/tree/hash layout
  crates. It depends on no SDK crate.
- **Root:** canonical program IDs, seeds, instruction tags and data layouts,
  state-account codecs, errors, and raw instruction builders.
- **Subpaths:** `./pda` contains address derivation; `./codecs` contains the
  canonical binary codecs; `./instructions` contains the complete raw builder
  set corresponding to
  [`instruction/builders/mod.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/instruction/builders/mod.rs).
- **Runtime:** browser and Node. It uses `Uint8Array`, `bigint`, and Solana
  address/instruction types; it performs no I/O.
- **Internal:** verifying keys, tree mutation helpers, generic codec machinery,
  and implementation-only constants that are not required to build or decode
  the public wire contract.
- **Errors:** `InterfaceError` for caller-side layout, range, PDA, and
  discriminator failures; `ShieldedPoolErrorCode` for stable on-chain codes
  7000–7025 from [`error.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/program-libs/interface/src/error.rs).
- **Boundary rationale:** this is the sole TypeScript owner of program layouts.
  Higher packages call these builders and codecs instead of recreating account
  order, signer/writable flags, tags, or serialization.

### `@zolana/keypair`

- **Rust source:** [`sdk-libs/keypair/Cargo.toml`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/Cargo.toml)
  and [`src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/lib.rs).
- **Allowed production dependencies:** audited P-256, Ed25519, AES-CTR, HKDF,
  SHA-256, Poseidon, randomness, zeroization, and Solana key primitives. It has
  no dependency on another Zolana SDK package.
- **Root:** signing, nullifier, viewing, public-key, shielded-address, keypair,
  view-tag, transaction-viewing-key, context-bound slot encryption/decryption,
  merge encryption/decryption, salt, and random-blinding operations. Slot
  cryptography retains the recipient or transaction viewing public key, salt,
  and `u32` slot index required by
  [`viewing_key.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/viewing_key.rs)
  and
  [`encryption.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/encryption.rs).
- **Subpath:** `./merge` contains verifiable merge encryption and its public
  contribution/hash functions from
  [`merge.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/merge.rs).
- **Runtime:** browser and Node. Random generation uses a Web Crypto-compatible
  source. APIs that import or export a Solana keypair belong in a Node/Solana
  adapter, not the browser root.
- **Internal:** raw ECDH, HKDF, AES, Poseidon, fixed-point constants, key
  serialization machinery, and secret buffers not explicitly returned by a
  public method.
- **Errors:** `KeypairError` with one stable TypeScript code per variant in
  [`error.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/error.rs).
- **Boundary rationale:** secret-bearing cryptography is isolated from
  transaction construction and network clients. Public methods return copies
  of retained byte input and never expose mutable secret storage.

### `@zolana/transaction`

- **Rust source:** [`sdk-libs/transaction/Cargo.toml`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/Cargo.toml)
  and [`src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/lib.rs).
- **Allowed production dependencies:** `@zolana/interface`,
  `@zolana/keypair`, protocol hash/event codecs, Borsh/wincode, P-256, and
  Solana address/signature primitives. No HTTP or Solana RPC dependency.
- **Root:** `Data`, UTXOs, `ProofInputUtxo`, `ProofOutputUtxo`,
  `ConfidentialTransfer`, `PreparedTransfer`, proof inputs, encrypted
  transaction values, asset registry, wallet state/history, authority value
  types, and Promise-based decryption over a supplied authority.
- **Subpaths:** `./serialization` owns proofless/confidential/anonymous/
  plaintext/split/merge codecs; `./instructions` owns transfer, split, merge,
  zone, shape, slot, and proof-input construction; `./wallet` owns pure wallet
  state transforms over caller-supplied indexed transactions.
- **Runtime:** browser and Node. The optional Rust Rayon implementation maps to
  an internal worker strategy; public results must be ordering-equivalent.
- **Internal:** the field-encoded Rust `utxo::ProofInputUtxo` (TypeScript uses
  `ProofInputUtxo` for Rust `SppProofInputUtxo`), wincode schemas, mutable
  assembly helpers, ciphertext slot mechanics not required by the workflow,
  and parallel scheduling.
- **Errors:** `TransactionError` from
  [`error.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/transaction/src/error.rs), including validation,
  amount, shape, serialization, asset-registry, decryption, and wallet-state
  failures.
- **Boundary rationale:** this package owns deterministic transaction math and
  state transitions. It accepts data and returns values without fetching
  accounts, proofs, blockhashes, or signatures.

### `@zolana/indexer-api`

- **Rust source:** [`sdk-libs/indexer-api/Cargo.toml`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/indexer-api/Cargo.toml)
  and [`src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/indexer-api/src/lib.rs).
- **Allowed production dependencies:** base58/base64, strict JSON
  serialization, and Solana public-key/signature parsing. It has no transport
  dependency.
- **Root:** five canonical JSON-RPC method constants, strict request/response
  schemas, encoded scalar types, pagination bounds, Merkle proofs, indexed
  transactions, and nullifier queue elements.
- **Subpath:** `./methods` contains typed method descriptors; it does not send
  requests.
- **Runtime:** browser and Node; pure validation and conversion only.
- **Internal:** OpenAPI derivation, serde visitors, wire-key conversion, and
  schema-generation helpers.
- **Errors:** `IndexerSchemaError` wraps hash, address, signature, base64,
  unknown-field, and page-limit validation failures.
- **Boundary rationale:** both indexer implementations and transports must use
  one JSON contract. `@zolana/api` consumes these types; it does not regenerate
  or redefine them. Its `MerkleProof` and `NonInclusionProof` are wire-schema
  types with branded base58 `Hash` fields. `NonInclusionProof` is a standalone
  ten-field type and has no inclusion-proof `leafIndex`.

### `@zolana/api`

- **Rust source:** [`sdk-libs/zolana-api/Cargo.toml`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/zolana-api/Cargo.toml)
  and [`src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/zolana-api/src/lib.rs).
- **Allowed production dependencies:** `@zolana/indexer-api`, `fetch`, and a
  strict JSON parser. No wallet, keypair, transaction, or prover dependency.
- **Root:** asynchronous `ZolanaApi`, request context, URL/API-key
  configuration, and typed calls for every indexer method.
- **Subpath:** `./node` may contain an explicitly Node-only blocking adapter;
  it is not re-exported from the browser root.
- **Runtime:** browser and Node for the root. The TypeScript root deliberately
  omits Rust's `BlockingZolanaApi`.
- **Internal:** JSON-RPC IDs/envelopes, header construction, response-body
  decoding, API-key redaction, and retry plumbing.
- **Errors:** `ApiError` from [`src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/zolana-api/src/lib.rs)
  mapped to configuration, request, HTTP status, JSON-RPC, and response-schema
  codes.
- **Boundary rationale:** transport owns network failure and authentication;
  `@zolana/indexer-api` owns wire meaning.

### `@zolana/client`

- **Rust source:** [`sdk-libs/client/Cargo.toml`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/Cargo.toml)
  and [`src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/lib.rs).
- **Allowed production dependencies:** `@zolana/interface`,
  `@zolana/keypair`, `@zolana/transaction`, `@zolana/api`, prover JSON/math,
  and Solana RPC/transaction primitives.
- **Root:** async RPC abstractions including state-inclusion,
  nullifier-non-inclusion, and combined input-proof fetching; Solana RPC and
  Photon adapters; retry/config values; prover values; `ZolanaClient`; and
  selected transaction types needed by proving. The proof capabilities come
  from frozen
  [`rpc.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/rpc.rs);
  `ZolanaClient` delegates them in
  [`client.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/client.rs).
- **Subpath:** `./prover` exposes independently usable prover request,
  assembly, shape, and proof conversion APIs. No local process spawning is
  public.
- **Runtime:** browser and Node. Root APIs are Promise-based. Node-only Solana
  RPC implementations may use a `./node` adapter; browser consumers may supply
  any `Rpc` implementation.
- **Internal:** blocking adapters, `spawn_prover`, raw field/JSON conversion,
  proof-point math, HTTP tracing, and retry loops.
- **Errors:** `ClientError` from
  [`error.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/error.rs), including RPC, indexer,
  prover, shape, proof, confirmation, tree, fee-payer, and transaction assembly
  failures.
- **Boundary rationale:** the client composes RPC, Photon, and the prover. It
  does not own wallet state, registry, authorities, action creation, signing
  orchestration, balances, history, or sync; those moved to `@zolana/wallet` in
  frozen Rust. Client proof types use `Bytes32`, not indexer `Hash`; the Photon
  adapter performs the explicit conversion. The client owns these semantic
  types rather than aliasing the schema package, so dependency flow remains
  client to API/indexer schema.

### `@zolana/wallet`

- **Rust source:** [`sdk-libs/wallet/Cargo.toml`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/Cargo.toml)
  and [`src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/lib.rs).
- **Allowed production dependencies:** `@zolana/client`,
  `@zolana/interface`, `@zolana/keypair`, `@zolana/transaction`, the user
  registry interface, and Solana instruction/transaction primitives.
- **Root:** complete Promise `WalletAuthority` and `LocalWalletAuthority`
  capabilities, registry reads/writes, deposits, transfer/
  withdrawal/split/merge creation, private-transaction building/signing,
  merge submission, sync, balances, and history. Wallet merge creation accepts
  exactly two to eight plain, same-owner, same-asset inputs, as enforced by
  [`actions/transaction.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/actions/transaction.rs);
  submission uses generic client `Rpc` proof fetching in
  [`actions/submit.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/wallet/src/actions/submit.rs).
- **Subpaths:** `./authority`, `./registry`, `./actions`, and `./sync` group the
  same root allowlist without creating alternate owners.
- **Runtime:** browser and Node. Public network and authority operations are
  Promise-based. External custody uses unsigned native transactions and async
  authority interfaces; raw private keys never cross into client transport or
  prover methods.
- **Internal:** Rust blocking/synchronous adapters, shielded-only intermediate
  signing helpers, input selection, recipient resolution details, and mutable
  sync indexes.
- **Errors:** wallet APIs reject with `WalletError` when the failure is
  action/approval/registry/sync-specific and preserve nested
  `TransactionError`, `KeypairError`, or `ClientError` as `cause`; fewer than
  two merge inputs maps frozen `NothingToMerge`, and more than eight maps
  `TooManyInputs`.
- **Boundary rationale:** state and user intent belong above stateless
  transaction math and service composition. No client compatibility re-export
  may undo this split.

### `@zolana/merkle-tree`

- **Rust source:** [`sdk-libs/merkle-tree/Cargo.toml`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/merkle-tree/Cargo.toml)
  and [`src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/merkle-tree/src/lib.rs).
- **Allowed production dependencies:** hash adapters, big integers, and the
  indexed-array implementation. No SDK client dependency.
- **Root:** reference `MerkleTree`, `IndexedMerkleTree`,
  `NonInclusionProof`, and their error types.
- **Subpaths:** none initially; hasher adapters remain constructor inputs.
- **Runtime:** browser and Node; deterministic in-memory computation only.
- **Internal:** test randomization, indexed-array storage, and concrete hasher
  implementations not backed by frozen vectors.
- **Errors:** `MerkleTreeError` and `IndexedMerkleTreeError`.
- **Boundary rationale:** it is a reference/test utility and must not replace
  an authoritative indexer proof in production proving. Its package-local
  `NonInclusionProof` records `value`, lower/higher range values, `leafIndex`,
  `nextIndex`, `merkleProof`, and `root`. It is not structurally interchangeable
  with either Photon or client non-inclusion proofs and introduces no dependency
  on those packages.

### `@zolana/smart-account-client`

- **Rust source:** [`sdk-libs/smart-account-client/Cargo.toml`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/smart-account-client/Cargo.toml)
  and [`src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/smart-account-client/src/lib.rs).
- **Allowed production dependencies:** Solana public-key/instruction and Borsh
  primitives only.
- **Root:** program ID, four PDA helpers, `Permissions`,
  `SmartAccountSigner`, `createSmartAccountInstruction`, and
  `executeSyncInstruction`.
- **Subpaths:** none. Payload compilation stays inside the execute builder.
- **Runtime:** browser and Node; pure instruction construction.
- **Internal:** Anchor discriminators, seeds, Borsh argument structs, payload
  account-index compilation, and signer/writable escalation.
- **Errors:** `SmartAccountClientError` for range, threshold, signer count,
  account-index, instruction-count, account-count, and payload-size failures.
- **Boundary rationale:** the Squads-compatible wire contract is independent of
  the shielded-pool interface. Its execute builder must preserve every inner
  account's signer/writable union and keep the vault non-signer in the outer
  instruction.

### `@zolana/test-kit` (private)

- **Rust source:** [`sdk-libs/program-test/Cargo.toml`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/program-test/Cargo.toml)
  and [`src/lib.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/program-test/src/lib.rs).
- **Allowed dependencies:** any production package plus local validator,
  fixture, process, and filesystem libraries used only by tests.
- **Root:** local-stack lifecycle, program deployment, fixture loading, typed
  fake RPC/indexer/prover implementations, deterministic randomness, and
  common protocol setup helpers.
- **Subpaths:** `./node` owns process/filesystem/localnet helpers; `./fixtures`
  owns frozen vectors.
- **Runtime:** Node only; private and unpublished.
- **Internal:** LiteSVM-specific state, test account mutation, path discovery,
  and SBF loading details.
- **Errors:** `TestKitError` wraps process, fixture, localnet, and production
  package errors.
- **Boundary rationale:** production bundles must not acquire local process,
  filesystem, test mutation, or validator dependencies.

## Runtime and type rules

- Publish ESM, ES2022, declarations, declaration maps, and source maps.
- Browser-capable roots use `Uint8Array`, `bigint`, `TextEncoder`, `fetch`,
  Web Crypto, and `AbortSignal`; they do not use `Buffer`, `node:*`,
  `process`, filesystem APIs, or CommonJS.
- Network methods accept an optional `RequestContext` containing
  `signal?: AbortSignal` and `timeoutMs?: number`.
- `u8`/`u16`/`u32` map to validated `number`; protocol `u64`, `i64`, and
  `u128` map to `bigint`; array indexes map to validated safe `number`.
- `[u8; N]` maps to a checked branded `Uint8Array`; retained arrays and bytes
  are copied. `Vec<T>` input is `readonly T[]`; returned collections are owned
  or readonly snapshots as declared.
- `Option<T>` maps to `T | undefined`; `null` is accepted only where the
  external JSON wire requires it.
- Rust enums become string-discriminated unions. Numeric wire tags remain in
  codecs.
- `solana_address::Address` and `solana_pubkey::Pubkey` both map to the selected
  Solana `Address` type; public APIs do not introduce a second `Pubkey` class.
- Rust blocking/async pairs collapse to one Promise API. The only synchronous
  public operations are pure constructors, validation, codecs, PDA derivation,
  and instruction builders.

## Error contract

Every package error extends `Error` and has stable `code`, optional structured
`details`, and optional `cause`. Public validation fails before I/O. Network,
authority, and proving failures reject Promises. Dependency errors are wrapped
once; message text is not a compatibility key. Tests assert codes and
structured details such as expected/actual byte length, amount, asset, shape,
input index, path length, method, HTTP status, tree, or signature.

## Deliberate TypeScript differences

- `P256Pubkey` becomes `P256PublicKey`; the scheme-tagged Rust `PublicKey`
  becomes `ShieldedPublicKey` to avoid collision with Solana terminology.
- Keypair methods camel-case and shorten Rust `get_*` names without removing
  counters, counterparties, public keys, salts, or slot indexes.
  `transactionViewingKey` returns a `ViewingKey`, matching
  [`ViewingKeyTrait`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/traits/view_key.rs).
  `ViewingKeyLike` deliberately narrows that trait to the optionally async
  authority methods currently consumed by higher packages.
- Verifiable merge encryption replaces Rust's tuple result with
  `{ ciphertext, txViewingPublicKey }`. The public-contribution object
  camel-cases, but retains, the transaction viewing public key's low/high
  limbs and the ciphertext hash from
  [`merge.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/keypair/src/merge.rs).
- Rust blocking variants and `_sync` functions are not exported. This removes
  stale `signTransaction`, `signTransactionSync`, and `_sync` aliases; neither
  frozen crate roots nor the selected current ownership require them in
  TypeScript.
- Rust's `BlockingZolanaApi`, `ZolanaIndexer`, `SolanaRpc`, and
  `ProverClient` blocking forms collapse into async TypeScript classes.
- `ZolanaClient.prove_transact` and `confirm_private_transaction` become
  Promise-returning `proveTransact` and `confirmPrivateTransaction` methods,
  sourced from [`client.rs`](https://github.com/helius-labs/zolana/blob/43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f/sdk-libs/client/src/client.rs).
- Wallet actions, authority, registry, balances, history, and sync stay in
  `@zolana/wallet`; `@zolana/client` has no compatibility re-export for them.
- `create_smart_account_ix` and `execute_sync_ix` use the descriptive
  `createSmartAccountInstruction` and `executeSyncInstruction` names.

## API review gate

Generate an API report for every package and entry point. Normalize type-only
and value exports, compare it with
[public-exports.md](public-exports.md), and fail on every missing, extra,
renamed, or misplaced symbol. Any deliberate difference requires a source link
and semver review after `0.1.0`.
