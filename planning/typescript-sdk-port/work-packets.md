# Implementation work packets

These packets implement the TypeScript port against frozen Rust revision
`43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`. A contextless agent starts with
[README.md](README.md), its packet's inventory rows, the exact declarations in
[public-exports.md](public-exports.md), and the relevant workflow in
[action-and-instruction-api.md](action-and-instruction-api.md).

## Rules for every packet

- Modify only owned files. A path or generated artifact has exactly one owner.
- Read Rust with `git show 43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f:<path>`;
  enumerate with `git ls-tree` at that revision.
- Do not edit `docs/spec.md`, Rust protocol code, programs, prover behavior, or
  examples unless the packet explicitly owns a test-only fixture generator.
- Start with a failing fixture/test. Do not copy protocol math into tests.
- Close every cited `inventory-active` row with implementation, fixture, test,
  and evidence; preserve `not applicable` rows as explicit exclusions.
- Use the exact package/API names in the public export manifest. Do not add
  removed signing aliases or wallet exports under `@zolana/client`.
- Record commands, exit status, fixture IDs, API diff, and changed paths in
  `sdk-libs/ts/reports/packets/<packet>.json`.

The commands below are stable responsibilities. The workspace packet may map
them to the selected package manager without changing their meaning.

## P00 — Baseline, inventory, and fixture oracle

Prerequisites: none.

Owned files:

- `xtask/src/**` files created solely for `ts-fixtures`;
- `sdk-libs/ts/fixtures/**`;
- `sdk-libs/ts/reports/inventory.json`;
- `sdk-libs/ts/reports/packets/P00.json`.

Source inventory rows: the seven rows whose `Packet` cell is `P00` (one
keypair, five client, and one transaction test/generator evidence row). P00 also
checks all 182 rows without taking ownership from their declared packets.
Frozen evidence includes crate roots, `sdk-tests/client/**`,
`program-tests/shielded-pool/**`, `program-tests/spp-test-validator/**`,
user-registry, and smart-account support.

Exports: none.

Work and fixtures:

- assert the frozen tree has 182 paths and each has one active marker or
  exclusion, one packet, and at least one fixture/test responsibility;
- generate the fixture manifest and package directories defined in
  [testing-and-conformance.md](testing-and-conformance.md);
- call production Rust for logical values, errors, bytes, accounts, proof
  inputs, Merkle/non-inclusion paths, prover JSON/result/compression,
  instructions, indexer schemas, smart-account vectors, and wallet sequences;
- mark test secrets and hash every fixture.

Tests and commands:

```text
cargo xtask ts-fixtures --check
npm run test:inventory
git diff --exit-code -- sdk-libs/ts/fixtures
```

Completion evidence: two clean generator runs; 182 covered paths, zero missing
or duplicate rows, zero unknown packet IDs; manifest hashes and frozen SHA
match. P00 does not change planning documents.

## P01 — Workspace and package scaffolding

Prerequisites: P00.

Owned files:

- root TypeScript workspace manifest and lockfile; P01 is the sole modifying
  owner of the root lockfile;
- root TypeScript, lint, format, test, build, browser, and package-consumer
  configuration;
- package manifests and build/test configs for all ten packages;
- `sdk-libs/ts/reports/packets/P01.json`.

Source inventory rows: the nine rows whose `Packet` cell is `P01`; the
non-inventoried interface package manifest is also scaffolded here.

Exports: no runtime export. Configure explicit root/subpath maps for
`@zolana/interface`, keypair, transaction, indexer-api, api, client, wallet,
merkle-tree, smart-account-client, and private test-kit.

Fixtures/tests: dependency graph snapshot, export-condition consumers, ESM
declaration paths, browser forbidden-import scan, and `npm pack` smoke.

Commands:

```text
npm ci
npm run check
npm run pack:check
npm run test:browser
```

Completion evidence: ten packages build; nine production packages pack and
import in fresh Node 20/22 and browser consumers; test-kit is private; no
production dependency reaches test-kit. Package source indexes and API reports
remain owned by P02–P10 and P14.

## P02 — Shielded-pool interface

Prerequisites: P00, P01.

Owned files:

- `sdk-libs/ts/interface/src/**`, including its root and three subpath indexes;
- `sdk-libs/ts/interface/test/**`;
- `sdk-libs/ts/reports/packets/P02.json`.

Source inventory rows: none; the six inventories cover `sdk-libs`, while this
packet maps frozen `program-libs/interface/src/lib.rs`,
`error.rs`, `pda.rs`, `shape.rs`, `state/**`,
`instruction/instruction_data/**`, and `instruction/builders/**` referenced by
the interface declarations and workflows.

Exports: complete `@zolana/interface`, `./pda`, `./codecs`, and
`./instructions` allowlist; no extra builder or verifier export.

Fixtures/tests: every ID/PDA/account decoder; every instruction builder; the
complete 18-tag map (`transact`, `deposit`, `zoneTransact`,
`zoneAuthorityTransact`, `createSplInterface`, `createTree`,
`createProtocolConfig`, `updateProtocolConfig`, `pauseTree`,
`createZoneConfig`, `updateZoneConfigOwner`, `updateZoneConfig`,
`mergeTransact`, `zoneMergeTransact`, `emitEvent`, `zoneDeposit`,
`createAssetCounter`, `batchUpdateNullifierTree`); deposit/transact SOL/SPL
exact bytes, account order, signer/writable flags; malformed data, lengths,
discriminators, integers, variants, and account-flag mutations.

Commands:

```text
npm run test:vectors --workspace @zolana/interface
npm run test:unit --workspace @zolana/interface
npm run test:browser --workspace @zolana/interface
npm run check --workspace @zolana/interface
```

Completion evidence: all cited builders/codecs match frozen Rust byte-for-byte;
root/subpath exports equal the manifest; P02 owns the interface package indexes
but not its API report.

## P03 — Smart-account client

Prerequisites: P00, P01.

Owned files:

- `sdk-libs/ts/smart-account-client/src/**`, including `src/index.ts`;
- `sdk-libs/ts/smart-account-client/test/**`;
- `sdk-libs/ts/reports/packets/P03.json`.

Source inventory rows: the one smart-account row whose `Packet` cell is `P03`
in
[inventory-indexer-and-smart-account.md](inventory-indexer-and-smart-account.md);
frozen `sdk-libs/smart-account-client/src/lib.rs`; frozen
`program-tests/test-utils/src/smart_account.rs` for integration vectors.

Exports: exact program ID, permissions, four PDA helpers, signer type,
`createSmartAccountInstruction`, `executeSyncInstruction`, and error.

Fixtures/tests: PDA seeds/bumps; create and execute bytes/metas; duplicate
privilege union; stable inner indexes; vault outer non-signer; `u8`, `u16`,
threshold, uniqueness, account/instruction/data/compiled-payload boundaries and
one-overflow rejections.

Commands:

```text
npm run test:vectors --workspace @zolana/smart-account-client
npm run test:property --workspace @zolana/smart-account-client
npm run test:browser --workspace @zolana/smart-account-client
```

Completion evidence: every meta bit and payload byte matches Rust; no truncating
cast survives mutation tests; package index has one owner.

## P04 — Keypair cryptography

Prerequisites: P00, P01.

Owned files:

- `sdk-libs/ts/keypair/src/**`, including root and `./merge` indexes;
- `sdk-libs/ts/keypair/test/**`;
- `sdk-libs/ts/reports/packets/P04.json`.

Source inventory rows: the 30 rows whose `Packet` cell is `P04` in
[inventory-keypair.md](inventory-keypair.md).

Exports: complete keypair root and merge allowlists, including corrected
nullifier `(utxoHash, blinding)` API; internals stay private.

Fixtures/tests: exact P256/Ed25519 parse/sign/verify, public and owner fields,
nullifier derivation, ECDH/HKDF/AES slots, all view tags, transaction viewing
keys, shielded addresses, merge encryption, randomness injection, secret
copy/destruction, malformed and tamper cases.

Commands:

```text
npm run test:vectors --workspace @zolana/keypair
npm run test:property --workspace @zolana/keypair
npm run test:browser --workspace @zolana/keypair
```

Completion evidence: Rust↔TypeScript signatures and ciphertexts verify both
ways; no Node global or secret diagnostic; every keypair inventory row closed.

## P05 — Transaction and pure wallet state

Prerequisites: P02, P04.

Owned files:

- `sdk-libs/ts/transaction/src/**`, including root, serialization,
  instructions, transact, and wallet indexes;
- `sdk-libs/ts/transaction/test/**` and benchmarks;
- `sdk-libs/ts/reports/packets/P05.json`.

Source inventory rows: the 62 rows whose `Packet` cell is `P05` in
[inventory-transaction.md](inventory-transaction.md).

Exports: complete transaction declarations, including `ProofInputUtxo`,
`PreparedTransfer`, `ConfidentialTransfer`, `SppProofInputs`, corrected SPL
`WithdrawalTarget`, `Wallet.utxos()`, and Promise `decryptTransactions`.

Fixtures/tests: all data/UTXO/serialization schemes; hashes/nullifiers;
transfer, split, merge, zone and slot behavior; shape/conservation/dummy
properties; exact proof inputs and their mapping to wire `InputUtxo`
(`nullifierHash`, `nullifierTreeRootIndex`, `utxoTreeRootIndex`, `treeIndex`,
`eddsaSignerIndex`), `OwnerTag`, `TransactOutput.data`, `relayerFee` `u16`,
message `data`, and 32-byte compressed P256 `commitment`/`commitmentPok`;
wallet
state/history/sync/tamper/worker equivalence and persisted regression seeds.

Commands:

```text
npm run test:vectors --workspace @zolana/transaction
npm run test:property --workspace @zolana/transaction
npm run test:browser --workspace @zolana/transaction
```

Completion evidence: all transaction rows closed; exact proof-input and state
snapshots match; no I/O dependency; package indexes have one owner.

## P06 — Merkle trees

Prerequisites: P00, P01, P04.

Owned files:

- `sdk-libs/ts/merkle-tree/src/**`, including `src/index.ts`;
- `sdk-libs/ts/merkle-tree/test/**`;
- `sdk-libs/ts/reports/packets/P06.json`.

Source inventory rows: the four rows whose `Packet` cell is `P06` in
[inventory-support.md](inventory-support.md).

Exports: exact Merkle tree allowlist.

Fixtures/tests: roots, paths, history/canopy/capacity/index errors, ordered
insertion, low/high neighbors, non-inclusion proofs, mutation and model
properties.

Commands:

```text
npm run test:vectors --workspace @zolana/merkle-tree
npm run test:property --workspace @zolana/merkle-tree
npm run test:browser --workspace @zolana/merkle-tree
```

Completion evidence: frozen roots and proofs match for each supported hasher;
all rows closed.

## P07 — Indexer schema

Prerequisites: P00, P01, P02.

Owned files:

- `sdk-libs/ts/indexer-api/src/**`, including `src/index.ts`;
- `sdk-libs/ts/indexer-api/test/**`;
- `sdk-libs/ts/reports/packets/P07.json`.

Source inventory rows: the one row whose `Packet` cell is `P07` in
[inventory-indexer-and-smart-account.md](inventory-indexer-and-smart-account.md).

Exports: five method constants; encoded scalar constructors and conversions;
all request/response/Merkle/non-inclusion/queue types; schema error.

Fixtures/tests: exact snake-case JSON and camel-case values; base58/base64,
address/signature, limits, optional cursor/start sequence, unknown fields,
path/index bounds, and all five response families.

Commands:

```text
npm run test:vectors --workspace @zolana/indexer-api
npm run test:property --workspace @zolana/indexer-api
npm run test:browser --workspace @zolana/indexer-api
```

Completion evidence: schema round trips match Rust and reject every malformed
mutation before a transport or wallet sees it.

## P08 — Indexer API transport

Prerequisites: P07.

Owned files:

- `sdk-libs/ts/api/src/**`, including `src/index.ts`;
- `sdk-libs/ts/api/test/**`;
- `sdk-libs/ts/reports/packets/P08.json`.

Source inventory rows: the one row whose `Packet` cell is `P08` in
[inventory-support.md](inventory-support.md).

Exports: `ZolanaApiConfig`, async `ZolanaApi`, `ApiError`; no blocking client or
schema re-export.

Fixtures/tests: exact JSON-RPC method/envelope/body for all five calls; URL and
API-key parsing; abort/timeout; HTTP/text/JSON/oversized bodies; JSON-RPC error;
missing/invalid result; bounded API-key/request/response redaction.

Commands:

```text
npm run test:unit --workspace @zolana/api
npm run test:cross --workspace @zolana/api
npm run test:browser --workspace @zolana/api
```

Completion evidence: P07 schema values cross the transport unchanged; no
competing generated schema and no credential/body leak.

## P09 — Client RPC, prover, and confirmation

Prerequisites: P02, P05, P07, P08.

Owned files:

- `sdk-libs/ts/client/src/**`, including root and `./prover` indexes;
- `sdk-libs/ts/client/test/**`, excluding acceptance E2E directories;
- `sdk-libs/ts/reports/packets/P09.json`.

Source inventory rows: the 45 rows whose `Packet` cell is `P09` in
[inventory-client.md](inventory-client.md).

Exports: exact client and prover allowlists: `IndexerPollConfig`,
`IndexerRpcConfig`, `RpcContext`, `MerkleContext`, `MerkleProof`,
`NonInclusionProof`, `GetMerkleProofsResponse`,
`GetNonInclusionProofsResponse`, root `SpendProof`, RPC adapters,
`ZolanaIndexer`, `ZolanaClient`, `assemble`, `intoProver`, `ProverClient`,
proof types and compression. `@zolana/client/prover` re-exports `SpendProof`
as a type. No wallet export.

Fixtures/tests: RPC account/blockhash/native-transaction behavior; poll config
bounds and retry timing; strict indexer conversion of `RpcContext`, state
inclusion and nullifier non-inclusion responses; `getMerkleProofs`,
`getNonInclusionProofs`, and ordered `getInputMerkleProofs` delegation/default
behavior; exact proof inputs, prover JSON/result and both proof rails;
compression; unsigned native message; abort/timeout/retry;
signature-to-output-tag Photon confirmation under lag and wrong-signature
responses.

Commands:

```text
npm run test:vectors --workspace @zolana/client
npm run test:cross --workspace @zolana/client
npm run test:prover --workspace @zolana/client
npm run test:browser --workspace @zolana/client
```

Completion evidence: deposit/transact stages through unsigned native assembly
match frozen fixtures; confirmation cannot be satisfied by another signature;
all client rows closed and no raw wallet key accepted.

## P10 — Wallet authorities, actions, and sync

Prerequisites: P05, P09.

Owned files:

- `sdk-libs/ts/wallet/src/**`, including root, authority, registry, actions,
  and sync indexes;
- `sdk-libs/ts/wallet/test/**`, excluding acceptance E2E directories;
- `sdk-libs/ts/reports/packets/P10.json`.

Source inventory rows: the ten rows whose `Packet` cell is `P10` in
[inventory-wallet.md](inventory-wallet.md), especially frozen
`sdk-libs/wallet/tests/transaction.rs`.

Exports: exact wallet allowlist with `createDeposit`,
`buildDepositTransaction`, registered/public fallback `createTransfer`,
`createWithdrawal`, `createSplit`, `createMerge`, `submitMergeTransaction`,
idempotent `createAssociatedTokenAccount`, `buildPrivateTransaction`,
`signPrivateTransaction`, authority/registry/sync/balance/history APIs. No
stale signing name.

Fixtures/tests: SOL/SPL deposit fields; registered/unregistered SOL/SPL routing;
input selection; authority encryption, approval rejection, P256 signing order;
split divisibility and encrypted bundle; merge input selection, preparation,
material identity and submission; idempotent ATA creation; unsigned custody
message; external signer contract; registration/rotation; indexer lag,
abort/timeout, atomic/repeated sync, balance/history snapshots and nested
errors. Concrete downstream fixtures/tests are
`fx-workflow-action-split-v1`/`e2e-action-split`,
`fx-workflow-action-merge-v1`/`e2e-action-merge-submit`, and
`fx-workflow-action-ata-idempotent-v1`/`e2e-action-ata-idempotent`.

Commands:

```text
npm run test:vectors --workspace @zolana/wallet
npm run test:cross --workspace @zolana/wallet
npm run test:browser --workspace @zolana/wallet
```

Completion evidence: all wallet rows closed; authority secrets never cross to
client/prover; unsigned and signer-convenience message bytes are identical.

## P11 — Private test kit

Prerequisites: P02–P10.

Owned files:

- `sdk-libs/ts/test-kit/src/**`, including its private index;
- `sdk-libs/ts/test-kit/test/**`;
- local TypeScript service lifecycle scripts;
- `sdk-libs/ts/reports/packets/P11.json`.

Source inventory rows: the 12 rows whose `Packet` cell is `P11` in
[inventory-support.md](inventory-support.md).

Exports: only the private test-kit allowlist. Production package indexes remain
untouched.

Fixtures/tests: local stack with port offset and readiness deadlines; fixture
loader; deterministic wallets; fake RPC/indexer/prover shared contracts;
admin, SPL, events, proofless, wallet-data, zone helpers; cleanup and abort.

Commands:

```text
npm run test:unit --workspace @zolana/test-kit
npm run pack:check
npm run test:inventory
```

Completion evidence: isolated stack starts/stops without killing foreign
services; production dependency and tarball scans contain no test-kit.

## P12 — Action-level E2E

Prerequisites: P10, P11.

Owned files:

- `sdk-libs/ts/e2e/actions/**`;
- action E2E result artifacts;
- `sdk-libs/ts/reports/packets/P12.json`.

Source rows and workflows: no inventory row is assigned to P12. This packet
observes wallet action/test rows owned by `P10`, client confirmation rows owned
by `P09`, program localnet/Photon evidence, and the action sections of
[action-and-instruction-api.md](action-and-instruction-api.md).

Exports: none; consume published package entry points only.

Fixtures/tests: SOL/SPL deposit; registered transfer; independent unregistered
SOL and SPL public fallback; SOL/SPL withdrawal; external HSM signer and local
signer convenience; split creation and resulting output count/amounts; merge
creation and merge submission; first-run and already-existing idempotent ATA
creation; authority rejection; abort/timeout; Photon lag; repeated
confirmation/sync; exact public/private/vault/tree/nullifier/history/decryption
assertions. The split, merge, and ATA cases consume the three named
`fx-workflow-action-*` fixtures and run `e2e-action-split`,
`e2e-action-merge-submit`, and `e2e-action-ata-idempotent`.

Forbidden imports: raw instruction fixture helpers, `ConfidentialTransfer`,
`assemble`, `intoProver`, and P13 helpers.

Command:

```text
npm run test:e2e:actions
```

Completion evidence: each action workflow starts from a fresh isolated stack,
submits its own transaction, confirms on Solana and Photon, and records a
machine-readable result.

## P13 — Instruction-level E2E

Prerequisites: P09, P10, P11.

Owned files:

- `sdk-libs/ts/e2e/instructions/**`;
- instruction E2E result artifacts;
- `sdk-libs/ts/reports/packets/P13.json`.

Source rows and workflows: no inventory row is assigned to P13. This packet
observes non-inventoried interface deposit/transact builders, transaction
transfer/proof-input/slot rows owned by `P05`, client
witness/prover/compression rows owned by `P09`, frozen program tests, and
instruction sections of the workflow contract.

Exports: none; consume published package entry points plus test-local native
adapter/assertion utilities.

Fixtures/tests: raw SOL/SPL deposit accounts/bytes and bootstrap tag; spend
selection/conversion; authority encryption/approval; inclusion and
non-inclusion paths; exact prover JSON/result/compression; raw registered
transfer; separate SOL/SPL withdrawal account suffixes; unsigned native
transaction, external signature, submission, confirmation, indexing,
decryption, sync; wrong paths/proofs/accounts/authority and lag/abort negatives.
Frozen vectors assert deposit, transfer, SOL-withdrawal, and SPL-withdrawal
instruction tags, account flags, data bytes, and decoded wire fields:
`nullifierHash`, both root indexes, `treeIndex`, `eddsaSignerIndex`, `OwnerTag`,
optional output `data`, `relayerFee` as `u16`, message `data`, and the 32-byte
P256 `commitment`/`commitmentPok`. The concrete fixture/test pairs are
`fx-workflow-instruction-deposit-v1`/`e2e-instruction-deposit-wire`,
`fx-workflow-instruction-transfer-v1`/`e2e-instruction-transfer-wire`,
`fx-workflow-instruction-withdraw-sol-v1`/`e2e-instruction-withdraw-sol-wire`,
and `fx-workflow-instruction-withdraw-spl-v1`/
`e2e-instruction-withdraw-spl-wire`.

Forbidden imports: wallet action builders (`createDeposit`,
`buildDepositTransaction`, `createTransfer`, `createWithdrawal`,
`buildPrivateTransaction`, `signPrivateTransaction`) and all P12 helpers.

Command:

```text
npm run test:e2e:instructions
```

Completion evidence: every stage has an independently captured value and Rust
fixture comparison; no action-level implementation appears in the call graph.

## P14 — Package integration and API reports

Prerequisites: P02–P13.

Owned files:

- every package API report under `sdk-libs/ts/api-reports/**`;
- root package/export/dependency integration tests;
- shared CI TypeScript jobs and root TypeScript `just` recipes;
- release, provenance, license, and audit scripts;
- `sdk-libs/ts/reports/packets/P14.json`.

Source rows: no inventory row is assigned to P14. Validate all 182 rows against
their direct `P00`, `P01`, `P03`, `P04`, `P05`, `P06`, `P07`, `P08`, `P09`,
`P10`, or `P11` owner, plus architecture and the public export manifest.

Exports: none. Package source indexes remain owned by P02–P11; P14 is the sole
owner of every API report.

Fixtures/tests: mechanically compare all 263 normalized declaration identities
to the declaration ledger, require 263 unique fixture IDs and 263 unique test
IDs, and reject missing/extra/misplaced exports; package graph; fresh packed
Node/browser consumers; 182-row inventory-to-test report; all split, merge,
ATA, action, and instruction E2E jobs; redaction, browser, license, provenance,
and tarball checks. Install from the committed root lockfile and fail if
dependency resolution would change it; P14 validates the lockfile but must not
modify it.

Commands:

```text
npm run check
npm run api:check
npm run pack:check
npm run test:inventory
npm run test:browser
npm run test:e2e:actions
npm run test:e2e:instructions
```

Completion evidence: zero API or inventory discrepancy; a clean post-install
lockfile diff; all release evidence is archived; one owner exists for every
package index, API report, and the root lockfile.

## P15 — Final parity and security review

Prerequisites: P14.

Owned files:

- review records and release notes only;
- `sdk-libs/ts/reports/packets/P15.json`.

Source rows/exports: no inventory row is assigned to P15. Review all 182 rows
under their direct `P00`, `P01`, `P03`, `P04`, `P05`, `P06`, `P07`, `P08`,
`P09`, `P10`, or `P11` owner, all public declarations, workflow stages,
security gates, and P00–P14 evidence.

Fixtures/tests: no new implementation. Re-run clean fixture generation, full
prover matrix, browser and packed consumers, schema/transport cross-tests,
smart-account vectors, and both independent E2Es. Audit secret/authority
boundaries, unsigned custody, confirmation binding, redaction, package release
order, and deliberate deviations.

Commands:

```text
cargo xtask ts-fixtures --check
npm run check
npm run test:inventory
npm run api:check
npm run pack:check
npm run test:prover
npm run test:e2e:actions
npm run test:e2e:instructions
```

Completion evidence: 182 rows closed; all public declarations traced; every
release blocker cleared or the parity claim narrowed; five sign-offs recorded.

## Dependency DAG and safe parallel groups

```text
P00 -> P01
P01 -> P02, P03, P04, P06, P07
P02 + P04 -> P05
P07 -> P08
P02 + P05 + P07 + P08 -> P09
P05 + P09 -> P10
P02..P10 -> P11
P10 + P11 -> P12
P09 + P10 + P11 -> P13
P02..P13 -> P14 -> P15
```

Safe parallel groups:

- Group A after P01: P02, P03, P04, P06, and P07.
- Group B when dependencies resolve: P05 and P08.
- Group C after P11: P12 and P13.

P09 follows P05/P08; P10 follows P09; P11 follows all production packages.
P14 alone owns API reports and shared CI/release integration. It validates the
P01-owned committed lockfile with a clean-diff check and never modifies it. No
parallel packet owns another packet's package index, root lockfile, API report,
E2E directory, result artifact, or packet evidence file.
