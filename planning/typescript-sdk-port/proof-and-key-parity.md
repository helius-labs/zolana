# Proof and key-handling parity certification

## Status and purpose

This document defines the evidence required before the TypeScript SDK may claim parity with Zolana's
canonical proof and key-handling behavior. It is an implementation and release plan, not a parity
attestation.

Audit snapshot:

- branch: `ts-sdk-port`;
- reviewed worktree HEAD: `ff5d05c59ca7ab186796bbc7ff78b82d375cacf3`;
- fixture baseline: `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`;
- review date: 2026-07-25;
- primary specification: [`docs/spec.md`](../../docs/spec.md);
- proof implementation authority: the Go prover, embedded verifying keys, and
  `programs/shielded-pool`;
- Rust SDK reference: `sdk-libs/keypair`, `sdk-libs/transaction`, `sdk-libs/client`, and
  `sdk-libs/wallet`;
- TypeScript implementation: `sdk-libs/ts/keypair`, `sdk-libs/ts/transaction`, `sdk-libs/ts/client`,
  and `sdk-libs/ts/wallet`.

The review loop is active and its checklist holds 145 rows, a denominator raised from 118 on
2026-07-25 by the coverage audit. Do not take a row status from this document: run
`node sdk-libs/ts/config/pkp-entry-gate.mjs` and read
[`review-checklist.md`](review-checklist.md), which is the authority for feature status. The
fixture baseline remains `43fde8e4`. [`remaining-work.md`](remaining-work.md) holds the sequence
that leads here.

The branch is moving. Before implementing a work packet below, refresh the HEAD, fixture revisions,
proving-key lock hash, and affected rows, and check current Rust drift. Evidence from different
revisions must not be combined into one parity claim without an explicit compatibility review.

## Entry criteria and scope

The four criteria below are evaluated by `sdk-libs/ts/config/pkp-entry-gate.mjs`, and
`pkp-entry-watch.sh` polls that gate and wakes the coordinator when it passes, so this phase begins
when the work is ready rather than when somebody notices. Run the gate before starting any packet
here.

Mechanising this was not tidiness. For most of the port's life "CI is green" meant "the four gates
run locally are green", while the 27 jobs on the pull request were skipping because it was a draft; the
first real run then failed eight jobs, two of them genuine defects including a browser bundle that
could not load. Criterion 4 was not merely unmet, it was unmeasured, and prose criteria are what let
that stand for months. The gate distinguishes cannot-decide from refuses for the same reason: an
unreachable GitHub is not evidence of a block.

This document is a post-parity certification overlay. It does not repeat the row inventory or
replace its verdicts. Start PKP-00 only after:

1. the 145 rows have been reviewed, a denominator raised from 118 on 2026-07-25 by the coverage
   audit;
2. actionable adverse rows have been implemented and independently re-reviewed;
3. specification-authority blockers have a recorded decision and matching implementation evidence;
4. full CI, fixture regeneration, browser, packed-package consumer, action E2E, and instruction E2E
   gates pass.

Then execute PKP-00 through PKP-08 in order. A complete proof or key-handling parity claim requires
native Rust verification of TypeScript-produced proof artifacts and real TypeScript prove-to-chain
evidence through the same-revision local stack.

## Decision

Use a native cross-language certification pipeline:

```text
specification and protocol decisions
  -> production Rust and shielded-pool verifier
  -> Rust-generated, versioned fixtures
  -> independent TypeScript implementation
  -> Rust and shielded-pool verification of TypeScript-produced artifacts
  -> local-stack prove, submit, verify, and confirmation tests
```

Do not add production Groth16 verification to the TypeScript SDK. TypeScript owns witness assembly,
prover request construction, proof response parsing, point validation and compression, and
instruction construction. The shielded-pool program owns verifying-key selection and cryptographic
proof verification. Rust tests may expose the same verifier as a test-only oracle.

Do not require full-SDK WASM. A native test oracle gives stronger coverage of the deployed Rust and
shielded-pool behavior without forcing network, process, Solana RPC, wallet, and prover dependencies
through `wasm32`. A narrow test-only WASM adapter may be reconsidered only when it replaces a proven
test bottleneck.

## Authority and conflict policy

Parity is undefined while the authorities disagree. Resolve conflicts before freezing new vectors.

**This is the reconciled order for the port, and it is the only one.** Finding G7-2 recorded that
two orders were written down and differed, the other being "Source precedence" in
[`README.md`](README.md#source-precedence). They are not rival rankings. The README's list decides
which revision of a source to read for the frozen plan and stops at the SDK, so it omits the two
authorities that decide the hardest conflicts, the deployed program and the prover. The list below
is the full one. Where the README appears to disagree, it is the shorter list and this one governs;
the README's tail, the pinned `zolana-examples` workflows and pull request 111, extends this order
below its last level rather than competing with it.

1. accepted protocol decisions recorded in `docs/spec.md`;
2. deployed or release-targeted shielded-pool behavior and circuit constraints;
3. Go prover request and witness behavior;
4. current Rust SDK behavior and Rust tests;
5. generated fixtures;
6. TypeScript behavior and tests;
7. planning inventories and historical review reports;
8. the pinned `zolana-examples` workflows, then pull request 111, as reference material.

This order does not permit silently changing deployed behavior to match prose. When specification
and implementation disagree:

1. name the exact disagreement;
2. identify the deployed/release-targeted behavior;
3. decide whether to update the specification or implementation;
4. test the chosen behavior in Rust and the Solana program where applicable;
5. regenerate fixtures from that revision;
6. update TypeScript;
7. obtain an independent re-review.

The per-conflict ledger that the second half of G7-2 asked for now exists, as
[`authority-rulings.md`](authority-rulings.md). It carries one section per disputed behaviour with
the evidence on each side, the options, the artifacts a change would touch, and a ruling block that
is filled once the owner decides. Read it rather than the summary below, which is a snapshot and
goes stale as rulings land.

Conflicts this document raised, and where each stands in that ledger:

- `docs/spec.md` defines P256 `pk_field` with y-parity, while current Rust, TypeScript, the
  owner-field gadget, and program reconstruction use a parity-free `owner_pk_field` for owner
  identity. Open, as `G7-1`, and the largest of these;
- the specification glossary describes `SPPProof` as a single 192-byte value, while the implemented
  instruction enum has a committed P256 form and an uncommitted Ed25519 form. Open;
- the Merkle source and fixture provenance repair is complete, while the shared frozen fixture
  baseline and legacy interface `sourceCommit` bookkeeping still require explicit revision review.
  Open, and tracked as G8-1 rather than as an authority conflict;
- specification prose and implementation had deposit, protocol-config, and output-slot
  disagreements. The deposit one is ruled: the discovery tag moved to the signing pubkey in both
  languages, applied at `1ff51a4c` and `114a5140`.

No fixture generated from a disputed behavior may be labelled canonical.

## Definition of parity

A capability has parity only when the conditions that apply to it hold:

1. Rust and TypeScript accept and reject the same logical inputs.
2. They produce the same logical values and exact protocol bytes.
3. They preserve the same ordering, optional-value, zero-sentinel, and numeric rules.
4. They report compatible stable error codes and structured safe details at the same boundary.
5. Rust-generated fixtures call production Rust functions rather than duplicate protocol
   mathematics.
6. TypeScript tests call the public TypeScript interface rather than fixture or test-only
   implementations.
7. TypeScript-produced signatures verify in Rust and Rust-produced signatures verify in TypeScript.
8. TypeScript-produced proof artifacts are accepted by the release-targeted Rust and shielded-pool
   verifier.
9. Required mutations are rejected at the expected layer.
10. Browser and Node behavior agree for browser-capable packages.
11. Secret ownership, copying, destruction, capability separation, and redaction rules agree with
    the documented threat model.
12. The fixture, prover, circuit, verifying-key, program, Rust, and TypeScript revisions are
    recorded together.

Passing unit tests, matching one happy-path vector, successful proof parsing, or successful point
compression is not proof verification and does not establish parity.

## Rust-to-TypeScript feature map

This map covers the proof and key-handling responsibilities certified by this overlay. The package
inventories and [`review-checklist.md`](review-checklist.md) remain authoritative for interface,
transaction, client, wallet, API, indexer, Merkle tree, and smart-account behavior.

The status labels mean:

- `strong`: TypeScript implements the feature and frozen Rust fixtures cover its primary byte-level
  behavior;
- `partial`: TypeScript implements the main behavior, but a type, rail, runtime, adversarial case,
  or verification layer is missing;
- `missing`: the Rust responsibility has no corresponding TypeScript implementation;
- `Rust/Solana`: the responsibility stays in Rust or the shielded-pool program by design.

These labels describe the evidence at the audit snapshot. They are not release verdicts.

### Key-handling map

#### Constants and domains

- Rust: `sdk-libs/keypair/src/constants.rs`
- TypeScript: `sdk-libs/ts/keypair/src/constants.ts`
- Status: `strong`
- Covered behavior: byte lengths, domain separators, and the committed P256 `P_CONST_SEC1`.
- Remaining evidence: independently derive the committed point from the specified hash-to-curve
  procedure.

#### Transfer encryption primitives

- Rust: `sdk-libs/keypair/src/encryption.rs`
- TypeScript: `sdk-libs/ts/keypair/src/encryption.ts`
- Status: `strong`
- Covered behavior: P256 ECDH, HKDF-SHA256, AES-256-CTR, slot key derivation, nonce use, and golden
  decryption.
- Remaining evidence: browser execution, slot boundaries, multi-block plaintext, and the complete
  wrong-key/salt/slot mutation set.

#### Hashing and owner identity

- Rust: `sdk-libs/keypair/src/hash.rs`
- TypeScript: `sdk-libs/ts/keypair/src/hash.ts`
- Status: `partial`
- Covered behavior: Poseidon, `hash_field`, big-endian 128-bit splitting, SHA-256 variants, and the
  implemented owner hash.
- Blocker: `docs/spec.md` describes a parity-sensitive P256 `pk_field`, while current Rust,
  TypeScript, the owner-field gadget, and program reconstruction use parity-free `owner_pk_field`
  for owner identity.

#### Merge verifiable encryption

- Rust: `sdk-libs/keypair/src/merge.rs`
- TypeScript: `sdk-libs/ts/keypair/src/merge/core.ts` and `sdk-libs/ts/keypair/src/merge/index.ts`
- Status: `partial`
- Covered behavior: merge ECDH, Poseidon KDF inputs, AES-CTR encryption/decryption, public
  contribution, and ciphertext hash.
- Remaining evidence: proof-level checks, complete tamper cases, and real merge/merge-zone
  verification.

#### Nullifier keys

- Rust: `sdk-libs/keypair/src/nullifier_key.rs`
- TypeScript: `sdk-libs/ts/keypair/src/nullifier-key.ts`
- Status: `strong`
- Covered behavior: nullifier-secret HKDF, public-key derivation, nullifier derivation, and frozen
  byte vectors.
- Remaining evidence: malformed field boundaries, duplicate insertion behavior, and dummy versus
  address-slot cases.

#### Public keys and signature rails

- Rust: `sdk-libs/keypair/src/pubkey.rs`
- TypeScript: `sdk-libs/ts/keypair/src/public-key.ts`
- Status: `partial`
- Covered behavior: P256 compressed SEC1 parsing, Ed25519 representation, scheme prefix, padding,
  owner tags, and owner public-key fields.
- Blocker: the runtime representation is 34 bytes, but current TypeScript signatures describe
  `ShieldedPublicKey.fromBytes` and `toBytes` with a 33-byte static type.

#### Signing and verification

- Rust: `sdk-libs/keypair/src/signing_key.rs`
- TypeScript: `sdk-libs/ts/keypair/src/signing-key.ts`
- Status: `partial`
- Covered behavior: P256 and Ed25519 key construction, signing, verification, secret-byte access,
  and fixed Rust vectors.
- Remaining evidence: Rust-to-TypeScript and TypeScript-to-Rust signature tests, explicit P256
  high-S policy, scalar boundary cases, and Ed25519 canonical-encoding compatibility.

#### Shielded addresses and aggregate keypairs

- Rust: `sdk-libs/keypair/src/shielded.rs`
- TypeScript: `sdk-libs/ts/keypair/src/shielded.ts`
- Status: `partial`
- Covered behavior: shielded and compressed addresses, owner hashes, tags, signatures, nullifiers,
  and P256/Ed25519 ownership rails.
- Remaining evidence: complete public API equivalence, secret lifecycle behavior, and
  capability-based substitution.

#### Viewing and transaction-viewing keys

- Rust: `sdk-libs/keypair/src/viewing_key.rs`
- TypeScript: `sdk-libs/ts/keypair/src/viewing-key.ts`
- Status: `strong`
- Covered behavior: viewing-root derivation, ECDH, sender/request/shared/merge tag streams,
  transaction viewing-key derivation, random salt, and random blinding.
- Remaining evidence: counter boundaries, viewing-key epochs, zero-scalar handling, and transaction
  viewing-key reuse tests.

#### Key capability traits

- Rust: `sdk-libs/keypair/src/traits/shielded_keypair.rs` and
  `sdk-libs/keypair/src/traits/view_key.rs`
- TypeScript target: `ShieldedKeypairLike`, `ViewingKeyLike`, wallet-authority, and signer
  interfaces
- Status: `missing`
- Required behavior: local, HSM, remote, viewing-only, nullifier-only, and native transaction signer
  implementations must be substitutable without exposing unrelated secret material.

#### Key errors and secret lifecycle

- Rust: `sdk-libs/keypair/src/error.rs` and secret-owning key types
- TypeScript: `sdk-libs/ts/keypair/src/error.ts` and `destroy()` implementations
- Status: `partial`
- Covered behavior: stable keypair error classes, defensive copies in several public types, and
  best-effort destruction.
- Remaining evidence: one-to-one error categories, nested-cause redaction, mutation-after-input and
  mutation-after-return tests, destroyed-object behavior, and documented JavaScript erasure limits.

### Proof map

#### Proof parsing and compression

- Rust: `sdk-libs/client/src/prover/proof.rs`
- TypeScript: `sdk-libs/ts/client/src/prover/proof.ts`
- Status: `strong`
- Covered behavior: gnark response parsing, proof A negation, G1/G2 validation and compression,
  BSB22 commitment parsing, commitment proof-of-knowledge parsing, and committed/uncommitted proof
  variants.
- Remaining evidence: a generated valid-point corpus and broader malformed-point mutations.

#### Field and byte conversion

- Rust: `sdk-libs/client/src/prover/field.rs`
- TypeScript: field helpers in `sdk-libs/ts/client/src/prover/types.ts` and
  `sdk-libs/ts/client/src/prover/assembly.ts`
- Status: `partial`
- Covered behavior: BN254 field representation, big-endian conversion, right alignment, and Poseidon
  inputs used by covered confidential vectors.
- Remaining evidence: complete range rejection and property comparison against Rust.

#### Confidential prover input types

- Rust: `sdk-libs/client/src/prover/inputs.rs`
- TypeScript: `sdk-libs/ts/client/src/prover/types.ts`
- Status: `partial`
- Covered behavior: transfer inputs, outputs, common transfer inputs, and P256 transfer inputs.
- Missing behavior: zone and zone-authority input variants.

#### Confidential witness and public-input assembly

- Rust: `sdk-libs/client/src/prover/transact/witness.rs`,
  `sdk-libs/client/src/prover/transact/eddsa.rs`, and
  `sdk-libs/client/src/prover/transact/p256_and_eddsa.rs`
- TypeScript: `sdk-libs/ts/client/src/prover/assembly.ts`
- Status: `strong` for the covered confidential fixtures and `partial` for the supported shape/rail
  certification target
- Covered behavior: real and dummy transfer inputs, outputs, root/nullifier ordering, public
  amounts, private transaction hash, external-data hash, Ed25519 rail, and P256 rail.
- Remaining evidence: named intermediate values across the complete shape set, mixed-owner cases,
  and Rust verification of TypeScript-produced proofs.

#### Zone transact assembly

- Rust: `sdk-libs/client/src/prover/transact/zone_eddsa.rs` and
  `sdk-libs/client/src/prover/transact/zone_p256.rs`
- TypeScript target: zone variants in `sdk-libs/ts/client/src/prover/types.ts`, `assembly.ts`, and
  `client.ts`
- Status: `missing`
- Required behavior: anonymous owner tags, non-zero zone program field, zone-specific public-input
  chain, Ed25519 rail, P256 rail, and zone prover request serialization.

#### Zone-authority assembly

- Rust: `sdk-libs/client/src/prover/zone_authority.rs`
- TypeScript target: zone-authority inputs, assembly, and prover serialization under
  `sdk-libs/ts/client/src/prover/`
- Status: `missing`
- Required behavior: 1x1, 2x2, 3x3, and 4x4 shapes; private input owner fields; uncommitted proof
  format; and the strict non-zero zone program rule.

#### Prover request serialization and transport

- Rust: `sdk-libs/client/src/prover/json.rs` and `sdk-libs/client/src/prover/client.rs`
- TypeScript: `sdk-libs/ts/client/src/prover/client.ts`
- Status: `partial`
- Covered behavior: prover request generation, fetch transport, confidential proving, merge proving,
  merge-zone proving, retries, response parsing, and proof compression.
- Remaining evidence: zone requests, zone-authority requests, exact malformed-response parity, and a
  TypeScript-driven live prover suite.
- Deliberate difference: Rust may spawn a local prover process. Browser TypeScript uses a configured
  HTTP prover and does not expose process spawning.

#### Default merge

- Rust: `sdk-libs/client/src/prover/merge.rs`
- TypeScript: `sdk-libs/ts/client/src/prover/merge.ts` and `client.ts`
- Status: `partial`
- Covered behavior: merge material assembly, 8x1 witness shape, request generation, and proof
  response conversion.
- Remaining evidence: exact named public-input values, final public-input hash assertions,
  TypeScript-produce/Rust-verify tests, and a real shielded-pool execution.

#### Merge-zone

- Rust: `sdk-libs/client/src/prover/merge_zone.rs`
- TypeScript: `sdk-libs/ts/client/src/prover/merge.ts` and `client.ts`
- Status: `partial`
- Covered behavior: merge-zone material assembly, request generation, and proof response conversion.
- Remaining evidence: exact zone owner/tag/hash values, Rust verification, and a real shielded-pool
  execution.

#### Groth16 verification

- Rust and Solana: `programs/shielded-pool/src/instructions/verifier.rs`,
  `programs/shielded-pool/src/instructions/transact/verify.rs`, and
  `programs/shielded-pool/src/instructions/merge/verify.rs`
- TypeScript: no production verifier
- Status: `Rust/Solana`
- Responsibility: the shielded-pool program selects the embedded verifying key, decompresses proof
  points, checks commitment presence against the key, and verifies the pairing for the supplied
  public-input hash.
- TypeScript responsibility: assemble the witness/request, parse and compress the proof, and
  serialize the instruction. A test-only Rust oracle must verify TypeScript-produced artifacts
  during certification.

### Certification sequence

The map becomes a parity claim only after this sequence succeeds:

1. production Rust generates versioned fixtures with source, prover, circuit, key, and program
   revisions;
2. TypeScript independently computes the named values and exact protocol bytes;
3. cross-language tests verify signatures in both directions;
4. the test-only Rust oracle verifies TypeScript-produced proof artifacts;
5. the shielded-pool program processes a real TypeScript-built transaction;
6. the local indexer and wallet tests confirm the expected state, decryption, and sync result.

## Threat model

Certification must cover these adversaries and failure sources:

- malformed or malicious prover responses;
- a prover returning a valid proof for different public inputs;
- a proof paired with the wrong rail, shape, zone mode, or verifying key;
- malicious or malformed Photon inclusion and non-inclusion proofs;
- tampered account order, signer flags, owner tags, settlement accounts, or instruction data;
- signature malleability or different canonical-encoding policies;
- malformed, zero, out-of-range, or wrong-curve keys;
- reused randomness, salts, transaction viewing keys, or slot indexes;
- mutable aliasing of key or witness bytes;
- accidental disclosure through errors, logs, traces, JSON, snapshots, URLs, or approval summaries;
- a remote authority, HSM, or signer receiving more capability than required;
- browser and Node crypto implementations accepting different inputs;
- stale proving/verifying keys or fixture provenance;
- tests that pass because proving, verification, signing, indexing, or submission is stubbed.

## Confirmed proof architecture

### Responsibility split

The proof pipeline has distinct interfaces:

1. `@zolana/transaction` constructs deterministic transaction and UTXO values.
2. `@zolana/client` validates indexed paths and assembles prover inputs.
3. `@zolana/client` serializes the prover request and parses the gnark response.
4. TypeScript negates proof A, validates curve points, and compresses the proof.
5. `@zolana/interface` serializes the proof into instruction data.
6. The shielded-pool program recomputes the public-input hash, selects the verifying key,
   decompresses points, and verifies the pairing.

The TypeScript SDK must not claim that `parseProof` or `compressProof` verifies a Groth16 proof.
Cryptographic verification occurs in `programs/shielded-pool/src/instructions/verifier.rs`.

### Proof encodings

Confirmed implemented forms:

- uncompressed G1: 64 bytes, big-endian `X || Y`;
- uncompressed G2: 128 bytes, big-endian `X.c0 || X.c1 || Y.c0 || Y.c1`;
- compressed G1: 32 bytes;
- compressed G2: 64 bytes;
- proof A is negated when parsing the gnark response;
- proof C, the BSB22 commitment, and commitment proof-of-knowledge are not negated;
- the P256 rail contains A, B, C, one commitment, and one commitment proof-of-knowledge;
- the Ed25519 and zone-authority rails carry A, B, and C only;
- proof commitment presence must match the selected verifying key.

### Circuit families

Certification must give each family an independent fixture and verification identity:

- confidential transact, Ed25519 rail;
- confidential transact, P256 rail;
- anonymous zone transact, Ed25519 rail;
- anonymous zone transact, P256 rail;
- zone-authority transact;
- default merge;
- merge-zone.

Confidential and zone transact must cover the supported shape set:

- 1 input, 1 output;
- 1 input, 2 outputs;
- 2 inputs, 2 outputs;
- 2 inputs, 3 outputs;
- 3 inputs, 3 outputs;
- 4 inputs, 3 outputs;
- 4 inputs, 4 outputs;
- 5 inputs, 3 outputs;
- 5 inputs, 4 outputs;
- 1 input, 8 outputs.

Zone-authority must cover its supported 1x1, 2x2, 3x3, and 4x4 shapes. Default merge and merge-zone
use the 8x1 shape with dummy input coverage for fewer real inputs.

### Current proof evidence

Currently strong:

- confidential Ed25519 and P256 public-input assembly for covered vectors;
- confidential prover JSON for the supported shape set;
- gnark proof parsing;
- A negation;
- G1/G2 compression for frozen vectors;
- committed versus uncommitted rail packing;
- Rust client integration tests that prove and verify against embedded keys;
- verifying-key selection and commitment-format rejection in the shielded-pool program;
- Merkle behavior and provenance under the completed M01 and M02 checklist rows;
- merge-zone interface codec and builder parity under I09 and I21; and
- implemented TypeScript merge-zone prepare, prove, assemble, and submit paths, without a
  certification verdict for T28.

Currently incomplete or absent:

- TypeScript zone and zone-authority prover input variants;
- TypeScript zone and zone-authority prover requests;
- complete zone, zone-authority, merge, and merge-zone certification fixtures;
- a TypeScript-driven live prover test whose resulting proof is checked by the Rust and
  shielded-pool verifier;
- a local-stack TypeScript prove-to-submit transaction with a real proof;
- tampered public-input and wrong-verifying-key tests driven from TypeScript;
- complete evidence that merge public-input bytes are asserted by TypeScript;
- property coverage comparing TypeScript G2 compression with Rust over a generated valid-point
  corpus.

## Proof certification suites

### P1. Public-input assembly

For each family, rail, shape, and required mixed-owner case:

- construct one canonical logical input document;
- assemble it through production Rust;
- assemble it independently through public TypeScript interfaces;
- compare each named intermediate, not only the final hash;
- compare the final `public_input_hash`;
- compare real and dummy input/output placement;
- compare root and nullifier ordering;
- compare public amount sign encoding;
- compare owner fields and owner-tag chains;
- compare payer and asset fields;
- compare zone program handling;
- compare private transaction and external-data hashes.

The fixture must preserve named intermediate values so a failing final hash identifies the first
divergent layer.

Required confidential chain assertions include:

- nullifier chain;
- output hash chain;
- UTXO root chain;
- nullifier-root chain;
- private transaction hash;
- P256 message digest field, or zero on the Ed25519 rail;
- external-data hash;
- public SOL and SPL amounts;
- public SPL asset field;
- zero zone field;
- payer field;
- input owner chain;
- output owner chain;
- P256 signing field, or zero on the Ed25519 rail.

Zone fixtures must assert the shorter anonymous chain and non-zero zone field. Zone-authority
fixtures must assert that input owner fields are private and absent from the public hash. Merge
fixtures must assert the distinct default and zone owner-binding tails.

### P2. Prover request parity

For each public-input fixture:

- compare exact `circuitType`;
- compare exact JSON key names and omission/null behavior;
- compare field encoding and array order;
- compare dummy witness encoding;
- compare P256 point limbs and signatures;
- compare Merkle and non-inclusion paths;
- compare merge ciphertext, public contribution, and zone fields;
- reject unknown fields and malformed field values;
- record the prover protocol revision.

Request snapshots must be generated from Rust production serializers. Tests must not hand-author a
second representation of the Rust request.

### P3. Proof response parsing and compression

Maintain frozen valid vectors for:

- vanilla Groth16;
- BSB22 committed Groth16;
- zero/identity points only where the verifier accepts them;
- leading-zero coordinates;
- parity-bit boundaries;
- G2 points with each valid parity branch.

Maintain rejection vectors for:

- missing or extra coordinate rows;
- malformed hexadecimal strings;
- values at or above the BN254 base modulus;
- off-curve G1 or G2 points;
- truncated and extended points;
- unknown response fields;
- only one of commitment or commitment PoK present;
- commitment present on an uncommitted rail;
- commitment absent on a committed rail.

Compare Rust and TypeScript uncompressed bytes, negated A, compressed A/B/C, commitment bytes, PoK
bytes, proof variant, and stable error category.

### P4. Cryptographic verification

For each family and supported shape:

1. build witness and request with TypeScript;
2. submit to the pinned local prover;
3. parse and compress with TypeScript;
4. pass the TypeScript artifact and public-input hash to a test-only Rust verifier using the
   embedded release-targeted key;
5. require successful verification;
6. build the production instruction with TypeScript;
7. execute it against the same-revision shielded-pool program;
8. require the expected state transition.

The test-only verifier must call the same `groth16-solana` verification path and embedded keys as
program/client tests. It must not reimplement pairings.

For each successful proof, independently require rejection after:

- flipping one bit in A, B, or C;
- flipping one bit in the commitment or PoK when present;
- changing the public-input hash;
- selecting the wrong shape key;
- selecting the wrong confidential/zone key;
- selecting the wrong P256/Ed25519 rail;
- adding a commitment to an uncommitted proof;
- removing a commitment from a committed proof;
- changing the zone program;
- changing a nullifier, output hash, root, payer, public amount, owner tag, or external-data field
  and rebuilding only the instruction.

Classify failures as encoding, rail mismatch, or verification failure. Do not assert unstable
library message text.

### P5. End-to-end proof flows

At least one real transaction per family must run through:

```text
TypeScript wallet intent
  -> authority approval and private authorization
  -> TypeScript witness assembly
  -> pinned local prover
  -> TypeScript proof parse/compress
  -> TypeScript instruction and native transaction
  -> local validator
  -> verification and state transition in the shielded-pool program
  -> Photon/local indexer observation
  -> recipient and sender sync
```

The test must assert:

- selected inputs and outputs;
- exact public-input hash;
- exact program ID, account order, flags, and instruction bytes;
- proof rail and shape;
- Solana success or expected typed failure;
- inserted nullifiers and output commitments;
- external SOL/SPL balance changes;
- indexed signature and complete output-tag set;
- successful decryption by intended recipients;
- rejection by unrelated keys;
- idempotent repeated confirmation and wallet sync.

No prover, verification, signing, submission, confirmation, or indexing stub may satisfy this gate.

## Confirmed key architecture

### Key roles

Keep these capabilities distinct:

- signing key: spend authorization;
- nullifier key: nullifier-secret derivation and spend nullifiers;
- viewing key: ECDH decryption and view-tag derivation;
- transaction viewing key: one-transaction ECDH context;
- Solana fee-payer/native signer: native transaction authorization;
- wallet authority: least-privilege orchestration over the preceding capabilities.

Possession of one capability must not imply possession of another.

### Encodings and derivations

Confirmed implemented conventions requiring certification:

- scheme-tagged `PublicKey` is 34 bytes;
- P256 public key body is 33-byte compressed SEC1;
- Ed25519 body is 32 bytes plus the tagged representation's required padding;
- P256 confidential owner tag is the x-coordinate;
- Ed25519 confidential owner tag is the full 32-byte public key;
- P256 full `pk_field` includes y-parity;
- current owner identity uses parity-free `owner_pk_field`;
- nullifier secret is HKDF-SHA256 output of length 31;
- nullifier public key and nullifier formulas use Poseidon;
- viewing keys are P256;
- transaction viewing keys derive from the first nullifier and viewing secret;
- transfer encryption uses P256 ECDH, HKDF-SHA256, and AES-256-CTR;
- key derivation includes both public keys, transaction salt, and big-endian slot index;
- CTR begins with the implemented counter value;
- merge verifiable encryption uses its separate Poseidon KDF and ciphertext hash contract;
- default-zone outputs use owner signing-key tags;
- anonymous-zone outputs use derived view tags;
- merge-zone uses its merge view-tag stream;
- `merge_transact` uses the default-zone owner tag.

### Current key evidence

Currently strong for frozen vectors:

- P256 and Ed25519 public-key encoding;
- fixed-vector signing and verification;
- owner fields and owner hashes as currently implemented;
- nullifier derivation;
- viewing-root and view-tag derivation;
- transaction viewing-key derivation;
- transfer ECDH/HKDF/AES encryption;
- merge verifiable encryption;
- random salt and blinding lengths;
- several wrong-key, wrong-slot, and tamper cases.

Currently incomplete or disputed:

- specification wording for owner identity;
- explicit cross-library P256 low-S acceptance policy;
- adversarial Ed25519 canonical-encoding policy;
- one-to-one key error taxonomy;
- TypeScript's 34-byte runtime key represented by a 33-byte static type;
- complete `ViewingKeyLike` and `ShieldedKeypairLike` capability interfaces;
- HSM/remote authority substitution evidence;
- secret lifecycle guarantees and documented JavaScript limitations;
- complete error/cause redaction tests;
- browser execution evidence for the full key suite;
- several Rust public keypair capabilities absent from TypeScript;
- exhaustive equivalence of scalar derivation from 48-byte HKDF output.

## Key certification suites

### K1. Public-key encoding and parsing

For P256 and Ed25519:

- compare tagged and untagged byte lengths;
- compare prefix, padding, compressed SEC1, x-coordinate, and parity;
- round-trip Rust bytes through TypeScript and TypeScript bytes through Rust;
- compare equality and zero-sentinel behavior;
- reject the 254 byte values outside the two defined prefixes;
- reject wrong lengths from 0 through the nearest valid boundaries;
- reject non-zero Ed25519 padding;
- reject invalid, noncanonical, and off-curve P256 points;
- verify returned arrays are owned copies.

Fix the TypeScript `ShieldedPublicKey.fromBytes` and `toBytes` static types to represent 34 bytes
before certifying this interface.

### K2. P256 signing and verification

Use a shared message/signature corpus containing:

- valid deterministic signatures;
- minimum and maximum valid private scalars;
- zero and out-of-range private scalars;
- malformed compact signatures;
- `r = 0`, `s = 0`, and values at or above the group order;
- low-S signatures;
- mathematically equivalent high-S signatures;
- altered messages and public keys;
- wrong-curve and wrong-rail keys.

For each valid case:

- Rust signs and Rust verifies;
- Rust signs and TypeScript verifies;
- TypeScript signs and Rust verifies;
- TypeScript signs and TypeScript verifies;
- compact `r || s` bytes and canonicalization policy are recorded.

The release must choose and document one high-S policy. Do not infer Rust's policy from one vector
or TypeScript's explicit `lowS` option. Test both acceptance and generation behavior directly
against the circuit and SDK libraries.

P256 transaction authorization must separately prove:

- the owner signs the final private transaction hash;
- the circuit verifies against `SHA-256(private_tx_hash)`;
- SPP recomputes the digest and includes it in the proof inputs;
- changing any approved transaction field invalidates authorization.

### K3. Ed25519 signing and verification

Use a shared corpus containing:

- valid signatures from Rust and TypeScript;
- empty, 32-byte, and variable-length messages where the public interface allows them;
- altered message, signature, and public key;
- noncanonical scalar and point encodings;
- small-order public keys and edge cases relevant to ZIP-215 behavior;
- wrong-rail signatures.

Record the precise `ed25519-dalek` and `@noble/curves` acceptance policy. The TypeScript
`zip215: false` setting must be proven compatible with the selected Rust policy rather than assumed.

For Solana-owner transactions, separately prove that:

- the instruction signer index names the intended account;
- the account is a native transaction signer;
- the circuit receives the correct public owner field;
- the P256 commitment/signature path is not selected;
- changing account order or signer flags fails.

### K4. Nullifier derivation and binding

Compare:

- signing-secret-to-nullifier-secret HKDF inputs and label;
- 31-byte output and field alignment;
- nullifier public key;
- UTXO hash, blinding, and nullifier-secret input order;
- nullifier output;
- repeated derivation determinism.

Reject or distinguish:

- wrong signing key;
- wrong blinding length;
- wrong UTXO hash length;
- malformed field inputs;
- altered HKDF label;
- duplicate real nullifier insertion;
- dummy and address-slot confusion.

End-to-end proof tests must demonstrate that knowing the nullifier secret is bound into `owner_hash`
and that the public nullifier matches the spent UTXO.

### K5. Viewing and transaction-viewing keys

Compare:

- committed `P_const` with the specified hash-to-curve derivation;
- ECDH x-coordinate;
- `view_root`;
- each defined HKDF label and output;
- sender, recipient-shared, recipient-request, first-transfer sender-key discovery, and merge tags;
- directional shared-tag agreement;
- counter encoding and boundaries;
- transaction viewing secret;
- first-nullifier salt;
- derived transaction viewing scalar and public key.

Test:

- counter 0, 1, and maximum supported values;
- both sender/recipient directions;
- wrong counterparty;
- rotated viewing epochs;
- zero-scalar derivation handling;
- retry behavior with the same first nullifier and a fresh transaction salt;
- no accidental transaction-viewing-key reuse.

The TypeScript suite must independently prove that the committed `P_const` matches the specified
hash-to-curve result, not merely copy the Rust constant.

### K6. Transfer encryption

Compare exact values for:

- sender transaction viewing key;
- recipient viewing key;
- ECDH shared x-coordinate;
- input key material order;
- HKDF info and output;
- AES key;
- nonce;
- initial CTR counter;
- ciphertext;
- decrypted plaintext.

Exercise:

- each ciphertext slot position used by transfer, split, and messages;
- boundary slot indexes and big-endian encoding;
- same plaintext in different slots;
- same keys with different salts;
- wrong key, salt, slot, ephemeral key, and recipient key;
- bit flips, truncation, and extension;
- empty and multi-block plaintext;
- UTXO-hash integrity check after decryption.

Decrypted plaintext must not enter wallet state until its recomputed UTXO hash matches the
proof-verified output commitment.

### K7. Merge verifiable encryption

Compare exact:

- P256 ECDH values;
- Poseidon domain separators;
- key-schedule context;
- AES key halves and ordering;
- nonce;
- CTR counter;
- plaintext;
- ciphertext;
- ciphertext hash;
- transaction viewing public key;
- public contribution values.

Require the merge proof to check:

- input owner uniformity;
- nullifier secret;
- asset uniformity;
- amount conservation;
- output owner;
- registered viewing key or zone binding;
- transaction viewing key consistency;
- ciphertext hash and output hash.

Reject wrong owner, viewing key, asset, amount, zone, ciphertext, hash, and transaction viewing key.

### K8. Secret ownership and lifecycle

For each secret-bearing TypeScript constructor and method:

- mutate the caller's input after construction and prove internal state is unchanged;
- mutate returned bytes and prove internal state is unchanged;
- destroy the object and prove its public operations reject;
- prove repeated destruction is safe;
- inspect enumerable properties and standard serialization;
- inspect thrown errors and nested causes;
- run failure paths that allocate intermediate ECDH, HKDF, AES, and scalar buffers;
- document buffers that JavaScript or crypto libraries may copy and cannot guarantee to erase.

For Rust:

- verify secret-returning methods use owned zeroizing buffers where promised;
- review clone and drop behavior;
- test redacted `Debug` and error output;
- record any deliberate inability to guarantee erasure.

Fixtures may contain fixed secrets only when marked `testOnlySecret: true`. Examples, snapshots,
release reports, and failure output must exclude production-like secrets.

### K9. Capability and HSM boundaries

Create conformance adapters for:

- local in-memory authority;
- asynchronous mock HSM;
- remote/custodial signer;
- viewing-only authority;
- native Solana transaction signer.

Prove that:

- viewing capability cannot sign or derive spend nullifiers;
- signing capability cannot decrypt;
- nullifier capability cannot sign or decrypt;
- the transaction signer receives no shielded secrets;
- client and prover interfaces receive finalized witness/request values, not a local key container;
- approval receives only the final public summary;
- remote failures do not expose request or witness bodies;
- asynchronous implementations preserve the same values and call ordering as the local adapter.

The public TypeScript capability interfaces must be sufficient for substitution without requiring
concrete `ViewingKey` or `ShieldedKeypair` instances.

### K10. Error and redaction parity

Build a closed cross-language error ledger covering:

- invalid secret/public key;
- zero scalar;
- wrong signature type;
- malformed signature;
- HKDF failure;
- Poseidon/field failure;
- invalid ciphertext;
- wrong slot or salt;
- destroyed key;
- unsupported capability.

For each case compare:

- stable code;
- safe structured details;
- boundary at which the error occurs;
- wrapped dependency category;
- JSON/inspection representation;
- absence of secret key, shared secret, witness, ciphertext plaintext, request body, and raw
  crypto-library cause.

Messages and stack text are not parity surfaces.

## Shared fixture contract

Extend the existing manifest rather than introduce a second fixture root.

Each proof/key fixture must record:

- schema and fixture version;
- stable fixture and test IDs;
- canonical source path and symbol;
- specification section;
- inventory/review row;
- Rust source revision;
- TypeScript revision used for certification;
- prover revision and circuit type;
- proving-key release and lock hash;
- verifying-key module and SHA-256;
- program revision;
- logical inputs;
- expected logical outputs;
- exact bytes as lower-case even-length hexadecimal;
- decimal strings for values outside safe JavaScript integer range;
- expected stable error code and safe details;
- `testOnlySecret: true` where applicable;
- required mutations and expected rejection layer.

Fixture generation requirements:

- call production Rust functions;
- do not duplicate protocol formulas in the generator;
- inject fixture randomness as explicit input;
- sort object keys and manifest paths;
- produce identical output on two consecutive runs;
- verify the hash of each generated file;
- fail when source revisions drift;
- generate into a temporary directory for `--check`;
- keep fixture writes out of ordinary tests.

The verifying-key module and its SHA-256 are a gate, not bookkeeping.
`provingKeyRelease` in the shared manifest pins a lock file path and hash, which
records the proving keys; the proof fixtures record no verifying key, so
rotating one would leave them passing against a key that no longer verifies
their proofs
([G8-2](production-readiness-issues.md#g8-2-verifying-key-provenance-is-not-tied-to-the-fixtures-high)).
The fixture gate compares the recorded identity against the key the verifier
loads and fails on a mismatch instead of reporting drift.

Fixture consumption requirements:

- TypeScript validates shape before use;
- Rust test consumers deserialize committed fixtures where this catches cross-language contract
  drift;
- both languages report the fixture ID on failure;
- no test derives the expected bytes using the implementation under test;
- fixture helpers do not normalize malformed inputs into valid ones.

## Test harness design

Add one test-only native Rust oracle with a narrow JSON interface. It should support:

- `verify-proof`: proof variant, compressed points, public-input hash, family/rail/shape, and
  expected verifying-key identity;
- `verify-signature`: scheme, public key, message, and signature;
- `derive-key-vector`: deterministic key derivations from explicit test input;
- `decrypt-vector`: deterministic transfer or merge decryption;
- `describe-vk`: verifying-key identity and hash.

The oracle must:

- call production Rust/public program verification functions where possible;
- accept raw fixed test secrets only in test mode;
- read one bounded request and return one bounded result;
- return stable codes rather than debug strings;
- run locally with network disabled;
- be excluded from published crates and npm packages.

Use it from Vitest only for certification and adversarial corpora. Normal TypeScript unit tests
remain independent and fixture-driven.

## CI and release gates

### Fast pull-request gate

Run:

- Rust keypair and proof parsing/compression tests;
- fixture manifest and clean regeneration check;
- TypeScript keypair/client vector tests;
- TypeScript property and mutation tests that require no prover;
- native oracle cross-signature and proof-encoding tests;
- browser key/proof-conversion tests;
- export, dependency, and packed-package checks;
- secret scanning of test output and artifacts.

### Prover integration gate

Run on changes to proof assembly, circuits, prover schemas, keys, transaction hashing, or fixtures:

- build/start the pinned local prover;
- one prove-and-Rust-verify case per family, rail, and shape;
- the required public-input and proof mutations;
- proving/verifying-key provenance checks.

### Local-stack acceptance gate

Run:

- one real action-level and one instruction-level flow per supported family;
- SOL and SPL settlement where applicable;
- P256, Ed25519, and mixed-owner cases;
- registered and unregistered routing;
- merge and merge-zone;
- zone and zone-authority;
- confirmation and wallet sync without behavior-hiding stubs.

### Release gate

Block release when any of these is true:

- unresolved specification/implementation conflict affects the capability;
- fixture provenance is stale or mixed without review;
- any required certification cell is missing;
- any proof family, rail, or shape lacks verification evidence;
- any cross-language signature direction is untested;
- any malformed/canonical key policy differs;
- any secret-bearing error or artifact is unredacted;
- any public key/capability interface has a known type mismatch;
- any proving or verification path is stubbed;
- browser and Node behavior differ;
- the public-export ledger or package gate fails;
- an adverse `PARTIAL`, `DIVERGENT`, `STALE`, or `BLOCKED` review verdict remains for the claimed
  capability.

## Implementation work packets

These packets begin after the entry criteria pass. Their status does not change
a checklist row; record row changes in
[`review-checklist.md`](review-checklist.md) through its fix and independent
re-review workflow.

### Findings these packets already own

Seven of the 26 findings in
[`production-readiness-issues.md`](production-readiness-issues.md#scheduling)
describe work these packets carry. They are listed here so a reader can see that
the register schedules them onto the PKP set rather than opening a second track
beside it. Two more findings are resolved by PKP-00 as authority rulings.

| Packet | Findings it closes |
| --- | --- |
| PKP-00 | G7-1 owner-hash encoding conflict; G7-2 the two authority orders and the missing per-conflict ledger |
| PKP-01 | G8-2 verifying-key identity per proof fixture; extends the G8-1 revision-compatibility rule to proof and key fixtures |
| PKP-02 | G2-1 P256 high-S policy through K2; G2-2 Ed25519 acceptance policy through K3; certifies the G1-3 34-byte type through K1 |
| PKP-04 | G6-3 custody seam through K9; certifies the G6-1 secret-lifetime limits through K8 |
| PKP-05 | G3-1 zone and zone-authority prover inputs; G3-2 the prepared zone-authority type |
| PKP-06 | G4-1 native verification of TypeScript-produced artifacts; G4-3 the tamper matrix |
| PKP-07 | G4-2 real prove-to-chain evidence |

The remaining 15 findings land in the remediation and gate phases of
[`review-checklist.md`](review-checklist.md#deterministic-selection) and are
listed there.

### PKP-00: Resolve authorities and freeze scope

Deliver:

- decisions for owner identity, proof sizes, and current slot-layout conflicts;
- updated specification and implementation tests;
- one reviewed source revision per capability;
- explicit supported family/rail/shape list.

Exit:

- no disputed behavior is labelled canonical.

### PKP-01: Harden fixture provenance

Deliver:

- proof/key fixture schema metadata;
- verifying-key identities and hashes, with the gate failing on a mismatch
  against the key the verifier loads;
- program/prover/source revision linkage, under the compatibility rule per
  revision key that
  [`testing-and-conformance.md`](testing-and-conformance.md#revision-compatibility)
  defines for the shared manifest;
- deterministic two-run generator check;
- CI fixture gate.

Exit:

- each fixture is attributable to production code and one reviewed revision.

### PKP-02: Complete key encoding and signature parity

Deliver:

- correct 34-byte TypeScript public-key type;
- P256 low/high-S policy and adversarial corpus;
- Ed25519 canonical-acceptance corpus;
- four-direction cross-language signature tests;
- aligned stable errors.

Exit:

- the key parse/sign/verify corpus has identical dispositions.

### PKP-03: Complete key derivation and encryption parity

Deliver:

- nullifier, viewing, transaction-viewing, transfer, and merge vectors;
- P-constant independent derivation test;
- slot/salt/counter boundary tests;
- cross-runtime property tests.

Exit:

- deterministic values and protocol bytes match for the required derivations.

### PKP-04: Enforce capability and secret boundaries

Deliver:

- substitutable TypeScript capability interfaces;
- local, HSM, remote, viewing-only, and transaction-signer adapters;
- copy/destroy/redaction tests;
- documented Rust and JavaScript erasure limits.

Exit:

- no interface grants unintended signing, viewing, nullifier, or custody capability.

### PKP-05: Complete proof assembly

The zone and zone-authority prover paths are no longer deferred to this packet. The owner ruled on
2026-07-25 that they are built during the parity phase, because a TypeScript caller can already
assemble a zone transaction through the transaction and interface packages and then cannot prove it,
and shipping a pipeline that stops one step short of working is worse than shipping it late. This
packet therefore certifies those paths rather than introducing them, and it is expected to receive
them already implemented and already covered by oracle tests.

That the paths arrive tested does not reduce the work here. Parity-phase evidence establishes that
TypeScript builds the same request bytes as Rust; it does not establish that the resulting proof
verifies against the intended statement and nothing else. The zone rails are the place that
distinction matters most, because their public-input chain is shorter than the confidential one and
their zone program field is the only thing binding a proof to its zone.

Deliver:

- confidential, zone, zone-authority, merge, and merge-zone TypeScript inputs;
- the required rail/shape public-input vectors;
- exact prover request vectors;
- exact merge and merge-zone hash assertions;
- for the zone rails specifically, evidence that a proof built for one zone does not verify for
  another, and that the anonymous chain cannot be satisfied by a confidential-chain assembly.

Exit:

- each supported circuit identity has independent Rust and TypeScript assembly evidence.

### PKP-06: Add native verification certification

Deliver:

- bounded test-only Rust oracle;
- TypeScript-produce/Rust-verify tests;
- wrong-key, wrong-rail, wrong-shape, and tamper matrix;
- stable rejection categories.

Exit:

- each TypeScript-produced proof artifact verifies only under its intended public input and
  verifying key.

### PKP-07: Add real prove-to-chain acceptance

Deliver:

- pinned prover and local-stack setup;
- action and instruction flows without stubs;
- state, settlement, indexing, decryption, and sync assertions;
- deterministic cleanup and diagnostics.

Exit:

- each supported family has a real TypeScript-driven verification path through the shielded-pool
  program.

### PKP-08: Independent review and release evidence

Deliver:

- completed certification matrix;
- command/result ledger;
- fixture and package hashes;
- independent review of each previously adverse row;
- explicit residual risk and unsupported-capability list.

Exit:

- release reviewers can reproduce the claim from a clean checkout.

## Required evidence index

Proof sources:

- `docs/spec.md`;
- `sdk-libs/client/src/prover/`;
- `sdk-libs/client/tests/`;
- `programs/shielded-pool/src/instructions/verifier.rs`;
- `programs/shielded-pool/src/instructions/transact/verify.rs`;
- `programs/shielded-pool/src/instructions/merge/verify.rs`;
- `program-libs/interface/src/verifying_keys/`;
- `sdk-libs/ts/client/src/prover/`;
- `sdk-libs/ts/client/test/`;
- `sdk-libs/ts/e2e/`;
- `sdk-libs/ts/fixtures/client/`;
- `sdk-libs/ts/fixtures/workflows/`.

Key sources:

- `sdk-libs/keypair/src/`;
- `sdk-libs/keypair/tests/`;
- `program-libs/interface/src/merge_utils.rs`;
- `sdk-libs/transaction/src/`;
- `sdk-libs/wallet/src/`;
- `sdk-libs/ts/keypair/src/`;
- `sdk-libs/ts/keypair/test/`;
- `sdk-libs/ts/transaction/src/`;
- `sdk-libs/ts/wallet/src/`;
- `sdk-libs/ts/fixtures/keypair/`.

Governance and release sources:

- [`architecture-and-api.md`](architecture-and-api.md);
- [`testing-and-conformance.md`](testing-and-conformance.md);
- [`security-and-release.md`](security-and-release.md);
- [`review-checklist.md`](review-checklist.md);
- `sdk-libs/ts/fixtures/manifest.json`;
- `xtask/src/bin/ts-fixtures.rs`;
- `xtask/src/ts_fixtures_*.rs`.

## Final certification statement

The final release evidence must answer, with reproducible artifacts:

1. Which specification and source revisions define the claim?
2. Which proof families, rails, and shapes are supported?
3. Do Rust and TypeScript assemble the same named values and exact bytes?
4. Do TypeScript-produced proofs verify with the intended embedded key?
5. Do altered proofs, inputs, keys, rails, and instructions fail?
6. Do signatures verify in both cross-language directions under one canonical policy?
7. Are owner, nullifier, viewing, and custody capabilities separated?
8. Are secret copying, destruction limitations, and redaction tested?
9. Do browser and Node consumers behave identically?
10. Does a real TypeScript flow prove, submit, verify in the shielded-pool program, index, decrypt,
    and sync without stubs?

Until each applicable answer is supported by current-revision evidence, the SDK may describe
individual certified capabilities but must not claim complete proof or key-handling parity.
