---
name: review-ts
description: Reviews the Zolana TypeScript SDK against the canonical Rust SDK file by file, with special scrutiny of privacy-sensitive key operations. Use whenever auditing TypeScript SDK completeness, checking Rust parity, investigating port drift, reviewing crypto or key handling, or planning work needed for full parity.
---

# Review the TypeScript SDK port

Audit `sdk-libs/ts` against the current Rust implementation until the TypeScript
SDK has complete public and behavioral parity. Review behavior rather than
requiring identical file layouts. Do not implement fixes unless explicitly
asked.

## Authority order

Resolve disagreements in this order:

1. `docs/spec.md`
2. Canonical wire definitions in `program-libs/interface`
3. Current Rust SDK implementation
4. Rust behavioral, property, and integration tests
5. Rust-generated fixtures in `sdk-libs/ts/fixtures`
6. TypeScript implementation and tests
7. Existing planning reports and inventory dispositions

Do not assume the frozen fixture commit represents current parity. Record both
the current commit and the fixture manifest's `frozenCommit`.

## Scope

Review these package pairs:

- `program-libs/interface` → `@zolana/interface`
- `sdk-libs/keypair` → `@zolana/keypair`
- `sdk-libs/merkle-tree` → `@zolana/merkle-tree`
- `sdk-libs/indexer-api` → `@zolana/indexer-api`
- `sdk-libs/zolana-api` → `@zolana/api`
- `sdk-libs/transaction` → `@zolana/transaction`
- `sdk-libs/client` → `@zolana/client`
- `sdk-libs/wallet` → `@zolana/wallet`
- `sdk-libs/smart-account-client` → `@zolana/smart-account-client`

Treat `@zolana/test-kit` as test infrastructure unless the user includes it.

## Review principles

- Review one canonical Rust source file at a time.
- Follow re-exports to determine whether an item is public.
- Accept consolidated TypeScript files when each mapped responsibility remains traceable.
- Treat matching names as insufficient evidence of matching behavior.
- Treat fixtures as evidence only for the cases and Rust revision they represent.
- Verify existing `internal`, `test-only`, `reuse`, and `not applicable`
  inventory dispositions instead of trusting them.
- Distinguish missing functionality from appropriate language ergonomics.
- Treat cryptographic preimages, serialization, field conversion, proof
  assembly, instruction bytes, PDA derivation, and error codes as exact contracts.
- Compare structured error codes and details, not message text.

## Start the session

- [ ] Record the current Rust commit.
- [ ] Record the fixture manifest's frozen commit.
- [ ] Determine whether canonical Rust sources changed since the freeze.
- [ ] Select one package for review.
- [ ] Clarify whether the review includes internals or only public behavior.
- [ ] Find unreviewed Rust files and inventory rows.
- [ ] Separate generated artifacts from hand-written code.
- [ ] Revalidate pre-existing findings.
- [ ] Build a progress list covering the Rust source files in the package.
- [ ] Order files so dependencies are reviewed before dependents.

## Per-file checklist

Answer the applicable questions for each Rust file.

### Role and disposition

- [ ] What responsibility does this Rust file have?
- [ ] Is it public, internal, test-only, feature-gated, or platform-specific?
- [ ] Which re-export makes its symbols public?
- [ ] Which TypeScript files claim responsibility for it?
- [ ] Is the inventory mapping accurate?
- [ ] If omitted, is the omission justified with evidence?
- [ ] If consolidated, can each mapped responsibility still be traced?

### Public API parity

- [ ] Is the full set of public types represented?
- [ ] Is the full public set of functions, constructors, methods, constants, and variants represented?
- [ ] Are generics translated into suitable TypeScript types?
- [ ] Are optional values, defaults, mutability, and ownership effects equivalent?
- [ ] Are enum values, tags, constants, and supported shapes exact?
- [ ] Are exports available from the intended package and subpath?
- [ ] Does TypeScript accidentally expose Rust-private helpers?
- [ ] Is each deliberate API difference documented and behavior-preserving?

Do not mechanically port Rust-only concepts such as ownership helpers or
blocking duplicates when they are meaningless in JavaScript. Preserve their
relevant capabilities.

### Behavioral parity

- [ ] What preconditions does Rust enforce?
- [ ] What does each valid input class produce?
- [ ] What edge and boundary cases exist?
- [ ] Does ordering affect results?
- [ ] Are duplicate, empty, maximum-size, and malformed inputs handled identically?
- [ ] Are defaults and fallback paths identical?
- [ ] Are state transitions and mutation timing equivalent?
- [ ] Are retry, polling, confirmation, and timeout semantics equivalent?
- [ ] Does asynchronous behavior preserve the Rust operation's observable result?
- [ ] Are browser and Node differences intentional and tested?

### Numeric and byte-level parity

When the file performs protocol math or encoding:

- [ ] Are integer widths, signedness, overflow checks, and endianness preserved?
- [ ] Are fixed-size arrays checked rather than silently resized?
- [ ] Are field reductions and canonical encodings identical?
- [ ] Do byte vectors use `u16` length prefixes?
- [ ] Do element-count vectors use `u8` length prefixes?
- [ ] Are discriminators, tags, account order, signer flags, and writable flags exact?
- [ ] Are Borsh, wincode, and manually packed formats kept distinct?
- [ ] Are decoding rejection rules equivalent?
- [ ] Is deterministic output byte-identical to a current Rust oracle?

## Key-operation and privacy checklist

Apply this section to signing, viewing, nullifier, encryption, ephemeral,
recovery, auditor, and merge keys. Matching output alone is insufficient:
privacy parity also requires preserving capability separation and preventing
additional secret exposure in the TypeScript API and runtime.

### Key derivation

- [ ] Is the exact Rust derivation path reproduced?
- [ ] Are seed length and validation rules identical?
- [ ] Are HKDF salt, info, labels, and output lengths exact?
- [ ] Are child indices and counters encoded with the correct width and endianness?
- [ ] Are signing, viewing, nullifier, and transaction-viewing keys domain-separated?
- [ ] Does the same seed produce byte-identical public outputs to Rust?
- [ ] Can keys from different domains collide or be substituted?
- [ ] Are unsupported derivation paths rejected rather than approximated?

### Capability separation

- [ ] Can a viewing key decrypt without gaining spend authority?
- [ ] Can a nullifier key derive nullifiers without signing or decrypting?
- [ ] Can a signing key authorize spending without exposing viewing secrets?
- [ ] Can public keys or addresses reconstruct any private material?
- [ ] Are P256 and Ed25519 keys impossible to confuse accidentally?
- [ ] Does each API require the least-powerful key type it needs?
- [ ] Are owner, auditor, recovery, recipient, and ephemeral keys distinct?
- [ ] Are encryption-key additions and removals authorized as required?

### Key generation and randomness

- [ ] Does production code use a cryptographically secure system RNG?
- [ ] Does it fail closed if secure randomness is unavailable?
- [ ] Are salts, blindings, nonces, and ephemeral keys generated independently?
- [ ] Is deterministic randomness limited to explicit test injection?
- [ ] Can retries reuse an ephemeral key, salt, nonce, or transaction-viewing key?
- [ ] Are zero, out-of-range, and invalid generated scalars rejected?
- [ ] Is rejection sampling unbiased and equivalent to Rust?

### Import, parsing, and validation

- [ ] Are exact key lengths enforced before parsing?
- [ ] Are malformed encodings rejected without truncation or padding?
- [ ] Are non-canonical field and scalar encodings rejected?
- [ ] Are invalid, off-curve, identity, and small-order points rejected where applicable?
- [ ] Is P256 decompression and `y` parity handling identical?
- [ ] Are private and public key encodings unambiguous?
- [ ] Are signature-type discriminators validated?
- [ ] Does each imported private key reproduce its expected public key?

### Public keys and addresses

- [ ] Is public-key derivation byte-identical to Rust?
- [ ] Does `pk_field` use the same coordinate limbs and endianness?
- [ ] Is `owner_hash` nested in the same order?
- [ ] Is P256 `y_is_odd` included exactly once?
- [ ] Are address compression and decompression lossless?
- [ ] Do equality checks use canonical encodings?
- [ ] Do malformed or mismatched addresses fail before transaction construction?

### Signing and verification

- [ ] Is the exact message or digest signed?
- [ ] Is domain separation included where Rust includes it?
- [ ] Does P256 sign the correct SHA-256 digest?
- [ ] Are signature encoding and canonicalization rules equivalent?
- [ ] Are externally supplied signatures verified before acceptance?
- [ ] Can signatures be replayed across rails, transactions, networks, or contexts?
- [ ] Are failures free of private scalar, nonce, and preimage leakage?

### Nullifier derivation

- [ ] Is the nullifier computed from the exact ordered preimage?
- [ ] Are UTXO hash, blinding, and nullifier secret encoded identically?
- [ ] Is the nullifier bound to the owner?
- [ ] Does the same owned UTXO deterministically produce the same nullifier?
- [ ] Could omitted fields make different UTXOs share the same input?
- [ ] Is derivation unavailable without the required private capability?
- [ ] Can public nullifiers reveal any secret inputs?

### Viewing and encryption

- [ ] Does ECDH use the same points and coordinate extraction?
- [ ] Is the shared-secret x-coordinate encoded identically?
- [ ] Are HKDF labels, salt, slot index, key length, and nonce length exact?
- [ ] Is the slot index encoded as `u32` big-endian where required?
- [ ] Are view tags derived and compared exactly as Rust does?
- [ ] Are default-zone owner tags separate from policy-zone view tags?
- [ ] Does decryption recompute and verify the proof-bound UTXO hash?
- [ ] Does incorrect-key decryption fail closed?
- [ ] Are truncated, extended, reordered, and tampered ciphertexts rejected?
- [ ] Can ciphertext or key material be substituted between recipient slots?
- [ ] Are transaction-viewing keys unique and correctly scoped?

### Merge and specialized operations

- [ ] Do verifiable merge encryption and decryption match Rust byte-for-byte?
- [ ] Does the merge ciphertext hash cover the exact canonical bytes?
- [ ] Are malformed merge ciphertexts rejected?
- [ ] Are recovery and auditor capabilities no stronger than intended?
- [ ] Are zone-specific key operations isolated from default-zone operations?
- [ ] Does each specialized operation require the appropriate key type?

### Secret handling in JavaScript

- [ ] Are secrets absent from exceptions, logs, fixtures, snapshots, and debug output?
- [ ] Do string conversion, JSON serialization, inspection, and spread avoid secrets?
- [ ] Are public key-operation exports deliberately limited?
- [ ] Do defensive copies prevent caller mutation of key material?
- [ ] Are temporary secret buffers overwritten when practical?
- [ ] Is JavaScript's inability to guarantee zeroization documented?
- [ ] Are `Buffer`, `Uint8Array`, Web Crypto, and library conversions checked for copies?
- [ ] Can secrets cross worker, storage, telemetry, or network boundaries implicitly?
- [ ] Is browser persistence opt-in and explicitly designed?

## Transaction and proof checklist

- [ ] Is shape selection identical to Rust for each proof rail?
- [ ] Is `external_data_hash` built from the same ordered preimage?
- [ ] Is `private_tx_hash` identical?
- [ ] Are owner tags resolved identically?
- [ ] Are default-zone owner tags distinct from policy-zone view tags?
- [ ] Are nullifiers, commitments, roots, and public amounts ordered identically?
- [ ] Are EdDSA Groth16 and P256 BSB22 layouts kept distinct?
- [ ] Are compressed proof bytes identical?
- [ ] Are prover JSON names and number encodings identical?
- [ ] Are instruction accounts, bytes, and compute limits equivalent?

## Error checklist

- [ ] What Rust errors can this file produce?
- [ ] Does TypeScript provide stable `code` and structured `details`?
- [ ] Does TypeScript preserve the distinctions among Rust and package error categories?
- [ ] Are precondition rejections, failed HTTP requests, invalid prover responses,
  JSON-RPC errors, and Solana custom program errors distinguished?
- [ ] Are surfaced `ShieldedPoolError` codes preserved?
- [ ] Does TypeScript reject at the same boundary as Rust?
- [ ] Do tests assert codes and details instead of message wording?

## Dependency and environment checklist

- [ ] Does TypeScript reuse canonical constants and lower-level implementations?
- [ ] Is protocol math duplicated unnecessarily?
- [ ] Are browser-safe packages free of Node-only imports?
- [ ] Are Node-only APIs confined to documented entry points?
- [ ] Are package dependency directions valid?
- [ ] Are runtime dependencies declared by their importing package?
- [ ] Are Web Crypto, Node crypto, and Solana library differences tested?
- [ ] Can tree-shaking or initialization alter observable behavior?

## Test evidence checklist

- [ ] Which Rust unit, BDD, property, tamper, or integration tests govern the file?
- [ ] Is each relevant Rust scenario represented in TypeScript?
- [ ] Is there a Rust-generated fixture for deterministic behavior?
- [ ] Does provenance identify the Rust path, symbol, inventory row, and commit?
- [ ] Do vectors cover both success and rejection?
- [ ] Are property tests used where examples cannot cover the state space?
- [ ] Are malformed and adversarial inputs tested?
- [ ] Does a live test cover behavior fixtures or mocks cannot prove?
- [ ] Are skipped environment-dependent tests recorded as unverified?
- [ ] Would a plausible wrong implementation still pass the current tests?
- [ ] Do key operations have positive vectors, malformed-input tests,
  capability-separation tests, and secret-exposure tests?

## Drift checklist

- [ ] Has the Rust file changed since the fixture freeze?
- [ ] Have its dependencies or governing spec sections changed?
- [ ] Can current fixtures detect those changes?
- [ ] Is TypeScript only matching stale fixtures?
- [ ] Does the inventory row need a new disposition or evidence?

## Verdict

Assign exactly one verdict:

- `PARITY`: current public behavior is represented with adequate evidence.
- `PARTIAL`: main behavior exists but a case, rail, runtime, or test class is missing.
- `MISSING`: required behavior has no TypeScript implementation.
- `DIVERGENT`: TypeScript conflicts with the spec or current Rust.
- `STALE`: evidence matches an older Rust revision.
- `NOT_APPLICABLE`: omission is valid and justified.
- `BLOCKED`: available evidence cannot determine parity.

Passing tests alone does not justify `PARITY`.

## Per-file report

Use this format:

```markdown
### [Rust path]

- TS counterpart: `[path or none]`
- Inventory row: `[id or none]`
- Role: `[public/internal/test-only/platform-specific]`
- Verdict: `[verdict]`
- Rust behavior: [one or two sentences]
- Evidence:
  - [spec, Rust tests, fixtures, TS tests]
- Gaps:
  - [specific missing or divergent behavior]
- Required action:
  - [smallest action needed for parity]
- Questions:
  - [unresolved decisions requiring human input]
```

Cite the relevant Rust symbol or behavior and TypeScript counterpart for each
reported gap. Avoid vague findings such as "needs more testing."

## Package completion

- [ ] Each canonical Rust source file has a verdict.
- [ ] The full set of public Rust exports has a TypeScript disposition.
- [ ] Each TypeScript export traces to Rust or a documented adaptation.
- [ ] Existing inventory claims have independent evidence.
- [ ] Rust changes since the fixture freeze have been reviewed.
- [ ] Deterministic bytes match current Rust vectors.
- [ ] Non-deterministic behavior has invariant or property coverage.
- [ ] Rust rejection and tamper scenarios have TypeScript equivalents.
- [ ] Errors have code and structured-details coverage.
- [ ] Browser and Node entry points respect their boundaries.
- [ ] Feature-gated behavior and each proof rail have dispositions.
- [ ] Relevant package checks pass.
- [ ] Remaining gaps identify exact paths and symbols.

## Full SDK completion

- [ ] Each scoped package satisfies package completion.
- [ ] Cross-package workflows match Rust behavior.
- [ ] Deposit, transfer, split, withdrawal, merge, registration, sync, and
  submission flows are covered.
- [ ] Instruction bytes work with same-revision Solana programs.
- [ ] Prover inputs work with the same-revision prover.
- [ ] Indexer requests and responses match the live Photon contract.
- [ ] EdDSA and P256 rails cover the full supported shape set.
- [ ] Zone transfer, zone authority, and merge-zone have named coverage.
- [ ] Fixture provenance points to the reviewed Rust revision.
- [ ] The public-export ledger has no unexplained differences.
- [ ] No `PARTIAL`, `MISSING`, `DIVERGENT`, `STALE`, or `BLOCKED` finding remains.

## End each session

Report:

1. Files reviewed and verdicts
2. Newly discovered gaps
3. Decisions requiring user input
4. Exact next Rust file to review
5. Package progress as reviewed files / total files
6. Whether current evidence supports a parity claim

For `sdk-libs/keypair`, review in this order:

1. `constants.rs`
2. `signing_key.rs`
3. `nullifier_key.rs`
4. `viewing_key.rs`
5. `pubkey.rs`
6. `shielded.rs`
7. `hash.rs`
8. `encryption.rs`
9. `merge.rs`
10. Public traits and exports
11. BDD, property, security, and transaction-boundary tests
