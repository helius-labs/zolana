# Security, dependencies, and release

These gates apply to frozen revision
`43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f` and the package split in
[architecture-and-api.md](architecture-and-api.md). A release is blocked when
a requirement lacks the named vector, negative test, or E2E evidence in
[testing-and-conformance.md](testing-and-conformance.md).

## Trust and package boundaries

- `@zolana/keypair` owns secret-bearing primitives. It performs no network I/O.
- `@zolana/transaction` owns deterministic transaction math and pure wallet
  state transforms. It receives authority results, not transport capability.
- `@zolana/client` owns RPC, indexer adaptation, prover transport, witness
  assembly, proof conversion, native transaction assembly, and confirmation.
  It owns no wallet, registry, authority, action, balance, history, or sync API.
- `@zolana/wallet` owns user intent, state, registration, authority calls,
  action creation, native-signing orchestration, and sync. It passes only the
  minimum public values or circuit witness required by the next stage.
- `@zolana/indexer-api` owns untrusted wire schema. `@zolana/api` owns fetch and
  authentication. Neither owns wallet state or proof math.
- `@zolana/interface` and `@zolana/smart-account-client` are pure instruction
  packages. They perform no I/O and retain no authority.
- private `@zolana/test-kit` is Node-only and cannot appear in production
  dependencies or published tarballs.

No compatibility barrel may move wallet APIs back under `@zolana/client`.

## Secret and authority boundary

Signing, nullifier, viewing, transaction-viewing, plaintext UTXO, and witness
material must not appear in logs, errors, traces, inspection hooks, JSON, URLs,
analytics, or approval summaries.

`WalletAuthority` is the only action-layer capability for:

- obtaining the public shielded identity and viewing-key set;
- deriving spend nullifier material;
- encrypting prepared recipient/change outputs;
- requesting approval over final recipient, asset, amount, fee, payer, and
  settlement accounts; and
- producing the P256 signature for the final private transaction hash.

`LocalWalletAuthority` may hold local keys. External implementations may be an
HSM, custodian, browser wallet, remote signer, or policy engine. Client and
prover APIs must not accept a local authority object merely to retrieve raw
keys. They accept finalized proof inputs, public paths, or a serialized prover
request at the documented boundary.

Incoming secret byte arrays are copied. Returned secret bytes, where the
allowlist requires them, are copies and documented as hazardous. `destroy()`
overwrites owned mutable arrays and marks the object unusable; documentation
must state that JavaScript cannot guarantee erasure of engine or crypto-library
copies. Fixed fixture secrets are test-only and are excluded from examples.

### Redacting a wrapped dependency error

`wrapKeypairError` attaches the original `@noble/curves` or `@noble/hashes`
error as `cause`. Those libraries put operand material in some messages, and the
keypair package operates on secret scalars, so a thrown keypair error can reach
a log aggregator with dependency-supplied detail about a secret-derived value.
The redaction rule the SDK states is not applied at the one place that would
apply it
([G5-1](production-readiness-issues.md#g5-1-raw-dependency-errors-are-retained-as-cause-high)).

The release records one of three dispositions for `cause` on a keypair error and
enforces it at the wrap site: dropped, replaced by a stable dependency-category
marker, or retained behind an opt-in the caller sets. A test asserts that no
serialized keypair error contains input-derived bytes.

### Secret lifetime in JavaScript

Rust secret types clear their memory on drop. A TypeScript `Uint8Array` persists
until the collector runs, and engine-internal copies are unreachable, so the
port cannot offer the Rust guarantee. Not stating that leaves a consumer unable
to reason about residual exposure
([G6-1](production-readiness-issues.md#g6-1-no-zeroization-of-secret-material-medium)).

The threat statement names both sides: which buffers the SDK owns and clears
after use, and which copies (engine-internal, crypto-library-internal, and any
string conversion) it cannot reach. Best-effort clearing applies where a secret
buffer's lifetime is under SDK control.
[PKP-04](proof-and-key-parity.md#pkp-04-enforce-capability-and-secret-boundaries)
K8 tests the stated limits.

### Custody seam width

`ShieldedKeypairLike` requires `nullifier`, and `ViewingKeyLike` requires
`transactionViewingKey`. Both need the implementer to hold key material, so a
custodian that exposes a signing operation alone cannot satisfy either
interface. No non-software implementation has been built against them
([G6-3](production-readiness-issues.md#g6-3-the-custody-abstraction-may-be-too-narrow-for-a-hardware-signer-medium)).

The release records whether a signing-only custodian is a supported
configuration. When it is,
[PKP-04](proof-and-key-parity.md#pkp-04-enforce-capability-and-secret-boundaries)
K9 builds the second implementation that proves the seam holds. When it is not,
the interfaces document the key material an external custodian must hold.

Circuit private inputs sent to a configured remote prover are an explicit trust
boundary. The threat model states exactly which witness values the prover sees.

## Unsigned custody flow

The custody-safe sequence is:

```text
wallet intent
  -> finalized authority approval/encryption/P256 authorization
  -> proof and interface instruction
  -> unsigned native Solana transaction
  -> external TransactionSigner or HSM
  -> RPC submission
  -> bound confirmation
```

`buildPrivateTransaction` returns a native transaction with final fee payer,
blockhash, compute-budget instructions, shielded-pool instruction, and empty
native signature slots. It does not submit and does not require the native
fee-payer secret. `signPrivateTransaction` is only a convenience that calls the
supplied `TransactionSigner`; it must produce the same message bytes.

Approval occurs after the user-visible and settlement fields are final and
before proof generation. Any mutation to recipient, asset, amount, fee,
expiry, payer, tree, selected inputs, output slots, or settlement accounts
invalidates approval and private authorization. Rebuilds generate fresh salt
and dummy randomness. Submission is not automatically retried after an
unknown outcome.

Payer, private owner, and native signer may differ. Ed25519 account signer
indices and P256 ownership fields identify the correct authority. No API may infer
that possession of one key grants the other role.

## Confirmation binding

`confirmPrivateTransaction(signature)` must:

1. wait for Solana confirmation of the submitted signature;
2. decode that transaction's shielded-pool instructions and extract its output
   view tags;
3. query Photon for those tags;
4. require indexed records carrying the same submitted signature and complete
   expected tag set; and
5. return only after both boundaries succeed.

An indexed transaction with matching tags but a different signature, or the
same signature with missing outputs, cannot satisfy confirmation. Indexer
appearance does not replace Solana confirmation. Lag, abort, expiry, and timeout
return typed `ClientError` values with safe method/signature/deadline metadata.
Repeated confirmation is idempotent.

## Protocol and state invariants

- Field inputs are canonical and below the BN254 modulus; caller values are not
  silently reduced.
- Shielded keys, owner hashes, domain separators, nullifier derivation, view
  tags, ECDH/HKDF/AES parameters, slot indexes, and salt lengths match frozen
  Rust and `docs/spec.md`.
- Each private transaction uses a fresh 16-byte CSPRNG salt. Production has no
  `Math.random` fallback.
- AES-CTR plaintext is accepted only after its UTXO hash matches the
  proof-verified output commitment.
- UTXO, external-data, private-transaction, public-input, and nullifier hashes
  include the exact fields in the required order. Optional zone/data fields follow frozen
  zero/absence rules.
- Real input/output order survives shape padding. Dummy commitments and
  nullifiers are pairwise distinct and contribute no value. Default-zone dummy
  outputs have no ciphertext.
- Per-asset conservation holds. One transaction has at most one public SPL
  asset and one withdrawal.
- Each real input has one state inclusion proof and one nullifier
  non-inclusion proof with exact path height and input order.
- P256 uses one BSB22 commitment and PoK; Ed25519 uses none. Proof points are
  validated and compressed with the required A negation.
- SPL settlement requires the canonical vault/interface, recipient ATA, CPI
  authority where required, and token program. SOL settlement requires the
  canonical SOL interface, recipient, and system program.
- Indexer data is untrusted and schema/length/path/signature validated before
  state mutation. Wallet sync is atomic and idempotent across duplicate pages,
  retries, and viewing-key epochs.
- User registry reads validate PDA, owner, discriminator, record owner, and
  bump once, then reuse the decoded value. Owner authorization gates
  non-auditor encryption-key changes.

## Network diagnostics and redaction

URLs are parsed before use. Remote documentation recommends HTTPS; plain HTTP
is local-development only. Requests accept timeout and cancellation.
Retries are limited to classified transient failures with capped jitter.

API keys are secrets regardless of whether the service places them in a
header, query string, or URL. Errors, traces, curl output, telemetry, snapshots,
and test failure diffs must replace them with a fixed redaction token. Request
bodies may contain tags, paths, witnesses, ciphertexts, or signatures and are
redacted by field allowlist, not dumped wholesale.

Response-body capture is disabled by default. Diagnostic capture is
size-bounded, content-type aware, and redacts the body before attaching safe
metadata. `ApiError`, `ClientError`, and nested causes do not retain an
unredacted body or `Request`/`Response` object. Tests cover text, JSON, binary,
oversized, malformed, and secret-reflecting responses.

## Smart-account safety

`createSmartAccountInstruction` validates `u128/u16/u32` ranges, unique signer
keys, non-empty signer set, threshold against signer count, permissions, and
serialized size before allocating the final instruction.

`executeSyncInstruction` validates:

- account index fits `u8`;
- signer, instruction, per-instruction account, and unique compiled-account
  counts fit their one-byte indexes;
- each inner data length fits `u16`;
- each generated account index exists and remains stable;
- duplicate accounts union writable and signer privileges without downgrading;
- program IDs are readonly/non-signer unless another use legitimately raises
  privilege;
- the vault is first in the compiled payload and non-signer in the outer
  account list; and
- the complete Borsh/payload/instruction size stays below the selected Solana
  message and transaction limits.

Builders reject overflow rather than truncating with `as u8` or `as u16`.
Golden vectors compare each account address, order, signer/writable bit,
discriminator, index, length, and payload byte. Mutations cover privilege
escalation/downgrade and boundary counts.

## Browser isolation

Production roots are ESM and browser-capable as declared in the
architecture. Browser entry graphs cannot reference `Buffer`, `process`,
`require`, CommonJS, `node:*`, filesystem/process APIs, Node type globals, or
automatic polyfills. Randomness uses `globalThis.crypto.getRandomValues`;
transport uses injected or global `fetch`; bytes use `Uint8Array`.

Node-only behavior is confined to explicit non-root adapters or private
`@zolana/test-kit`. Packed browser-consumer tests inspect the generated graph,
not only source imports. Browser tests cover cryptography, codecs, proof
conversion, API/client transport, wallet authority/sync, and both instruction
packages.

## Dependency admission

Admit a dependency only after:

- exact Rust-vector parity for each used cryptographic or codec operation;
- invalid point/scalar/length and field-boundary rejection;
- ESM browser and Node support without hidden polyfills;
- active maintenance, provenance, compatible license, and acceptable audit
  history for cryptographic code;
- pinned lockfile and no install script without approval;
- measured bundle cost and duplicate crypto-version review; and
- deterministic property-test replay where used in tests.

Static OpenAPI types are insufficient for Photon. Runtime validation remains
owned by `@zolana/indexer-api`; `@zolana/api` must consume it rather than
generate a competing schema.

## Release order

Use one coordinated version while the API is pre-1.0. Build, test, and publish
in this dependency order:

1. `@zolana/interface`, `@zolana/keypair`, `@zolana/merkle-tree`, and
   `@zolana/smart-account-client`;
2. `@zolana/transaction`;
3. `@zolana/indexer-api`;
4. `@zolana/api`;
5. `@zolana/client`;
6. `@zolana/wallet`.

Cryptographic certification follows base SDK parity. First complete the
118-row review, remediate and independently re-review actionable adverse rows,
resolve specification-authority blockers, and pass the full CI, fixture,
browser, packed-package consumer, and independent E2E gates. Then run
[PKP-00 through PKP-08](proof-and-key-parity.md#implementation-work-packets).

The PKP work is a certification overlay on this release evidence. It does not
replace the review checklist or add a second source inventory. A complete
proof or key-handling parity claim requires native Rust verification of
TypeScript-produced artifacts and real TypeScript prove-to-chain flows against
the same-revision local stack.

Private `@zolana/test-kit` is built before E2E and is not published. Packages in
the same numbered group may release in parallel only when they have no
workspace dependency on each other. The release transaction stops before
dependent publication if any tarball, provenance, API, vector, browser, or E2E
gate fails. Internal dependency ranges must prevent incompatible protocol
versions from being combined.

Each package is packed and installed in fresh Node and browser consumers before
publication. Publish leaf packages first, verify registry artifacts and
checksums, then publish dependents. A partial release records exactly which
versions exist and does not advance the aggregate release tag.

## Semver and evidence

- Patch: implementation fix with unchanged public types and wire behavior.
- Minor: additive API or compatible circuit/protocol support.
- Major, including pre-1.0 documented breaking minor: removed/renamed API,
  ownership move, default change, persistence break, or wire incompatibility.

Protocol-byte changes require a separately authorized `docs/spec.md` change,
Rust and TypeScript changes, fixture-version update, and coordinated
program/indexer/prover migration.

Release blockers include an unclosed inventory row; any mismatch between the
263 canonical export declarations and the 263 declaration-ledger fixture/test
pairs; unexplained API-report delta; secret or API key in diagnostics;
unchecked remote schema or proof point; raw wallet key crossing into client or
prover; unsigned custody mutation; unbound confirmation; smart-account
overflow/flag failure; surviving protocol-byte mutation; Node global in a
browser package; missing changed-code Solana program E2E; tarball consumer failure;
critical/high dependency finding without a time-bounded exception; or failure
of either independent E2E suite. Split creation, merge creation/submission,
idempotent ATA creation, and frozen deposit/transfer/SOL-withdrawal/
SPL-withdrawal tag-and-wire vectors are mandatory action/instruction evidence.

Required release evidence:

- frozen fixture manifest and clean regeneration;
- 182-row inventory-to-packet/test coverage report;
- 263-declaration ledger report with 263 unique fixture IDs, 263 unique named
  tests, and zero uncovered or extra declarations;
- package and subpath API reports;
- dependency/license/provenance/duplicate-crypto reports;
- browser graph and consumer results;
- prover, indexer schema/transport, smart-account, action E2E, and instruction
  E2E results;
- tarball hashes and published-artifact verification; and
- protocol/cryptography, Solana/interface, wallet/indexer, TypeScript/runtime,
  and release-owner sign-offs.
