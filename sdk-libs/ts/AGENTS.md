# Architecture and Security Contract — `@heliuslabs/zolana` for TS SDK

This contract is binding for every change under `sdk-libs/ts`; its normative
terms are literal requirements. Preserve system invariants, not merely passing
tests. Weakening a gate, decoder, type, error, or allowlist to admit a change is
a defect.

## Non-negotiable invariants

- The SDK MUST NOT silently lose wallet state, advance past unrepresented
  chain data, expose secrets, authorize unintended value movement, emit a
  transaction known to be invalid, or claim a public API the package does not
  export.
- Security and correctness paths MUST fail closed. Unsupported, ambiguous,
  malformed, stale, partially decoded, or unauthenticated state is an error,
  never an empty result, default value, successful sync, or best-effort skip.
- Every invariant MUST have one implementation owner and adversarial tests at
  the boundary where it can fail. Copying policy is forbidden.
- Probabilistic filters, caches, and heuristics may optimize the average path
  only. They MUST NOT decide correctness or authorization; every adversarial
  hit/miss has a deterministic, bounded escape hatch, even if it costs more.

## Architecture and dependency direction

- Dependency direction is protocol primitives -> transaction/domain logic ->
  shared flows -> wallet/ring orchestration -> client adapters -> public
  barrels. Lower layers MUST NOT import concrete clients or orchestration.
- `test/boundaries.test.ts` is the executable layer map. Change it only with a
  documented architectural reason; never add an exception for convenience.
- Capability contracts and their DTOs live in `src/client/ports.ts`. A port
  MUST NOT import `client.ts`. Public builders accept the smallest named port
  composition they use, never `ZolanaClient`, broad facades, or structural
  bags with unrelated capabilities.
- Concrete clients implement ports; domain code depends on ports. Transport,
  selection, settlement, compilation, retry, persistence, and error policy
  each have one shared implementation. No rail-specific fork may duplicate
  them.
- A module MUST NOT reach through another layer's internal file. Promote a
  narrow contract or move the shared concept to its rightful owner. Cycles and
  barrel imports inside implementation code are forbidden.

## Types are proofs, not decoration

- Production code MUST NOT use `any`, `as unknown as`, unchecked branded
  casts, generic `fake<T>`/`cast<T>` helpers, or assertions that manufacture a
  capability. Tests receive no exemption.
- `unknown` is required at an untrusted boundary and MUST disappear through a
  runtime decoder. Inside trusted domain code, pervasive `unknown`, broad
  records, and optional-method probing indicate a missing type or port.
- A branded value may be asserted only immediately after the runtime invariant
  that proves the brand. Keep the assertion local and name the invariant.
- Type predicates claim exactly what they check. Partial validation MUST yield
  a partial type. Prefer discriminated unions, exhaustive switches,
  `satisfies`, and typed fixture builders with explicit defaults.
- Public structural signed/request objects MUST be revalidated at the method
  boundary; callers can construct interfaces without using SDK builders.

## Public and release surface

- `package.json.exports` plus the emitted `.d.ts` files define the API. Source
  exports and deep internal paths do not. Every promised symbol MUST be
  importable from a supported package subpath.
- Public DTOs belong beside their public port. No public declaration may
  reference an unexported, concrete, or `@internal` type.
- Every public change updates `CHANGELOG.md` under `CHANGELOG-RULES.md` in the
  same branch. The packed artifact is truth; prose, source barrels, and commit
  titles are not.
- REQUIRED gates for public changes: `npm run check`, `npm pack --dry-run`, and
  a consumer fixture importing the packed subpath with `skipLibCheck: false`.
  `check:dist` alone does not prove named exports exist.
- Only the current package version may be `unreleased`. Historical unpublished
  versions use their bump date; published versions use the registry date.
- Release order is fixed: set `package.json` version, date the matching
  changelog entry, run `npm run check`, publish, then push
  `ts-sdk-v<version>`. Never tag or document an artifact not verified above.

## Untrusted input and transport

- RPC, HTTP, JSON, storage, and deserialized values remain `unknown` until a
  decoder accepts exact shape, range, encoding, and semantics. Reuse
  `src/interface/decode.ts` with the owning layer's error factory.
- Addresses, signatures, hashes, cursors, keys, base58/base64, integers, and
  enums MUST be validated canonically. Numeric conversion MUST prove safe
  range before `Number(...)`; responses MUST be correlated with the request.
- Do not catch decode failures and continue unless the protocol explicitly
  defines that item as ignorable and progress remains replayable. Filtered RPC
  scans MUST distinguish “unsupported/failed” from “successfully empty”.
- Every external I/O path MUST propagate `RequestContext` cancellation and
  deadline. HTTPS policy, redirect refusal, size caps, content type, timeouts,
  canonical JSON-RPC envelopes, and sanitized failures belong to the shared
  transport and MUST NOT be bypassed.
- Error details MUST NOT expose response bodies, credentials, URL queries,
  request witnesses, decrypted plaintext, or server-controlled text.

## Wallet sync, cursors, and persistence

- Sync is a transaction: read into a session clone, validate the complete
  result, then commit exactly once through `_commitSync` on the wallet queue.
  Any failure leaves rows, UTXOs, registry, nullifiers, timestamps, and cursors
  unchanged.
- A cursor is a durable commit record, not a paging optimization. It may advance
  only when every fetched item before it is durably represented in wallet
  state or durably retained for deterministic replay.
- Unknown assets, failed/unsupported registry backfill, undecoded owned data,
  incomplete follow-up reads, or unresolved dependencies MUST prevent cursor
  commit. Returning diagnostics while committing past the data is forbidden.
- Cursors remain separate per stream and per stable tag/nullifier. A newly
  learned key starts at its own beginning; another key's watermark MUST NOT be
  reused. Terminal empty pages advance only from an authoritative
  `scannedThrough` value.
- Snapshot encoding has one owner:
  `src/transaction/wallet/persistence.ts`. Deserialization validates everything
  and supports every shipped version; migrations are explicit and tested.
- `syncPersistedWallet` is the only sync+save composition. Sync, serialization,
  and save run in the same wallet queue; save occurs only after commit. Store
  replacement MUST be atomic. Cross-process safety is not implied: one stored
  snapshot has one writer unless an explicit CAS/lease protocol is added.

## Concurrency and reservations

- Note selection and reservation form one synchronous state transition.
  Concurrent builds on one wallet MUST NOT select the same note.
- Every failure after reservation MUST release it in `finally` or the owning
  error boundary. Success retains it until confirmation, sync-observed spend,
  explicit cancellation, or documented expiry.
- In-memory queues and reservations MUST NOT be described as distributed
  locks. Crash recovery guarantees require the reservation-bearing snapshot
  to be durably saved and tested.

## Secrets, authorization, and intent

- Secret access is capability-scoped and callback-bounded. Do not return or
  cache borrowed keys. Temporary byte buffers are wiped and temporary key
  objects destroyed in `finally` on success, rejection, and thrown callbacks.
- Ownership transfer of a secret MUST be explicit: clear the local owner before
  cleanup so failure paths wipe exactly once. Avoid immutable secret
  projections; `bigint` cannot be wiped. A required prover scalar is the narrow
  exception and MUST NOT escape its proof lifetime.
- Never log, stringify, serialize, clone unnecessarily, place in error details,
  or branch with ordinary equality on secrets. Use constant-time comparison
  where secrecy is relevant.
- User approval binds a canonical `TransactionIntent`. The final proved and
  compiled transaction MUST be revalidated against that intent immediately
  before return. Approval summaries are display data, never authorization.
- All derived keys, nonces, domain separators, tree/ring identifiers, assets,
  amounts, recipients, settlements, and signer sets MUST be bound at the layer
  that authorizes or proves them.

## Errors and observability

- Every expected failure has a stable code from its owning layer's closed
  taxonomy. No bare strings, generic `Error`, server messages, or catch-all
  codes at public boundaries.
- A boundary preserves its outer operation code and records sanitized inner
  codes in `causeCode`/`causeCodes`. It MUST NOT erase the operation context or
  leak the original cause through JSON or enumeration.
- Never convert “cannot know” into `false`, `[]`, zero, or absence when callers
  could mistake it for an authoritative answer.

## Verification discipline

- A bug fix MUST include a regression that fails before the fix and asserts
  both the result and forbidden side effects. Atomicity tests inspect all state
  that must remain unchanged; security tests exercise every throw path.
- Wire/protocol behavior shared with Rust MUST use common constants or pinned
  cross-language vectors. A TS convenience MUST NOT redefine protocol truth.
- Run `npm run check` before handoff. Run relevant live E2E for changed network
  flows and state explicitly when it was not run. Never delete, skip, loosen,
  or whitelist a failing test to make a change pass.
