# Re-review of nine adverse rows: K11-K14, C06, C21, W04, I37, X01

Branch `port/rereview`. The nine rows were adverse because nobody had gone back
to check work that had already landed, not because nine things were broken.

**Result: six rows close, three do not.** `K11`, `K12`, `K13`, `K14`, `I37` and
`W04` close at `PARITY`. `X01` closes as `PARITY` against its port target and
leaves a documentation residue that no SDK change can clear. `C06` and `C21`
stay `DIVERGENT`, each on a difference that is real, reachable, and fixable only
in Rust.

Nothing in this batch was taken on a previous worker's report. Every claim below
was re-read at this HEAD, and three of them turned out to be stale in the
report's favour and one in the opposite direction:

- `K12`'s blocker, Rust's secret-returning `nullifier_key()`, is gone from the
  Rust trait.
- `I37`'s blocker, the frozen-revision fixture gate, passes.
- `K11`'s three unconverted call sites are converted, and the three bindings
  left concrete are the three Rust also declares concrete.
- `C06`'s recorded reason for tolerating its one divergence does not hold. The
  divergence is reachable, and this batch has the failing case.

## 1. What changed in this batch

| Change | Why |
| --- | --- |
| `client/test/vectors/field-alignment.test.ts` | A new case reaches the `C06` divergence through `assemble`, and the comment that argued it was unreachable is replaced by the reason it is not. |
| `sdk-libs/ts/reports/inventory.json` | Regenerated for the two inventory rows amended earlier in this branch. `ts-fixtures --check` byte-compares this file, so an inventory edit that skips it turns the fixture gate red. |

Two inventory amendments landed earlier on this branch and are described under
their rows: `14bb9267` (`K14`) and `be5c3804` (`C06`).

No file under `programs/`, `program-libs/`, `prover/` or `xtask/` was touched.
Two files in the worktree, `wallet/src/actions.ts` and `wallet/src/submit.ts`,
carry edits that are not this batch's and were left alone.

## 2. K11 `sdk-libs/keypair/src/traits/view_key.rs` -> PARITY

The row's remaining finding was that three call sites still bound the concrete
`ViewingKey`, so no backend could be passed. All three now bind the interface:
`transaction/src/wallet/sync.ts:184,506,525,574,748,764`,
`transaction/src/serialization/codecs.ts:924,937,947,997,1010,1088,1099`, and
`wallet/src/sync.ts:96`. That is what [Q17](../authority-rulings.md#q17-an-out-of-process-viewing-key-backend-k11)
requires, and because the interface is synchronous
(`keypair/src/shielded.ts:148-181`) none of them became `async`.

Three bindings are still concrete, and they are correct that way:
`DecodeContext.viewingKey` and `decodeContextForSlot`
(`transaction/src/serialization/codecs.ts:1117,1135`) mirror Rust's
`DecodeCx { viewing_key: &'a ViewingKey }`
(`sdk-libs/transaction/src/serialization/mod.rs:21-22,31`), and
`WalletSyncMaterial.viewingKeys` (`transaction/src/wallet/authority.ts:69`)
mirrors `viewing_keys: Vec<ViewingKey>`
(`sdk-libs/transaction/src/wallet/authority.rs:69-73`). Widening them would make
TypeScript the more permissive side, which is the failure this queue keeps
finding in the other direction.

The type gate exists and runs.
`transaction/test/types/viewing-key-like.types.ts` asserts the seven codec
signatures accept a `ViewingKeyLike`, and pins the three deliberate concrete
bindings with `@ts-expect-error` controls at `:49` and `:63`; an unused
`@ts-expect-error` is itself a compile error, so the controls cannot rot into
decoration. `config/typecheck.mjs:19,48-49` compiles `test/types/tsconfig.json`
for any package that has one, so `npm run typecheck` is the gate.

The interface half is pinned against the Rust source rather than a
transcription: `keypair/test/vectors/trait-surface.test.ts:94-97` scrapes
`ViewingKeyTrait`'s method list out of `sdk-libs/keypair/src/traits/view_key.rs`
and asserts set equality with `keyof ViewingKeyLike` through an exhaustive
`Record`, and `:105-109` asserts the trait declares no `async fn` and the
interface declares no `Promise<`.

## 3. K12 `sdk-libs/keypair/src/traits/shielded_keypair.rs` -> PARITY

The row's one open item was that Rust's trait handed out the nullifier secret
while TypeScript's offered only the public key. **Rust has moved.**
`ShieldedKeypairTrait` declares `nullifier_pubkey()` at
`sdk-libs/keypair/src/traits/shielded_keypair.rs:50` and no `nullifier_key()`;
`trait-surface.test.ts:121-126` asserts both halves of that, so a re-added
secret accessor fails the TypeScript suite.

The remaining asymmetry is `try_sign`
(`traits/shielded_keypair.rs:38`), which has no TypeScript counterpart and needs
none: Rust splits panicking `sign` from non-panicking `try_sign`, TypeScript has
one throwing `sign` (`keypair/src/shielded.ts:132`), and no input distinguishes
them because a TypeScript throw is already the catchable form Rust added
`try_sign` to provide. `trait-surface.test.ts:71-77,91` records it as the one
Rust-only name rather than hiding it in a loose comparison.

The interface is proven satisfiable rather than only declared:
`keypair/test/api-surface.test.ts` runs an async `RemoteBackend` through it, and
`transaction/test/capability-call-sites.test.ts:63-107` runs all four
keypair-rail builders against a keypair proxy that throws if the builder reaches
for `viewingKey()` or `nullifierKey()`, with a control at `:113-120` proving the
guard fires. That is the executed form of Rust's generic bounds.

## 4. K13 `sdk-libs/keypair/src/traits/mod.rs` -> PARITY

Both residues are gone. The packed-package blocker was resolved and its cause
recorded elsewhere. The "no trait-specific fixture" residue is answered by
`keypair/test/vectors/trait-surface.test.ts`, added at `335a026c` after the row
was written. A trait declares no values, so there is nothing for a Rust oracle
to emit; scraping the trait blocks out of the two Rust files and asserting set
equality against the TypeScript interfaces compares against the Rust source
itself, which is stronger than a generated fixture would have been.

`keypair/src/traits/index.ts` is type-only, as `traits/mod.rs` is: both
re-export the two trait/interface names and no runtime item, and
`api-surface.test.ts` asserts the subpath ships no value.

## 5. K14 `sdk-libs/keypair/src/lib.rs` -> PARITY

The row's last item was the inventory disposition of
`sdk-libs/keypair/src/constants.rs`, recorded as `internal`. It is not internal:
every `pub` item of the Rust module is re-exported by name from the package
root (`keypair/src/index.ts:14-25`), which is what `port` means, while
`internal` claims callers reach it only through the allowlist. Amended at
`14bb9267`, with the target cell naming the seven exported constants and the
reason the `INFO_*` labels and HPKE prefixes stay behind (Rust keeps them
`pub(crate)`).

**Worth recording, because it is now an inconsistency rather than an
oversight:** `sdk-libs/keypair/src/hash.rs` and
`sdk-libs/keypair/src/encryption.rs` sit in exactly the same position, both
still `internal`, both re-exported by name at `keypair/src/index.ts:26-27`.
They belong to `K07` and `K09` and were left for their owners. `internal` now
means one thing on `constants.rs` and another on its two neighbours until those
rows move.

Regenerating `sdk-libs/ts/reports/inventory.json` is not optional after an
inventory edit: `ts-fixtures --check` regenerates the report from the markdown
and byte-compares it (`xtask/src/bin/ts-fixtures.rs:42-49,107-113,122-129`), so
the edit alone turns `npm run fixtures:check` red. Regenerate with
`cargo run -p xtask --bin ts-fixtures -- --reports-only`, which touches the
reports and nothing else.

## 6. C06 `sdk-libs/client/src/prover/field.rs` -> DIVERGENT

The row carried one behavioural difference, argued unreachable. **The argument
does not hold, and the reachable case is now a test.**

The difference: `bytesField` right-aligns and reads big-endian as
`right_align_slice` and `be` do, then runs the result through the BN254 range
check and raises `CLIENT_INVALID_FIELD`
(`client/src/internal.ts:74-90`). Rust's `be` returns whatever the 32 bytes say
(`sdk-libs/client/src/prover/field.rs:21-23`).

The recorded argument was that the values reaching `bytesField` are 31-byte
secrets, Poseidon outputs, or caller-supplied hashes, and that a caller-supplied
hash at or above the modulus already fails inside Poseidon. That enumeration
misses a whole class: **merkle witness values, which come off the wire from the
indexer and are never hashed locally.** `createRealInput` runs the state root,
the nullifier root, every state and nullifier path element, and the low and high
elements through `bytesField` (`client/src/prover/assembly.ts:367-377`). Rust
runs the same values through `be`
(`sdk-libs/client/src/prover/transact/p256_and_eddsa.rs:320-327`). Nothing
between the response and that point looks at them: `validate_spend_proofs`
compares leaves and tree addresses only
(`sdk-libs/client/src/client.rs:884-904`), and neither side recomputes a root
from its path.

So a `get_merkle_proofs` response carrying a 32-byte root at or above the
modulus is refused by TypeScript at assembly and carried to the prover by Rust,
where the proof it produces cannot verify. The indexer decoder does not close
this either: it validates a `Hash` as 32 bytes, not as a field element.

`client/test/vectors/field-alignment.test.ts` now has
`refuses a merkle root at the modulus, which Rust carries to the prover`, which
builds a real 1x2 eddsa spend proof, substitutes the oracle's own modulus bytes
into `state.root`, and asserts `assemble` raises `CLIENT_INVALID_FIELD` while
the unmodified proofs assemble. The control matters: without it the case would
pass on any assembly failure.

**What blocks the row.** Which side moves is an owner's call and both directions
are code this batch may not write. Rust adding the check is the smaller change
and matches [C08](../authority-rulings.md#rail-inference-when-parsing-a-proof-c08),
where the owner ruled "Fix Rust, TypeScript is correct" on the same shape of
difference. TypeScript dropping the check would remove a refusal that saves a
caller a prover round trip and a proof that cannot verify. Recommended Rust
change, not made here: give `be` a checked sibling that returns
`ClientError::InvalidField` at or above the BN254 modulus and use it for the
witness values in `p256_and_eddsa.rs:320-330`.

The row's other item, the inventory, is closed at `be5c3804`. The claim that it
pointed at a nonexistent `src/prover/field.ts` was already stale; the target
cell now also names `bytesField` and `bytesToBigInt`, the disposition stays
`internal` with the reason stated (the Rust module is `pub` at
`sdk-libs/client/src/prover/mod.rs:2` and the port keeps the helpers unexported
deliberately), and the fixture cell points at the oracle that exists rather than
the `fixtures/client/field.json` that does not.

## 7. C21 `sdk-libs/client/src/client.rs` -> DIVERGENT

Most of the row is closed. The two reversed rejection orders are fixed and
tested, and the fee-payer-before-tree order holds at this HEAD:
`finishSubmissionUnsigned` checks the payer at `client/src/client.ts:472-476`
and the tree at `:477`, as `finish_submission_unsigned` does at
`sdk-libs/client/src/client.rs:283-284`.

**Two error selections diverge, and the defect is Rust's.**

| Input | Rust | TypeScript |
| --- | --- | --- |
| Signature never reaches confirmed commitment | `ClientError::Rpc("signature not confirmed: {sig}")` (`client.rs:921-923`, `:939-941`) | `CLIENT_CONFIRMATION_TIMEOUT` (`client.ts:510-513`) |
| Confirmed `TRANSACT` carries no output view tags | `ClientError::Rpc("confirmed TRANSACT instruction has no output view tags")` (`client.rs:954-957`, `:982-985`) | `CLIENT_MISSING_OUTPUT` (`client.ts:516`) |

Both are inputs expressible in either language, and each names a different
error. The consequence reaches past naming, which is why this is worth a fix
rather than a note. `ClientError::retry_cause` maps `Rpc(_)` to
`RetryErrorCause::Rpc` (`sdk-libs/client/src/error.rs:233-240`), so Rust treats
both as retryable; TypeScript's `retryCause` returns `undefined` for both
(`client/src/retry.ts:139-169`), so a caller's retry loop spends its whole
schedule on one side and gives up at once on the other. "No output slots" is a
structurally permanent condition, so retrying it is the wrong behaviour.

Rust already has the variant it should be using: `ClientError::MissingOutput`,
"transaction has no output slots" (`error.rs:187-188`), defined and unreachable
from any production path. This is what the repository's own error rule forbids,
a bare generic where a precise variant exists.

**Do not fix this in TypeScript.** Adding the two codes to `retryCause` would
match Rust's classification by copying Rust's bug, and it would contradict a
Rust-generated oracle: `client/test/vectors/retry-schedule-oracle.test.ts:18-22`
maps the Rust variant `MissingOutput` to `CLIENT_MISSING_OUTPUT` and `:44`
replays it as the fatal case, which is correct for the variant and wrong only
for the call site that fails to raise it. Recommended Rust change, not made
here: return `ClientError::MissingOutput` at `client.rs:955` and `:983`, and add
a named confirmation-timeout variant for `:921` and `:939`. Both are small, and
the TypeScript side then needs no change at all.

**Also still open**, and out of this batch's scope: `fixtures/client/client.json`
does not exist, and generating it is `xtask` work.

## 8. W04 `sdk-libs/wallet/src/actions/transaction.rs` -> PARITY

The four original clauses hold at this HEAD, verified against Rust rather than
against the report: `applyP256Signature` reads the rail off the authority's own
address (`wallet/src/private-transaction.ts:82-89`), and `matchingInput`
compares tree, commitment, nullifier, `dataHash`, `zoneDataHash` and the whole
note through `sameUtxo` (`:41-50,58-75`), which is the field set Rust's derived
`PartialEq` compares. The substitution oracle from the `stragglers` work replays
eleven single-field substitutions through `signPrivateTransaction`.

The row's residue was that the rail rule itself is not observable through the
public TypeScript surface. **That is correct, and I confirmed the direction
rather than taking it**, because this branch has produced a backwards
strictness claim before. The discriminating input is a P256 authority spending
ed25519-owned notes. Rust's `ConfidentialTransfer::new` accepts it: it stores
`owner`, `inputs` and the payer hash and validates nothing
(`sdk-libs/transaction/src/instructions/transact/transfer.rs:89-97`); Rust's own
test builds one with `Vec::new()` at `:597`. TypeScript's constructor refuses it
before signing is reached (`transaction/src/instructions/transact.ts:633-649`).
TypeScript is the stricter side, as reported.

Because the refusal that hides the rail rule lives in another file, `W04` is at
parity for what it owns and the residue belongs to the row below.

### Unrecorded: T25 is closed at PARITY and carries three TypeScript-only rejections

`transaction/src/instructions/transact.ts:633-649` refuses, in the constructor,
three inputs that `ConfidentialTransfer::new` accepts:

| Input | TypeScript | Rust |
| --- | --- | --- |
| Empty input list | `TRANSACTION_NO_INPUTS` at construction | Accepted; `TransactionError::NoInputs` later, from `first_nullifier` in `prepare` (`spp_proof_inputs.rs:59-64`) |
| A dummy input | `TRANSACTION_DUMMY_INPUT_NOT_ALLOWED` | No counterpart on the transfer path |
| An input owned by anyone but the transfer owner, or carrying another nullifier key | `TRANSACTION_INPUT_OWNER_MISMATCH` | No counterpart on the transfer path |

The first is an early refusal that reaches the same error for a complete build.
The other two have no Rust counterpart anywhere before proving. `T25` is marked
`done` / `PARITY` and records deleting two other over-strict guards, the
zero-amount checks in `send` and `withdraw`, without mentioning these three.
Whether to delete them is the same judgement `T25` already made twice, and it
is what would make `W04`'s rail rule observable.

## 9. I37 `program-libs/interface/src/lib.rs` -> PARITY

Not `NOT_APPLICABLE`: the row has a real TypeScript counterpart in
`interface/src/index.ts`, and its constants and export surface are evidenced by
the interface oracle suite. The question was the one residue, the frozen-revision
fixture gate.

**It passes.** `npm run fixtures:check` at this HEAD reports
`verified 58 fixtures and 182 inventory rows`, exit 0. The `43fde8e4` mismatch
is gone because the gate was rebuilt rather than re-frozen: the revision strings
are provenance stamps now, and what catches drift is `--check` regenerating
every fixture from the working tree and byte-comparing it
(`xtask/src/bin/ts-fixtures.rs:29-38`). `canonicalSourceRevisions.baseline` and
`.interface` are both `8ce9897c` in `sdk-libs/ts/fixtures/manifest.json:2-7`.

The `G8-1` entry in [production-readiness-issues.md](../production-readiness-issues.md)
and the `fixtures:check` line in
[testing-and-conformance.md](../testing-and-conformance.md) both still describe
the old failure and should be updated by whoever owns them; neither is a
TypeScript gap.

## 10. X01 `sdk-libs/indexer-api/src/lib.rs` -> PARITY against the port target

Per instruction I picked no winner. Establishing what each of the three does
changed the shape of the question, because **two of the three are the same
artifact.** Photon does not define these schemas. It imports them:
`services/photon/src/api/method/rings/common.rs:15-17` and
`.../rings/get_nullifier_queue_elements.rs:8-11` take the request and response
types from `zolana_indexer_api` directly, and the production handler at
`:19-61` returns the crate's `GetNullifierQueueElementsResponse`. So Photon's
wire format is the Rust crate's wire format by construction, and the
disagreement is two-way: the specification against Rust, Photon and the port
together.

That is the disagreement
[the owner already ruled on](../authority-rulings.md#ruled-indexer-api-schema-authority-x01):
where Rust, the port and Photon agree, the agreement is authoritative and the
specification is stale. The port is correct as it stands, and none of the
following needs an SDK change.

### What each side does today

**The output and match schemas.** `docs/spec.md:1950-1958` gives
`EncryptedUtxoMatch` a flat `tag` and `ciphertext`; Rust gives it a nested
`output_slot: RingsOutputSlot` and a transaction-level `salt`
(`sdk-libs/indexer-api/src/lib.rs:492-502`), and the port decodes exactly that
(`indexer-api/src/codec.ts:238-255`). `docs/spec.md:1993-1997` gives
`OutputSlot` a `tag`, a flat `hash` and a `payload`; Rust's `RingsOutputSlot`
carries `view_tag`, a nested `RingsOutputContext { hash, tree, leaf_index }` and
`payload` (`lib.rs:517-530`).

**The transaction schema.** `docs/spec.md:1978-1991` omits three fields Rust
carries: `salt`, `messages` and `proofless`
(`lib.rs:540-555`).

**The nullifier queue endpoint.** `get_nullifier_queue_elements` exists in Rust
(`lib.rs:587-611`), in Photon
(`services/photon/src/api/method/rings/get_nullifier_queue_elements.rs:19`) and
in the port (`indexer-api/src/codec.ts:445-461`), and nowhere in `docs/spec.md`:
it is absent from the RPC contents list at `docs/spec.md:59-63` and from the
body. It is an undocumented extension, not a divergence.

**The integer domain**, which is the one place the specification is ahead rather
than behind. `docs/spec.md:1897-1909` now permits a decimal string alongside a
JSON number for any field the protocol does not bound below `2^53`, and names
the per-field test rather than only a field list. The port implements exactly
that: `unboundedWireInteger` on `block_time`, both `slot` fields, both
`root_seq` fields, and the nullifier-queue `seq` and `start_seq`
(`indexer-api/src/codec.ts:107-133,209,249,271,306,333,341,448`), and
`wireInteger` everywhere else. Rust declares all seven as plain `i64`/`u64` with
default serde and installs no string acceptor
(`sdk-libs/indexer-api/src/lib.rs:478,496,544,591,609,630,662`), so **Rust
refuses a body the amended specification permits.**

The port never writes one: every integer it encodes is a JSON number
(`codec.ts:160-197`), so no body the port produces is a body Rust rejects. The
string form is a reader's tolerance, which is what
[C04](../authority-rulings.md#ruled-the-u64-integer-domain-c04) ruled and closed
on.

### What an owner still has to decide

Two items, both outside `sdk-libs/ts` and neither blocking the port:

1. **Amend the indexer schemas in `docs/spec.md`** to the implemented shapes,
   and add a `get_nullifier_queue_elements` entry. This is the follow-up the
   X01 ruling already names; the text at `docs/spec.md:1933-1998` has not been
   touched yet.
2. **Decide whether Rust accepts the decimal string** the amended specification
   permits on those seven fields. If yes, the change is `serde(with = ..)` or a
   deserialize-with helper on each; if no, the specification's union has to be
   narrowed to a TypeScript-reader tolerance explicitly, because as written it
   is normative for any reader. Nothing in `sdk-libs/ts` moves either way.

Also still open from the ruling itself, and still true: the promised
`fixtures/indexer-api/lib.json` does not exist and needs an `xtask` generator,
and live-Photon evidence needs a running indexer.

## 11. Verification

Run in this tree at `59e6f095`, all green:

| Command | Result |
| --- | --- |
| `npm run build` | pass |
| `npm run typecheck` | pass, including the `K11` type-assertion project |
| `npm run test:unit` | pass |
| `npm run lint` | pass |
| `npm run lint:packages` | pass |
| `npm run test:vectors` | pass, including the new `C06` case |
| `npm run fixtures:check` | `verified 58 fixtures and 182 inventory rows` |
