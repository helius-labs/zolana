# Secret redaction through `KeypairError` and the client wrapper

**No secret material reaches an error surface.** The keypair rewrite that
landed in `8d644562` and `d80af2ac` tightened four things and loosened none: it
replaced an open `Record<string, unknown>` details bag with a nine-key
allowlist, restricted values to `number` and `string`, made `cause`
non-enumerable, and added a `toJSON` that emits `name`, `code`, and `details`
only. All 39 detail values across the 24 `new KeypairError(...)` constructions in
`sdk-libs/ts/keypair/src` are a quoted label, a numeric bound, a module
constant, a length, an index, or the leading tag byte of a public key. Nothing
derived from a private key, a seed, a nullifier key, a viewing key, or a
plaintext is attached at any of them.

**The guarantee rests on those call sites, not on the sanitizer.** This is the
part worth flagging. `sanitizeDetails` bounds which detail *keys* survive; it
does not look at what they hold. A 32-byte secret rendered as hex and passed as
`{ name: material }` crosses the allowlist, crosses the client's denylist
because the key is `name`, and lands in `ClientError.cause.details.name` and in
`JSON.stringify` of the error. Verified by running, not inferred. The
protection today is that no call site does this, which is a property of the
call sites and was not tested until this report.

## 1. What populates `details` at each construction site

Read across all 16 files of `sdk-libs/ts/keypair/src`. Grouped by what the value
actually is:

- **Quoted labels naming the rejected argument.** `{ reason: "destroyed" }`
  (`nullifier-key.ts:77`, `signing-key.ts:163`, `viewing-key.ts:314`),
  `{ reason: "nonzeroPadding" }` (`public-key.ts:87`), `{ type: "p256" }`
  (`signing-key.ts:81`, `viewing-key.ts:117`), `{ expected: "ed25519" }` and
  `{ expected: "p256" }` (`public-key.ts:145`, `:152`), `{ name: "slotIndex" }`
  and `{ name: "account" }` (`viewing-key.ts:86`, `:125`).
- **Key-schedule labels.** `{ name: INFO_NULLIFIER }` (`nullifier-key.ts:45`)
  and `{ name: info }` (`viewing-key.ts:272`). These are HKDF `info` strings,
  the domain separators declared in `constants.ts:14-25` as `TSPP/nullifier`,
  `TSPP/tx_viewing` and siblings. They are the label the derivation is bound
  to, never its input keying material. The three private callers of
  `#viewSecret` pass constants (`viewing-key.ts:152`, `:160`, `:168`, `:189`).
- **Lengths and counts.** `{ actual: input.length }` (`poseidon.ts:50`),
  `{ actual: inputCount }` (`poseidon.ts:22`, `:29`),
  `{ actual: message.length }` (`signing-key.ts:113`),
  `{ actual: info.length }` (`merge/core.ts:43`), `{ actual: length }`
  (`viewing-key.ts:68`).
- **Bounds.** `{ minimum: 1, maximum: PARTIAL_ROUNDS.length }`
  (`poseidon.ts:23`), `{ maximum: 32 }` (`poseidon.ts:49`),
  `{ maximum: MAX_INFO_LENGTH }` (`merge/core.ts:42`), the `u64` and `u32`
  ceilings in `viewing-key.ts:76-88`.
- **Positions.** `{ index }` in `poseidon.ts:48` and `:55`, naming which input
  of a hash was rejected, not its value.
- **One byte of a public key.** `{ prefix: owned[0] ?? 0 }`
  (`public-key.ts:90`) and `{ prefix: this.#bytes[0] ?? 0 }`
  (`public-key.ts:113`). Byte 0 of the 34-byte tagged encoding is the
  signature-type discriminant, `0` for P256 and `1` for ed25519
  (`public-key.ts:84-91`, `:112-114`). It is public and it is exactly what
  Rust's `InvalidSignatureType(u8)` carries.

`invalidLength(name, expected, actual)` (`error.ts:116-118`) is reached only
through `checkedBytes` (`bytes.ts:19-28`). Its `name` is the label of the
rejected parameter, and all 23 `checkedBytes` call sites pass a string literal.
Several of those literals contain the word "secret", for instance
`"P256 signing secret"` (`signing-key.ts:78`) and `"wallet seed"`
(`viewing-key.ts:130`). Those are descriptions of which argument failed. The
material itself is never the argument.

Two sites are worth naming because they attach the length of something that
*is* secret. `KEYPAIR_FIELD_ELEMENT_TOO_LONG` carries the byte length of a
Poseidon input (`poseidon.ts:47-51`), and a Poseidon input can be a
right-aligned nullifier secret (`nullifier-key.ts:53-56`). Likewise
`invalidLength` carries the length of a rejected key. In both cases the value
is a length above a known bound, the operation already refused the input, and
the length is not the input. This is metadata about a rejection, not the
rejected material.

## 2. What crosses into `@zolana/client`

`KeypairError` is constructed nowhere outside `sdk-libs/ts/keypair/src`, so
`fromClientCause` only ever wraps errors built by the sites above.

Three layers apply, and they are not equally strong:

1. **`keypair/src/error.ts:71-82`, an allowlist.** Copies the nine keys of
   `KeypairErrorDetails` and only where the value is a `number` or a `string`.
   A `Uint8Array`, a nested object, or an unknown key is dropped before the
   error exists.
2. **`client/src/error.ts:608-613` and `:680-710`, a denylist.** Re-walks the
   surviving details and drops any key matching
   `/(secret|private|seed|blinding|nonce|scalar)/iu`, deep-copying and freezing
   what remains.
3. **`client/src/error.ts:565-602`, cause replacement.** `safeCause` builds a
   fresh frozen `{ category, code, details? }` and the constructor stores that.
   The original `KeypairError` instance is not retained anywhere on the
   `ClientError`.

Layer 3 is what closes the highest-risk path. `encryption.ts:13-19` and
`:35-43`, `poseidon.ts:62-64`, and `signing-key.ts:126-128` hand the underlying
`@noble` rejection to `wrapKeypairError` while operating on secret material,
and a dependency message can quote the bytes it refused. `keypair/src/error.ts:96-101`
already keeps that cause off enumeration and out of `toJSON`, so it never
reaches `JSON.stringify` or a spread. The client then drops the link entirely:
`safeCause` reads `cause.code` and `cause.details` and never `cause.cause`.
Confirmed by running, with `new Error("ikm=<64 hex chars>")` as the cause: the
wrapped client error is `{ category: "keypair", code: "KEYPAIR_HKDF" }`, has no
`cause` property on its cause, and its JSON does not contain the hex.

Freezing and deep copying hold. `copyAndFreeze` and `cloneSafeValue`
(`client/src/error.ts:655-678`) rebuild `details` from own data properties
only, throwing on an accessor and on any value that is not a primitive, an
array, or a plain object, so a caller cannot reach nested state through the
error and cannot mutate it afterwards. `sanitizeDetails` freezes each nested
object and array it produces. Because the keypair allowlist already flattens
details to primitives, the client's recursion has nothing to recurse into on
this path.

One correctness wart, not a leak: the `seen` `WeakSet` in
`client/src/error.ts:683-695` is added to and never removed, so it drops a
repeated reference rather than only a cycle. Given `{ a: X, b: X }`, `b`
disappears. It is invisible on the keypair path for the same flattening reason.

## 3. What Rust does at the same sites

Rust carries strictly less structured detail and strips strictly less.

`sdk-libs/keypair/src/error.rs:3` derives `Copy`, so no variant can hold a
`String` or a `Vec<u8>`. The entire payload surface of the Rust error is three
integers: `InvalidSignatureType(u8)` at line 15, `Poseidon(u32)` at line 24,
and `InvalidPrehashLength(usize)` at line 30. Every other variant is a unit
variant, including `Hkdf` and `FieldElementTooLong`, where TypeScript attaches
a label or a length. The two TypeScript-only codes, `KEYPAIR_INVALID_LENGTH`
and `KEYPAIR_HASH`, exist because Rust rejects those shapes in the type system
and never reaches a runtime error, which `error.ts:1-19` already states.

So TypeScript is wider than Rust, by labels, bounds, indices, and lengths. It
is not wider by anything secret-derived, and the widening covers checks Rust
performs at compile time. Recorded as a deliberate divergence rather than a
defect.

In the other direction Rust keeps more. `sdk-libs/client/src/error.rs:16-17`
declares `Keypair(#[from] KeypairError)`, so `thiserror` generates both the
conversion and a `#[source]`, and the whole `KeypairError` value stays
reachable through `Error::source()`. Its `Display` prints
`"keypair error: {0}"`, the full inner rendering including the integer payload.
Rust has no analogue of `safeCause` or `sanitizeDetails`: it propagates the
keypair error verbatim and strips nothing. TypeScript's redaction layer is
additional hardening with no Rust counterpart, and the price is that a
TypeScript consumer cannot reach the originating `KeypairError` or the
dependency error beneath it, both of which a Rust consumer still reads through
`source()`.

## 4. Whether the existing test would catch a regression

Partly, and for the wrong reason.

`client/test/error.test.ts` asserted that a wrapped `KeypairError` cause has no
`details`, using the fixture
`{ public: {...}, private: {...}, nested: { seed, value } }`. Every key in that
fixture is outside `KeypairErrorDetails`, so the assertion only ever
demonstrated that unknown keys are dropped. It never put a value under a known
key, which is the one shape that can carry a secret through. The companion
assertion, `JSON.stringify(wrapped)` not containing the sentinel, passed for
two independent reasons at once, the allowlist and the denylist, so it isolated
neither.

Three further gaps. The wrapper test used `toMatchObject`, a subset match, so a
key that survived sanitizing into `cause.details` would not have failed it.
Nothing exercised key material arriving as a `Uint8Array`. And nothing
exercised the dependency-rejection path at all, although that is the only place
where a message quoting real bytes exists.

The tests are strengthened in `3e2360b2`. Three controls confirm each new
assertion is falsifiable:

| Control edit | Result |
| --- | --- |
| `sanitizeDetails` returns its input unfiltered | "drops key material" fails, alongside the pre-existing test |
| A call site passes `{ name: toHex(bytes) }` | The call-site scan fails, naming `nullifier-key.ts:45` |
| A call site passes `checkedBytes(bytes, 32, describe(bytes))` | The label scan fails, naming `signing-key.ts:78` |
| `safeCause` keeps `cause.cause` | "drops key material" fails; **the pre-existing test passes** |

The last row is the point. The dependency-cause path had no coverage, so a
change that reconnected the client to the underlying `@noble` error would have
landed green.

The scan then caught an unrelated in-flight change on its first full run, which
is the fairest test it could have had. The `bigIntToBytes` overflow fix adds
`{ expected: length, actual: width }` at `keypair/src/bytes.ts:50`, and `width`
is a locally computed count of significant bytes rather than a literal.
Adjudicated as a length and admitted: the two callers inside the package pass
domain-separation constants and a Poseidon digest, never a secret scalar, and
the pair mirrors Rust's `InvalidInputLength(usize, usize)`
(`program-libs/hasher/src/errors.rs:19`). The point is that the addition
required a decision instead of passing unnoticed.

Because no runtime check can tell the label `"wallet seed"` from a secret
rendered as hex under the same key, the new suite pins the invariant where it
actually lives. One test asserts the residual honestly, that a known key
crosses intact, so nobody reads the sanitizer as protection it does not offer.
A second reads all 16 keypair sources and requires every one of the 39 detail
values and all 23 `checkedBytes` labels to be a literal, a module constant, a
length, a tag byte, or one of eight audited parameters. Both scans assert a
floor on what they matched, so a rename that stopped them matching fails rather
than passing vacuously.

## 5. Recommended keypair-side change, not made

`keypair/src/error.ts` belongs to the running `port/keypair` batch, so per the
plan's rule this is recorded rather than applied.

Bound the allowlisted string values. Every label the package passes today is a
short descriptor; the shortest secret it could carry is 44 characters in base64
or 64 in hex, while the longest current label,
`"transaction viewing public key"`, is 30. A cap in the low forties separates
them with room to spare and turns the call-site discipline into a runtime
invariant. It would also make the source scan in the client test redundant,
which is the better end state.

## 6. Related observations

**The transaction branch is the weaker one.** `safeCause` treats
`TransactionError` the same way it treats `KeypairError`, but
`transaction/src/error.ts:97` types details as an open
`Record<string, TransactionErrorValue>` guarded only by a denylist at line 183.
The denylist misses `plaintext`, `mnemonic`, `entropy`, `ikm`, `okm`,
`viewingKey`, and `nullifierKey`. It is not exploited today: the surveyed
construction sites pass field names, indices, counts, and amounts. Amounts in
errors match Rust, which puts them in `InsufficientBalance` and
`SplitNotDivisible` (`sdk-libs/client/src/error.rs:34-35`, `:119-120`), so that
is parity rather than a leak. `unknownTransactionError`
(`transaction/src/error.ts:131-136`) forwards an arbitrary payload object into
details and has no callers, which makes it a latent surface worth deleting or
constraining.

**`npm run test:unit` validates build output.** Packages resolve each other
through their `exports` map, so a cross-package test imports `dist`, not `src`.
A stale `dist` or a stale vite transform makes the suite report the previous
build. That produced a false failure on this branch immediately after the
keypair merge, and the symmetric case, a false pass, is worse. `npm run check`
is unaffected because `check:static` builds first. Running `test:unit` alone is
only meaningful after a build.

**Test files are not type-checked.** `config/typecheck.mjs` runs `tsc` against
each package's `tsconfig.json`, and those include `src/**/*.ts` only. Type
errors in `test/**` are caught only as far as the typed ESLint rules reach.

**Two pre-existing lint errors on this branch**, both in another batch's
package and unrelated to this work:
`interface/src/codecs/index.ts:141` and `interface/src/instructions/index.ts:14`.
`npm run lint` is clean; `npm run lint:packages` is not.

## 7. Verified by running versus concluded by reading

Verified by running:

- A hex string under the allowlisted key `name` reaches
  `ClientError.cause.details.name` and appears in `JSON.stringify`.
- A `Uint8Array`, a nested object, and an unknown key are each dropped, leaving
  the cause exactly `{ category, code }`.
- A dependency error quoting 64 hex characters does not reach the client cause,
  which carries no `cause` property, and does not appear in the JSON.
- `JSON.stringify` of a raw `KeypairError` yields `{ name, code }` only, and
  its own enumerable keys are `code`, `details`, `name`, so the dependency
  cause survives neither serialization nor a spread.
- Each of the four control edits in section 4 fails the intended assertion, and
  the pre-existing test misses the fourth.
- `npm run test:unit` at 1021 passing and 1 skipped, `npm run typecheck` and
  `npm run lint` clean, `review-checklist-check.mjs` exit 0.

Concluded by reading:

- That the 39 detail values and 23 `checkedBytes` labels are what section 1
  describes, now also enforced by the scan.
- That the HKDF `info` labels are the constants in `constants.ts` at every
  private call site.
- That Rust's `Copy` derive bounds its payload to three integers, and that
  `#[from]` keeps the keypair error reachable through `source()`.
- That `unknownTransactionError` has no callers.
