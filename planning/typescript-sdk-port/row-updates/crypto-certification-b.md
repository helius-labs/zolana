# Cryptographic certification, K6 through K10

The second half of the certification phase in
[proof-and-key-parity.md](../proof-and-key-parity.md): transfer encryption,
merge verifiable encryption, secret ownership, the capability boundary, and the
error ledger. K1 through K5 belong to another worker and are not touched here.

## Bottom line

**All five suites are certified against fixtures generated from the running
`zolana-keypair` crate, and twenty-seven control edits were caught.** Nothing in
either cipher diverges: the keystreams, ciphertexts, hashes, and wrong-key
recoveries in the fixture match Rust byte for byte. Four divergences exist and none is in the
cryptography; three are deliberate and one is a defect in the port's error
mapping. One gap remains open in K9 because the interface narrowing it depends
on has not landed, and one bounded gap remains in K6 and K7 because the values
they certify are private to the Rust crate.

The one thing worth reading past the summary is [A row that could not detect a
divergence](#a-row-that-could-not-detect-a-divergence): a control edit passed,
which means one certification row was decorative, and it had to be rewritten
before the suite meant anything.

## The fixtures

`sdk-libs/keypair/tests/crypto_certification.rs` generates
`sdk-libs/ts/vectors/keypair-crypto-cert-v1.json` and asserts on every run that
the committed file still matches the crate, so a change to Rust breaks the Rust
test before it can silently pass the TypeScript one. Every value comes through
the crate's public API. Regenerate with `UPDATE_KEYPAIR_VECTORS=1 cargo test -p
zolana-keypair --test crypto_certification`.

It is a separate file from `parity_vectors.rs` on purpose: that file belongs to
the K1-K5 worker, and a shared generator would have been a file-level collision
between two agents working the same night.

### Why keystreams

Both ciphers are AES-256-CTR, so encrypting an all-zero plaintext returns the
raw keystream. The suites ask for the AES key, the nonce, and the initial
counter block as named values, and Rust exposes none of the three:
`derive_key_nonce` and the merge `key_schedule` are private, and the fixture
contract forbids re-deriving them in the generator. Five blocks of keystream pin
all three jointly, because changing any one of them changes every byte, and five blocks
catch a counter that increments in the wrong byte too.

What a keystream does not separate is a pair of compensating errors across the
key, the nonce, and the counter. No implementation produces that by accident,
but it is the honest limit of the evidence. See [Gaps](#gaps).

The generator also carries `vectors_rest_on_the_properties_they_claim`, which
checks that zero-plaintext output really is the keystream, that every boundary
row differs from its base, and that no two key-schedule labels share a
keystream. A fixture that stopped discriminating would fail there rather than
keep passing on both sides.

## K6, transfer encryption

`sdk-libs/ts/keypair/test/vectors/transfer-encryption-certification.test.ts`,
nine rows against `transferEncryption`.

Certified: ECDH in both directions; the joint key/nonce/counter derivation
through the keystream; each input of the HKDF info perturbed on its own (slot,
salt, recipient key, ephemeral key), with each row required to differ from the
base so the row proves the input reached the derivation; big-endian slot
encoding across all four bytes, with the 1 and 0x01000000 rows required to be
distinct so a little-endian port cannot pass; salt byte order; the full
ciphertext and both decryption directions; the exact garbage a wrong recipient
or wrong ephemeral key recovers, rather than merely "not the plaintext"; the
per-transaction viewing key the production flow actually encrypts under.

Truncation is certified rather than left as a gap. The cipher has no framing and
no length prefix, and the ciphertext is exactly as long as the plaintext, so a
truncated input decrypts to the matching prefix and nothing refuses it. Rows at
0, 1, one AES block short, and one byte short pin that, because a port that
added a length check here would reject inputs the protocol accepts.

Control edits, all caught:

| Edit | Result |
| --- | --- |
| Initial CTR counter 1 instead of 2 | 7 of 8 failed |
| Slot index dropped from the HKDF info | 7 of 8 failed |
| Slot index encoded little-endian | 7 of 8 failed |
| IKM concatenation order swapped | 7 of 8 failed |
| HKDF key/nonce split shifted one byte | 7 of 8 failed |
| Truncated input refused instead of decrypted | 4 of 9 failed |

## K7, merge verifiable encryption

`sdk-libs/ts/keypair/test/vectors/merge-encryption-certification.test.ts`, nine
rows against `mergeEncryption`.

Certified: ECDH in both directions; the Poseidon key schedule twice, once
through `encryptVerifiable` and once through `symmetricApply` from a pre-shared
secret, which isolates the schedule from the ECDH above it; a single flipped bit
of the shared secret reaching the whole keystream; `packInfo` at its 31/32 limb
split, at the byte position within a limb, and at the length prefix, with six
labels required to produce six distinct keystreams; the right-aligned trailing
chunk of `ciphertextHash` at lengths 1, 15, 16, 17, 31, 32, 33, 47 and 71, since
a left-aligning port agrees on the exact multiples of 16; `pack33` on both
y-coordinate parity branches; the bundle's ciphertext, recovery, and hash; the
exact garbage from a wrong user key, a wrong transaction key, and a tampered
byte; and truncation, where only the proof-committed hash moves.

Control edits, all caught:

| Edit | Result |
| --- | --- |
| AES key halves swapped | 5 of 8 failed |
| Nonce from the leading twelve bytes | 5 of 8 failed |
| Info length prefix dropped | 5 of 8 failed |
| Info limb left-aligned | 5 of 8 failed |
| `pack33` parity branch ignored | 3 of 8 failed |
| Trailing chunk padded right (in `@zolana/interface`) | 2 of 8 failed |
| Truncated bundle padded to a block | 3 of 9 failed |

The trailing-chunk edit is in `sdk-libs/ts/interface/src/merge-utils.ts`, which
keypair reaches through that package's `dist`, so it needed the interface
package rebuilt around the edit rather than the standard harness. The file was
restored and rebuilt afterwards; `git status` was clean.

## K8, secret ownership and lifecycle

`sdk-libs/ts/keypair/test/vectors/secret-lifecycle-certification.test.ts`, eight
rows against `secretLifecycle`.

Rust and TypeScript do not have the same lifecycle. Rust wipes on `Drop` through
`Zeroizing` and gives the caller no destruction; TypeScript has no drop, so it
exposes `destroy()`. The suite splits accordingly. The shared properties are
asserted against measured Rust behaviour: an exported secret is independent of
the key it came from, for both viewing and signing keys; a constructor copies
its input rather than aliasing it; `ShieldedKeypair.viewingKey()` duplicates the
way Rust's `Clone` does, so destroying one duplicate reaches neither the other
nor the source.

The `destroy()` half is measured against the threat model it exists for rather
than against a Rust counterpart, and the fixture records `rustHasExplicitDestroy:
false` so no reader mistakes it for parity. It walks the trait's own capability
list from the fixture, taking all fourteen viewing capabilities and confirming
each works before destruction and raises `KEYPAIR_INVALID_SECRET_KEY` with
`reason: "destroyed"` after, so a capability added later cannot escape the
check. Signing and nullifier keys get the same treatment, destruction is
idempotent, `signatureType()` survives because a rail is not key material, and
the error a destroyed key raises carries neither the secret nor the public key.

Control edits, all caught:

| Edit | Result |
| --- | --- |
| `secretBytes` returns the live buffer | 2 of 8 failed |
| Constructor aliases its input | 2 of 8 failed |
| `destroy` leaves the key usable | 2 of 8 failed |
| Nullifier secret export aliases the key | 1 of 8 failed |
| Keypair facade hands out its inner viewing key | 1 of 8 failed |

## K9, capability and HSM boundaries

`sdk-libs/ts/keypair/test/vectors/capability-boundary-certification.test.ts`,
five rows against `capabilityBoundary`.

The owner's 2026-07-26 ruling that an out-of-process viewing-key backend is not
a supported deployment is taken as settled; this suite certifies the boundary
that ruling implies and does not reopen where it sits.

`trait-surface.test.ts` already certifies the method lists by scraping the Rust
trait declarations, and that is not duplicated. This suite covers the rest:

- **A backend that is not a `ViewingKey` satisfies the interface.** The
  TypeScript adapter mirrors the Rust fixture's `BackendViewingKey`, which
  implements `ViewingKeyTrait` for a type that is not a `ViewingKey` and so
  proves at compile time that the surface is sufficient for a custodial backend.
- **Neither interface offers construction or secret export.** Checked at compile
  time with an `Extract<keyof Interface, ...> extends never` assertion over
  `secretBytes`, `fromBytes`, `fromSeed`, `generate` and `destroy`, and against
  the Rust exclusion list, which the generator reads out of the trait source
  rather than restating.
- **A full `ShieldedKeypair` stands in wherever a viewing backend is required**,
  as Rust's blanket impl does.
- **No capability returns a promise.** All fourteen viewing capabilities across
  three implementations, and all nine keypair capabilities.

The generator also records the Rust-to-TypeScript method mapping, reading the
Rust names out of the trait source and asserting the parsed lists are still
fourteen and ten long, because `zip` truncates and a method added to a trait
would otherwise drop out of the mapping instead of failing.

Control edits, all caught:

| Edit | Result |
| --- | --- |
| A viewing capability answers with a promise | 1 of 5 failed |
| A keypair capability answers with a promise | 2 of 5 failed |
| Backend output drifts from Rust's ciphertext | 1 of 5 failed |

### A row that could not detect a divergence

The third edit was originally written against a row that compared the adapter's
ciphertext to the concrete `ViewingKey`'s. The control edit passed: a change to
the key schedule moves both sides together, so the row could not detect one. It
was rewritten to assert Rust's recorded ciphertext, after which the same edit
failed it. This is the failure mode the phase exists to catch, and it was found
by the control edit rather than by reading the test.

## K10, error and redaction parity

`sdk-libs/ts/keypair/test/vectors/error-redaction-certification.test.ts`, eight
rows against `errorLedger`.

The ledger is closed: every case Rust reaches, every case it cannot, and every
case that is not an error at all. Each Rust row now names the port's boundary
for the same refusal, so the suite walks the ledger rather than a transcription
of it, and seven rows are checked to refuse at the mapped boundary with the same
Rust variant.

The rows that are *not* errors matter as much. CTR carries no authentication
tag, so a wrong slot, a wrong salt, and a tampered byte all decrypt successfully
to garbage, and a malformed signature returns `false` rather than raising. The
exact garbage is pinned, because a port that raised here would reject
transactions the protocol accepts.

Redaction is checked by feeding distinctive key material into every reachable
failure and searching every rendering a logger or a crash reporter would
produce: `message`, `String(error)`, `stack`, `JSON.stringify`, a spread, an
own-property replacer, `util.inspect` with hidden properties, and the whole
`cause` chain, each searched for the material as hex in both cases, base64,
latin1, and both array spellings. Nothing leaks, including through the noble and
hasher errors carried as causes, which report shapes rather than inputs. The
allowlist itself is tested: a `Uint8Array` handed to `details` is dropped, an
unknown key never reaches the error, and the cause stays non-enumerable while
remaining reachable.

Control edits, all caught:

| Edit | Result |
| --- | --- |
| Wrong variant at the prehash boundary | 1 of 7 failed |
| Info bytes reach the error details | 1 of 7 failed |
| Rejected secret reaches the error details | 1 of 7 failed |
| Cause becomes enumerable | 1 of 7 failed |
| Details copied without the allowlist | 1 of 7 failed |
| Merge hash boundary reports the Rust variant | 1 of 8 failed |

## Divergences

1. **`KEYPAIR_HASH` at the merge ciphertext hash is wrong, and it is the only
   defect found.** Rust's `merge_ciphertext_hash(&[])` reaches the hasher and
   returns `KeypairError::Poseidon`. The port wraps every hasher failure at that
   boundary as the TypeScript-only `KEYPAIR_HASH`, whose `rustVariant` is null.
   The two TypeScript-only codes exist because a JavaScript caller can reach
   shapes Rust cannot express, and an empty slice is not one of those: Rust
   accepts the call and answers with a variant the port has. Pinned as a
   divergence in the K10 suite rather than fixed, because the fix is
   `wrapKeypairError("KEYPAIR_POSEIDON", error)` at `merge/index.ts:63` plus the
   matching expectation in `test/security.test.ts:67`, and the same question
   applies to the two `KEYPAIR_HASH` sites in `public-key.ts`, which the K1-K5
   worker holds. It should be decided for all three at once.
2. **`NullifierKey::secret()` lends where TypeScript gives.** Rust returns
   `&[u8; 31]`, a borrow of live key material; TypeScript returns an owned copy.
   TypeScript is the stricter side, so this is recorded rather than reconciled.
3. **`sign` and `try_sign` are one method in TypeScript.** Rust's `sign` panics
   on a bad P256 prehash length and `try_sign` returns the error; a TypeScript
   throw is the same control flow as the `Result`, and the language draws no
   panic-versus-`Result` distinction for a caller to choose between. The fixture
   maps `try_sign` to `sign` and records Rust's `sign` as having no counterpart,
   so the method is accounted for rather than missing.
4. **`NotEd25519` is unreachable in the port.** Rust raises it only from
   `to_solana_keypair`, which returns a `solana_keypair::Keypair` the port does
   not carry. The code stays declared for ledger completeness, and the K10 suite
   scans the package sources to assert nothing throws it, so the claim stays
   true as the port grows. Asking a P256 key for its Ed25519 bytes raises
   `InvalidSignatureType` in both languages, which is certified.

There is also a small diagnostic-shape difference inside a matching variant:
Rust's `InvalidSignatureType(u8)` carries the offending prefix byte, and
TypeScript's `ShieldedPublicKey.ed25519()` sends `expected: "ed25519"` instead.
Same variant, same refusal, different payload. Not worth a change on its own.

## Gaps

| Gap | What would close it |
| --- | --- |
| K6, K7: the AES key, the nonce, and the initial counter are certified jointly through a keystream, not individually. Compensating errors across all three would pass. | A Rust accessor for `derive_key_nonce` and the merge `key_schedule` behind a test-only feature, recorded as three named values per row. This needs a decision on the fixture contract, which currently forbids re-deriving them in the generator. |
| K9: `ViewingKeyLike` and `ShieldedKeypairLike` still declare `T \| Promise<T>` returns, so the type admits an async backend the ruling excludes. The suite certifies that no implementation returns a promise, which is the consequence of the ruling for in-process backends, but a call site could still be written to await one. | Dropping the `\| Promise<...>` arms in `sdk-libs/ts/keypair/src/shielded.ts` and adding the type-level assertion that every capability's return type has no `Promise` member. Not done here: a separate agent may hold that narrowing, and the file is a collision risk. |
| K8: that `destroy()` and the internal `fill(0)` calls actually zero their buffers is unobservable from outside the class, so the suite certifies the behaviour they exist for, which is every capability refusing afterwards, rather than the wipe itself. | Nothing proportionate. A test-only accessor for the private field would weaken the property it is testing. |
| K10: `ZeroScalar` and `Hkdf` are unreachable from either language's public API, so neither is certified as behaviour. The suite asserts both stay in the variant mapping rather than being dropped, and the fixture records why each is unreachable. | Nothing. Reaching them would mean constructing an HKDF input whose derived P256 scalar is zero, or a call site asking for more than 255 hash blocks; neither exists. |

## Nothing needs a program or circuit change

Both ciphers agree with Rust on every input tested, including the ones the
circuit constrains: the merge ciphertext hash, its right-aligned trailing chunk,
and the `pack33` limbs on both parity branches. Nothing found here implies a
change to a program or a circuit.

## Reproducing

```bash
cargo test -p zolana-keypair --test crypto_certification
cd sdk-libs/ts/keypair && npx vitest run --config ../config/vitest.vectors.config.js certification
```

Control edits were driven through `tools/control-edit.mjs` from the keypair
package directory, except the `@zolana/interface` one, which needed that package
rebuilt around the edit.
