# P256 RFC 6979: closing the nonce divergence on the Rust side

Resolves the one open divergence from
[key-certification.md](key-certification.md#the-p256-nonce-divergence): for a
P256 prehash at or above the group order `n`, Rust and TypeScript produced
different (both valid) signatures for the same key and message.

## Bottom line

**Rust now reduces, and the two languages agree byte for byte.** The fix is a
reduction at the call site in `sdk-libs/keypair`, not an `ecdsa` upgrade. Three
recorded signatures changed, all of them K2 boundary cases that existed to pin
the divergence. Nothing else in the corpus moved, and nothing depended on the
old bytes.

## The finding, re-derived rather than trusted

Confirmed from the crate sources in the registry, not from the earlier
write-up:

| Claim | Where it is visible |
| --- | --- |
| Rust seeds the nonce unreduced | `ecdsa-0.16.9/src/signing.rs:159` calls `bits2field`, which left-pads or truncates but never reduces (`hazmat.rs:185`), then hands the result to `try_sign_prehashed_rfc6979`, which passes it straight to `rfc6979::generate_k` (`hazmat.rs:103`). |
| The crate being driven asks for a reduced input | `rfc6979-0.4.0/src/lib.rs:62`: "`h`: hash/digest of input message: must be reduced modulo `n` in advance". |
| Reducing cannot disturb anything else | `ecdsa-0.16.9/src/hazmat.rs:239`: `sign_prehashed` reduces the prehash itself before the signature equation. The nonce seed is the *only* thing the reduction reaches. |

The third row is what makes the fix safe rather than merely correct: below `n`
the reduction is the identity, and at or above `n` the signature equation was
already using the reduced value. Only `k` changes.

## Why not upgrade `ecdsa`

Checked first, as the better fix if it were available.

`0.16.9` is the **last** release of the `0.16` line, so there is no in-line
upgrade. Upstream did fix this, but only in `ecdsa` 0.17.0, which seeds through
`rfc6979::KGenerator::new` and applies `bits2octets` internally
(`rfc6979-0.6.0/src/lib.rs:74`); its doc now reads "Does not have to be reduced
in advance."

Reaching it means `p256` 0.13 to 0.14, which is the `elliptic-curve` 0.14
migration. Tried, measured, reverted: six errors in `zolana-keypair` alone, and
the breakage is the load-bearing kind rather than mechanical churn.

- **`rand_core` major bump.** `OsRng` no longer satisfies `CryptoRng`, so the
  whole workspace's `rand` has to move with it.
- **`Scalar::from_okm` is gone.** That is the RFC 9380 scalar reduction K5
  certifies (control edit 6 in the key-certification chain). Rewriting it under
  an upgrade risks a certified surface to fix an unrelated one.
- **It leaves `sdk-libs/`.** `GenericArray` to `Array` churn reaches
  `program-tests/spp-test-validator` and `program-tests/zone-test-program`,
  which are out of scope for this dispatch.

So: reduce at the call site, keep the dependency where it is. The upgrade
remains the right move whenever the workspace takes the `elliptic-curve` 0.14
migration for its own reasons, at which point this reduction becomes redundant
rather than wrong.

## Nothing depended on the old bytes

Checked before changing the signer, since regenerating something a client
depends on is a different decision than this one.

- **No cache, store, identifier, or key.** The P256 signature reaches exactly
  one place: the prover, as the `p256_sig_r` / `p256_sig_s` witness input. It is
  never hashed into a commitment, stored, or used as a map key. Every
  `tx_signature` in `sdk-libs/wallet` and `sdk-libs/client` is a Solana
  transaction signature, unrelated to this rail.
- **Committed fixtures: 19 JSON files carry P256 signature material.** Scanned
  all of them for a recorded prehash at or above `n`, since a signature can only
  move if its prehash is at or above `n`. Exactly four hits, all in
  `key-certification-v1.json`, and one of those (`signatureCases.maxDigest`) is
  a constructed negative case whose `verified: false` does not depend on the
  nonce. The other three are the K2 boundary cases this work is about.
- **The transaction path is reachable, and records nothing.**
  `SppProofInputs::message_hash` returns a raw `sha256` digest, not a field
  element masked below the modulus, so a real spend lands at or above `n` with
  probability about 2⁻³². No fixture records one, but the input class is live
  rather than theoretical, which is why the second call site below had to be
  fixed and not just noted.

## The change

Two call sites, both in `sdk-libs/`, both driving the crate rather than forking
it.

| File | Change |
| --- | --- |
| `sdk-libs/keypair/src/signing_key.rs` | `reduce_prehash` reduces the 32-byte prehash modulo the group order before `sign_prehash`. |
| `sdk-libs/transaction/src/wallet/authority.rs` | `sign_p256_with` built its own `EcdsaSigningKey` and so carried the same defect independently. Now routed through `SigningKey::try_sign`, so there is one signer. |

The second was not in the original finding. It is the path that signs real
transactions, and fixing only the keypair crate would have left it diverging.
Routing it through the one signer also resolves the rail *before* signing
rather than producing an ed25519 signature and rejecting it afterwards.

## The pins, turned around

K2 pinned the divergence from both sides so it could not drift silently. It now
pins the agreement, over the same boundary cases:

| Was | Is |
| --- | --- |
| `matchesReducedDigestSignature` is `false` | it is `true` |
| TypeScript's bytes differ from the recorded Rust bytes | they are identical |
| each side verifies the other's signature | unchanged, still asserted |
| TypeScript's `sign(z) == sign(z mod n)` | unchanged, still asserted |

Two things kept it from becoming a happy path. The loop still runs over every
at-or-above-`n` entry and asserts the reduction is observable
(`reducedDigestBytes != digestBytes`), so a case that stopped being a boundary
case fails rather than passing vacuously. And a second test reads the reduction
out of the **corpus alone**: an entry at or above `n` must carry the signature
Rust recorded for the digest it reduces to. A replay cannot satisfy that by
reducing the same way twice, which is the failure mode a pure replay has.

The corpus makes the property visible directly: `order` now signs to the same
bytes as `zero`, and `orderPlusOne` to the same bytes as `one`.

## Re-certification

The full chain, both directions, plus control edits in both languages.

| Step | Result |
| --- | --- |
| `cargo test -p zolana-keypair` | pass |
| Regenerate `key-certification-v1.json` | **6 changed leaves out of a 119 KB corpus**: `signatureBytes` and `matchesReducedDigestSignature` on the three at-or-above-`n` boundary cases. Everything else byte-identical. |
| `cargo test -p zolana-keypair --test key_certification_reverse` | pass, unchanged. Rust re-signs every TypeScript-produced signature and still gets identical bytes, which is the direct evidence the reduction is a no-op below `n`. |
| Regenerate `key-certification-typescript-v1.json` | **unchanged**, byte for byte. |
| `npm run test:vectors` (keypair) | 12 files, 269 tests, pass |
| `npm run test:vectors` (workspace) | 1432 tests, pass |
| `npm run test:unit` | 1943 pass, 1 skipped |
| `npm run test:cross`, `npm run test:property` | pass |
| `cargo test -p zolana-transaction`, `-p zolana-wallet` | pass |
| `cargo clippy` on both touched crates, `npm run typecheck`, eslint, prettier | clean |

**Control edits, one per language, each restored:**

| Edit | Caught by | Result |
| --- | --- | --- |
| Replay the pre-fix corpus against TypeScript | K2 | caught, exactly 2 of 269 |
| Remove `reduce_prehash` from the Rust signer | Rust generator | caught, corpus no longer matches |

Each fails the tests that should fail rather than everything, and the pin now
holds in both directions: whichever language stopped reducing would break here.

## Scope

`sdk-libs/keypair`, `sdk-libs/transaction`, `sdk-libs/ts/keypair`, and the two
committed corpora. No `programs/`, `program-libs/`, or `prover/` change, and no
dependency change. `review-checklist.md` is left to its reconciler.
