# TypeScript SDK production-readiness issue register

## Status and purpose

This register records the open issues that block a production-readiness claim for the TypeScript
SDK, the evidence behind each one, and what closing it would require. The 26 findings are now
scheduled. The [scheduling table](#scheduling) places each finding in one phase of the delivery
sequence in [`review-checklist.md`](review-checklist.md#deterministic-selection), names the plan
document or work packet that owns it, and names the gate that proves closure.

Several findings restate work that
[`proof-and-key-parity.md`](proof-and-key-parity.md#implementation-work-packets) already owns. Those
rows point at the existing PKP packet rather than open a second work item beside it.

Verification snapshot:

- branch: `ts-sdk-port`;
- worktree HEAD: `b230b314dc8546df831f3b6901874c93e866003e`;
- worktree state: dirty, with uncommitted edits under `sdk-libs/ts/client`, `sdk-libs/client`,
  `sdk-libs/transaction`, and `xtask`;
- fixture baseline (`sdk-libs/ts/fixtures/manifest.json` `frozenCommit`):
  `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`;
- checklist baseline: `31 done / 118`, `60 needs_fix`, `0 needs_re_review`, `27 todo`;
- verification date: 2026-07-25.

The findings were first recorded at `7c697c2c7e63a824a383c29a7cbb940a0e9b4e92`. Before scheduling,
the five load-bearing claims (G1-3, G3-1, G8-1, G9-1, G9-2) were re-read against the worktree at the
HEAD above. Two had drifted; the correction is recorded under the issue. Where a claim depends on
the Rust or specification counterpart, both sides are cited. Line numbers move, so treat the cited
symbol name as the durable anchor and re-confirm before acting.

Because the worktree is dirty, a finding may already be under repair in the uncommitted `K01`
through `K03` and `C04` work. Confirm against a clean tree before starting on one.

## How to read a severity

| Level     | Meaning                                                                                        |
| --------- | ---------------------------------------------------------------------------------------------- |
| `blocker` | A release claiming parity or production readiness would be false while this is open.           |
| `high`    | Silent divergence from the Rust or specification contract, reachable through the public API.   |
| `medium`  | Contract is unproven rather than known-wrong, or the gap needs a caller mistake to be reached. |
| `low`     | Hygiene, typing, or documentation drift with no known exploit path.                            |

Severity describes consequence if shipped, not implementation cost.

## Group summary

| Group | Theme                                    | Items | Highest severity |
| ----- | ---------------------------------------- | ----- | ---------------- |
| G1    | Range and length validation              | 4     | `high`           |
| G2    | Signature acceptance policy              | 3     | `high`           |
| G3    | Circuit coverage in the prover path      | 2     | `blocker`        |
| G4    | Absent verification oracle               | 3     | `blocker`        |
| G5    | Error taxonomy and secret redaction      | 3     | `high`           |
| G6    | Secret lifecycle and custody boundary    | 3     | `medium`         |
| G7    | Specification authority conflicts        | 2     | `blocker`        |
| G8    | Fixture and proving-key provenance       | 2     | `high`           |
| G9    | Continuous integration and release gates | 4     | `blocker`        |

## Scheduling

The delivery sequence in
[`review-checklist.md`](review-checklist.md#deterministic-selection) has five phases: review the 118
primary rows, remediate and independently re-review, resolve specification-authority blockers, pass
the package and full SDK gates, then run PKP-00 through PKP-08.

No finding lands in phase 1, which is read-only row review, and none lands in phase 4, which
evaluates gates rather than producing changes. Four findings (G8-1, G9-1, G9-2, G9-4) are
remediated in phase 2 and proven by gate lines added to the phase-4 gate sets.

### Phase 2: remediation and independent re-review

G9-1 and G9-2 are listed first because they are ordered first. Phases 3, 4, and 5 each rest on a
claim that a gate passed. While no workflow runs the TypeScript scripts and the aggregate `check`
script skips the cross-language and prover suites, that claim rests on one contributor's local
shell, which a reviewer cannot reproduce. Fixing the two of them turns the later gate rows into
evidence.

| Issue | Severity | Owner artifact | Now | Closed when | Proven by |
| ----- | -------- | -------------- | --- | ----------- | --------- |
| G9-1 | `blocker` | [`testing-and-conformance.md`](testing-and-conformance.md#continuous-integration-tiers) | `typescript.yml` runs `npm run check` on pull requests, one job per sub-script behind a `merge gate` job. | A pull-request workflow runs the merge gate. | Full SDK gate: a repository workflow runs the TypeScript gate set. |
| G9-2 | `blocker` | [`testing-and-conformance.md`](testing-and-conformance.md#continuous-integration-tiers) | `check` is composed of `check:static`, `check:suites`, `check:packaging`, `check:fixtures`, and `check:e2e`, which cover the ten formerly excluded suites. | Those suites run in the merge gate, and `check` states its real scope. | Full SDK gate: the merge gate covers the named suites. |
| G9-3 | `medium` | [`testing-and-conformance.md`](testing-and-conformance.md#continuous-integration-tiers) | `format:check` enumerates paths by hand, so a new package stays unformatted. | The list is glob-based with explicit ignores and covers `planning/`. | `npm run format:check` fails on an unformatted new file. |
| G9-4 | `medium` | [`testing-and-conformance.md`](testing-and-conformance.md#failure-lag-and-runtime-matrix) | `browser-check.mjs` greps sources and bundles with esbuild. | The keypair and transaction vector suites execute in headless Chromium, with the required Web Crypto surfaces named. | Package gate: browser-capable packages execute their vectors in a browser engine. |
| G8-1 | `high` | [`testing-and-conformance.md`](testing-and-conformance.md#fixture-layout-and-provenance) | The manifest pins four source revisions plus five more identity keys, with no compatibility rule. | Each revision key has a stated compatibility rule and a regeneration trigger, and a check rejects an incompatible pin. | Full SDK gate: the fixture provenance check rejects an incompatible revision combination. |
| G1-1 | `high` | [`review-checklist.md`](review-checklist.md) rows `T23`, `C06`, `C10` | `signedField` reduces any `bigint` into BN254. | Values outside the signed 64-bit range throw a typed error before the field map, and the owning layer is recorded. | Boundary vectors for `i64::MIN`, `-1`, `0`, `i64::MAX`, and one value past each end. |
| G1-2 | `high` | [`review-checklist.md`](review-checklist.md) row `K07` | `hashField` zero-extends a short input. | `hashField` rejects input that is not 32 bytes, and `splitBigEndian128` has a recorded export decision. | Keypair rejection vectors for each non-32-byte length Rust forbids. |
| G1-3 | `high` | [PKP-02](proof-and-key-parity.md#pkp-02-complete-key-encoding-and-signature-parity) plus row `K05` | The 34-byte value is declared `Bytes33` and cast on return. | A `Bytes34` brand replaces both signatures and the casts are gone. | Compile-time negative test: a 33-byte value stops type-checking. |
| G1-4 | `low` | [`review-checklist.md`](review-checklist.md) row `K07` | `fieldFromBytes` normalizes any length with no stated domain. | The domain is stated, plus either a check or a named caller invariant. | Keypair vectors covering the stated domain edge. |
| G2-3 | `medium` | [`review-checklist.md`](review-checklist.md) row `K02` | `sign` accepts any message length. | `sign` is recorded as general-purpose or asserts the 32-byte protocol digest. | Keypair vectors for the accepted and rejected lengths. |
| G5-1 | `high` | [`security-and-release.md`](security-and-release.md#secret-and-authority-boundary) plus row `K10` | `wrapKeypairError` attaches the raw `@noble` error as `cause`. | The redaction rule for `cause` is written and enforced at the wrap site. | Test: no serialized keypair error contains input-derived bytes. |
| G5-2 | `high` | [`review-checklist.md`](review-checklist.md) row `K10` | Distinct Rust `KeypairError` variants share codes such as `KEYPAIR_HASH`. | A code-per-variant table exists, with each deliberate merge justified. | Keypair vectors asserting one code per listed Rust variant. |
| G5-3 | `medium` | [`testing-and-conformance.md`](testing-and-conformance.md#differential-and-cross-package-tests) | The Rust-to-TypeScript error mapping exists only in prose. | The generator records `(input, rust_error_variant)` pairs. | `npm run fixtures:check` plus the cross-language mapping test. |
| G6-1 | `medium` | [`security-and-release.md`](security-and-release.md#secret-and-authority-boundary) | The port states no position on secret lifetime in JavaScript. | A threat statement names what is and is not mitigated, and SDK-owned buffers are cleared after use. | Security sign-off in the phase-4 gate set; extended by [PKP-04](proof-and-key-parity.md#pkp-04-enforce-capability-and-secret-boundaries) K8. |
| G6-2 | `medium` | [`testing-and-conformance.md`](testing-and-conformance.md#property-and-mutation-gates) | `copyBytes` is used on several return paths; the set has not been audited. | Each public accessor returning secret-adjacent bytes has an aliasing test. | Package gate: the aliasing suite mutates each returned buffer and asserts internal state. |

### Phase 3: specification-authority rulings

| Issue | Severity | Owner artifact | Now | Closed when | Proven by |
| ----- | -------- | -------------- | --- | ----------- | --------- |
| G7-1 | `blocker` | [PKP-00](proof-and-key-parity.md#pkp-00-resolve-authorities-and-freeze-scope) plus the checklist rows marked `BLOCKED` | `docs/spec.md` builds `owner_hash` from the parity-inclusive `pk_field`; the program, circuit gadget, Rust, and TypeScript use the parity-free form. | The specification describes both encodings, names which one enters `owner_hash`, and restates the collision argument for the parity-free form. | PKP-00 exit: no disputed behavior is labelled canonical. |
| G7-2 | `blocker` | [`proof-and-key-parity.md`](proof-and-key-parity.md#authority-and-conflict-policy) plus [`README.md`](README.md#source-precedence) | Two authority orders exist and differ; neither carries a per-conflict ruling row. | One reconciled order, one resolution procedure, and one row per open conflict with its ruling and the artifact changed. | PKP-00 exit plus the reconciled conflict ledger. |
| G2-1 | `high` | [PKP-02](proof-and-key-parity.md#pkp-02-complete-key-encoding-and-signature-parity) K2 | Production signing pins `lowS: true`; the prover vector helper pins `lowS: false`. | The circuit's ECDSA gadget and the Go prover are read, the policy is recorded as the authority, and both call sites match it. | PKP-02 K2 corpus, covering low-S and equivalent high-S signatures. |
| G2-2 | `medium` | [PKP-02](proof-and-key-parity.md#pkp-02-complete-key-encoding-and-signature-parity) K3 | `zip215: false` is pinned with no recorded rationale against the Solana runtime's policy. | The Ed25519 authority is named and any deliberate strictness is documented. | PKP-02 K3 corpus: a signature valid under one convention and not the other. |

### Phase 5: PKP-00 through PKP-08

Each row here maps onto a packet that already exists. None of them creates a new packet.

| Issue | Severity | Owner artifact | Now | Closed when | Proven by |
| ----- | -------- | -------------- | --- | ----------- | --------- |
| G3-1 | `blocker` | [PKP-05](proof-and-key-parity.md#pkp-05-complete-proof-assembly) | `ProverInputs` covers `transfer` and `transferP256`; Rust has five transact-family entry points. | The union and assembly cover zone Ed25519, zone P256, and zone authority. | PKP-05 exit: one public-input hash fixture per circuit, generated from Rust, at the supported shapes. |
| G3-2 | `medium` | [PKP-05](proof-and-key-parity.md#pkp-05-complete-proof-assembly) | `prepareZoneAuthority` returns a type no prover consumes. | The prepared type is reconciled against the Rust `ZoneAuthorityProver` inputs. | PKP-05 exit for the zone-authority identity. |
| G4-1 | `blocker` | [PKP-06](proof-and-key-parity.md#pkp-06-add-native-verification-certification) | TypeScript proof tests compare against Rust-recorded fixtures only. | The test-only Rust oracle verifies TypeScript-assembled public inputs and proofs at the same revision. | PKP-06 exit: a TypeScript-produced artifact verifies only under its intended public input and key. |
| G4-2 | `blocker` | [PKP-07](proof-and-key-parity.md#pkp-07-add-real-prove-to-chain-acceptance) | The two live suites reach a validator; neither sends a proof through the shielded pool. | Deposit, transact, and withdraw run against the same-revision local stack with a TypeScript-assembled proof. | PKP-07 exit: state transitions asserted, no stub in the proving, submission, or indexing path. |
| G4-3 | `medium` | [PKP-06](proof-and-key-parity.md#pkp-06-add-native-verification-certification) tamper matrix | Adversarial coverage is thin next to `sdk-libs/client/tests`. | One negative case per public input and per proof component, each asserting a named typed rejection. | PKP-06 tamper matrix, with the G5-2 code split as its prerequisite. |
| G6-3 | `medium` | [PKP-04](proof-and-key-parity.md#pkp-04-enforce-capability-and-secret-boundaries) K9 | Ruled: a signing-only custodian is not supported. A custodian holds nullifier and viewing key material, and `shielded.ts` states that at both interfaces. | The ruling is recorded and the interfaces state the requirement. | PKP-04 K9 conformance adapters, each holding that key material. |
| G8-2 | `high` | [PKP-01](proof-and-key-parity.md#pkp-01-harden-fixture-provenance) | `provingKeyRelease` pins a lock hash; no proof fixture records the verifying key it was produced against. | Each proof fixture records the verifying-key module and its SHA-256. | PKP-01 exit plus the full SDK gate that fails on a verifying-key identity mismatch. |

## G1. Range and length validation

These share one root cause. The Rust reference encodes its domain in the type (`[u8; 32]`, `i64`),
so an out-of-domain value cannot be constructed. The TypeScript port replaces those types with
`Uint8Array` and `bigint`, which admit any length or magnitude, and then normalizes silently instead
of rejecting.

### G1-1 Public amounts are reduced modulo the field instead of range-checked (`high`)

Scheduled: phase 2, owned by [`review-checklist.md`](review-checklist.md) rows `T23`
(`spp_proof_inputs.rs`, which holds the Rust `signed_to_field`), `C06` (`field.rs`), and `C10`
(`witness.rs`, which owns `assembly.ts`). The layer decision belongs to `T23` and `C10` together.

`signedField` maps an arbitrary `bigint` into the BN254 field with a double modulo, so a value
outside the protocol's signed 64-bit amount domain produces a valid-looking field element rather
than an error:

```472:475:sdk-libs/ts/client/src/prover/assembly.ts
function signedField(value: bigint, name: string): bigint {
  const result = ((value % BN254_MODULUS) + BN254_MODULUS) % BN254_MODULUS;
  return field(result, name);
}
```

The Rust counterpart takes `i64`, so the domain bound is structural and no reduction is reachable:

```32:40:sdk-libs/transaction/src/instructions/transact/spp_proof_inputs.rs
pub fn signed_to_field(value: i64) -> [u8; 32] {
    let magnitude = BigUint::from(value.unsigned_abs());
    let field = if value < 0 {
        modulus() - magnitude
    } else {
        magnitude
    };
    right_align_slice(&field.to_bytes_be())
}
```

Rust callers make the bound explicit at the boundary, as in
`i64::try_from(net_public(Asset::Sol)).expect("public amount fits i64")` in
`sdk-libs/client/tests/steps/transfer.rs`, and `ExternalData::public_sol_amount` is `Option<i64>`.
The TypeScript public amount type is unbounded `bigint` at both layers: `publicAmounts` in
`sdk-libs/ts/transaction/src/instructions/builders.ts`, and `assembly.ts` lines 188 to 189.

Impact: a caller passing an amount above `i64::MAX` gets a proof request whose public SOL or SPL
amount silently differs from the value it asked for. Balance conservation still holds inside the
circuit, so the proof would be internally consistent for an amount the caller did not ask for.

Closing this requires: reject outside the signed 64-bit range with a typed error before the field
map, plus a fixture case per boundary (`i64::MIN`, `-1`, `0`, `i64::MAX`, and one value past each
end) proving Rust and TypeScript agree on both the accepted encodings and the rejections. It also
requires a decision on which layer owns the check, since Rust places it in `transaction` and
TypeScript currently places it in `client`.

### G1-2 `hashField` accepts any input length and zero-pads (`high`)

Scheduled: phase 2, owned by [`review-checklist.md`](review-checklist.md) row `K07`.

```8:18:sdk-libs/ts/keypair/src/hash.ts
export function splitBigEndian128(value: Uint8Array): readonly [Uint8Array, Uint8Array] {
  const low = new Uint8Array(32);
  const high = new Uint8Array(32);
  high.set(value.subarray(0, 16), 16);
  low.set(value.subarray(16, 32), 16);
  return [low, high];
}

export function hashField(value: Uint8Array): Bytes32 {
  return poseidon(splitBigEndian128(value)) as Bytes32;
}
```

Rust fixes the length in the signature, so both limbs are populated for any accepted input:

```10:21:sdk-libs/keypair/src/hash.rs
pub fn hash_field(value: &[u8; 32]) -> Result<[u8; 32], KeypairError> {
    let (low, high) = split_be_128(value);
    poseidon(&[&low, &high])
}
```

Impact: a short input is zero-extended, so a 16-byte value and the 32-byte value whose low half is
zero hash to the same field element. `hashField` feeds `hashPublicKeyX`, the asset field, and the
owner-tag derivation, so a length slip upstream yields a colliding commitment rather than a thrown
error. No current call site is known to pass a short slice. The hazard is that nothing prevents one.

Closing this requires: a 32-byte length assertion in `hashField`, a recorded decision on whether
`splitBigEndian128` stays exported and lenient, and a rejection fixture for each non-32-byte length
that the Rust type forbids.

### G1-3 The 34-byte tagged public key is typed as `Bytes33` (`high`)

Scheduled: phase 2, owned by [PKP-02](proof-and-key-parity.md#pkp-02-complete-key-encoding-and-signature-parity),
which already lists "correct 34-byte TypeScript public-key type" as a deliverable, and by
[`review-checklist.md`](review-checklist.md) row `K05`. The type change lands with the other
remediation work; PKP-02 K1 certifies the parse and encode interface afterwards.

`SHIELDED_PUBLIC_KEY_LENGTH` is 34, but the parse and return signatures declare `Bytes33`, and the
return value is cast rather than checked:

```70:74:sdk-libs/ts/keypair/src/public-key.ts
  static fromBytes(bytes: Bytes33): ShieldedPublicKey {
    const owned = checkedBytes<Uint8Array>(
      bytes,
      SHIELDED_PUBLIC_KEY_LENGTH,
```

```88:90:sdk-libs/ts/keypair/src/public-key.ts
  toBytes(): Bytes33 {
    return copyBytes(this.#bytes) as Bytes33;
  }
```

Partially repaired since the finding was recorded. The inner call was `checkedBytes<Bytes33>` and is
now `checkedBytes<Uint8Array>`, so the local branded value is gone. The declared parameter type, the
declared return type, and the `as Bytes33` cast remain.

The runtime length check uses the correct constant, so behavior is right today. The declared type is
wrong, which means the compiler accepts a genuine 33-byte value here and rejects a correct 34-byte
one, and the `as Bytes33` cast suppresses the diagnostic that would catch it.

Impact: no current mis-encoding, but the branded-length system, which is the port's main defense
against byte-layout drift, is disabled at the boundary between the 33-byte P256 encoding and the
34-byte tagged encoding. That is the layout most likely to be confused.

Closing this requires: a `Bytes34` brand, corrected signatures on `fromBytes` and `toBytes`, removal
of the casts, and a compile-time negative test proving a 33-byte value no longer type-checks.

### G1-4 `fieldFromBytes` normalizes without a stated domain (`low`)

Scheduled: phase 2, owned by [`review-checklist.md`](review-checklist.md) row `K07`.

```49:51:sdk-libs/ts/keypair/src/hash.ts
export function fieldFromBytes(bytes: Uint8Array): Uint8Array {
  return bigIntToBytes(bytesToBigInt(bytes));
}
```

The function accepts any length and returns a canonical 32-byte encoding. Whether an input at or
above the field modulus should be rejected, reduced, or is unreachable by construction is not
documented, and the Rust side has no single equivalent to compare against.

Closing this requires: a statement of the intended domain, then either a check or a comment naming
the caller invariant that makes the check unnecessary.

## G2. Signature acceptance policy

Signature malleability policy is a protocol-level choice. The port currently makes that choice in
three places without a recorded decision, and the choices disagree.

### G2-1 Production signing enforces low-S; the test oracle does not (`high`)

Scheduled: phase 3, owned by
[PKP-02](proof-and-key-parity.md#pkp-02-complete-key-encoding-and-signature-parity), whose K2 suite
already requires the release to choose and document one high-S policy against the circuit and the
SDK libraries rather than infer it from a vector.

Production code requests canonical low-S for both signing and verification, at
`sdk-libs/ts/keypair/src/signing-key.ts` lines 64 and 82. The prover test vector helper deliberately
disables it:

```173:178:sdk-libs/ts/client/test/helpers/prover-vectors.ts
    const signature = p256.sign(
      privateMessage(inputs, outputs, externalData.hash()),
      bytes(fixture.inputs.p256SecretBytes),
      { prehash: false, format: "compact", lowS: false },
    );
```

Impact: the vectors that certify the prover path are generated under a different acceptance policy
than the library enforces, so they cannot demonstrate that the policy is correct. One of the two is
wrong, and this register cannot say which without the circuit's own position.

Closing this requires: reading the acceptance policy out of the SPP circuit's ECDSA gadget and the
Go prover, recording it as the authority, and aligning both call sites to it. If the circuit accepts
high-S, the library's `lowS: true` silently narrows what the protocol permits and would reject
signatures produced by a conforming Rust or hardware signer. If the circuit rejects high-S, the test
helper is producing vectors the protocol would refuse.

### G2-2 Ed25519 verification pins `zip215: false` without a recorded rationale (`medium`)

Scheduled: phase 3, owned by
[PKP-02](proof-and-key-parity.md#pkp-02-complete-key-encoding-and-signature-parity), whose K3 suite
already requires `zip215: false` to be proven compatible with the selected Rust policy.

```85:85:sdk-libs/ts/keypair/src/signing-key.ts
      return ed25519.verify(signature, message, this.publicKey().ed25519(), { zip215: false });
```

`zip215: false` selects strict RFC 8032 cofactorless verification, which is narrower than what the
Solana runtime's Ed25519 check accepts. Since Ed25519-owned inputs are authorized by the runtime
signer check rather than by this function, a divergence here changes which signatures the SDK
considers valid relative to what would actually land.

Closing this requires: identifying the authority for Ed25519 acceptance on this rail, which is the
Solana runtime rather than the SDK, documenting whether the SDK is intentionally stricter, and a
fixture pair covering a signature that is valid under one convention and not the other.

### G2-3 Signing message length is unconstrained (`medium`)

Scheduled: phase 2, owned by [`review-checklist.md`](review-checklist.md) row `K02`.

`sign` accepts an arbitrary-length `Uint8Array`. The protocol messages it is used for are fixed
length, specifically a 32-byte `private_tx_hash` digest on the P256 rail. Nothing prevents signing a
value of another length, and the `prehash: false` setting means no digest step would normalize it.

Closing this requires: deciding whether `sign` is a general-purpose primitive or a
protocol-constrained one, and if the latter, asserting the expected length.

## G3. Circuit coverage in the prover path

### G3-1 The prover input union omits the zone and zone-authority circuits (`blocker`)

Scheduled: phase 5, owned by
[PKP-05](proof-and-key-parity.md#pkp-05-complete-proof-assembly). PKP-05 already lists
"confidential, zone, zone-authority, merge, and merge-zone TypeScript inputs" as its deliverable,
and the proof map already labels the zone transact and zone-authority assembly rows `missing`.
Checklist rows `C13`, `C14`, and `C18` already carry the `MISSING` verdict for the three circuits.
This finding is the same work seen from the type side, not a second item.

Re-read at HEAD `b230b314`: the union is unchanged.

```78:80:sdk-libs/ts/client/src/prover/types.ts
export type ProverInputs =
  | Readonly<{ circuit: "transfer"; payload: TransferInputs }>
  | Readonly<{ circuit: "transferP256"; payload: TransferP256Inputs }>;
```

Rust implements five transact-family prover entry points:
`sdk-libs/client/src/prover/transact/eddsa.rs`, `p256_and_eddsa.rs`, `zone_eddsa.rs`,
`zone_p256.rs`, and `sdk-libs/client/src/prover/zone_authority.rs`. The TypeScript union covers the
first two.

The zone-authority instantiation is not a variant of the others. Per `docs/spec.md` line 980, it
removes owner authorization, dropping both the P256 gadget and the signature check inside the proof,
and keeps each input owner `pk_field` private. Authorization rests on the `zone_config` PDA signer
plus the zone program's policy. Its public input construction therefore differs structurally from
the transact circuits, not just in field values.

Impact: TypeScript callers have no path to prove zone or zone-authority transactions. Any parity
statement scoped to "the prover path" is currently a statement about two of five rails.

Closing this requires: extending the union and assembly with the three missing circuits, a public
input hash fixture per circuit generated from the Rust side, and shape coverage matching
`SPP_SUPPORTED_SHAPES` for each.

### G3-2 Zone preparation exists in `transaction` but has no prover consumer (`medium`)

Scheduled: phase 5, owned by [PKP-05](proof-and-key-parity.md#pkp-05-complete-proof-assembly)
alongside G3-1.

`prepareZoneAuthority` in `sdk-libs/ts/transaction/src/instructions/builders.ts` performs the zone
consistency checks (`TRANSACTION_MERGE_INPUT_ZONE_MISMATCH`, `TRANSACTION_OUTPUT_ZONE_MISMATCH`) and
returns a `PreparedZoneAuthority`. Nothing in `sdk-libs/ts/client/src/prover` accepts that type,
because of G3-1.

Impact: the validation is untested end to end, and its output shape has not been checked against
what the zone-authority prover request actually needs. Fixing G3-1 without revisiting this risks
discovering the prepared shape is insufficient.

Closing this requires: treating the prepared type as a draft until a zone-authority prover consumer
exists, then reconciling it against the Rust `ZoneAuthorityProver` inputs.

## G4. Absent verification oracle

The certification model assumes TypeScript output can be checked by something that is not
TypeScript. Three links in that chain are missing, and they are the reason G3 cannot simply be
"implemented and tested."

### G4-1 No Rust or shielded-pool verification of TypeScript-produced artifacts (`blocker`)

Scheduled: phase 5, owned by
[PKP-06](proof-and-key-parity.md#pkp-06-add-native-verification-certification). PKP-06 already
delivers the bounded test-only Rust oracle and the TypeScript-produce, Rust-verify tests, and the
[P4 suite](proof-and-key-parity.md#p4-cryptographic-verification) already specifies the eight steps.
This finding states the consequence of that packet being unstarted; it does not add a packet.

Current TypeScript proof tests compare against Rust-generated fixtures. That proves TypeScript
reproduces recorded inputs. It does not prove a TypeScript-assembled proof request yields a proof
the shielded-pool verifier accepts. The direction of the check matters: fixture comparison catches
divergence on the recorded cases only, and the recorded cases were chosen by the Rust side.

Closing this requires: a harness that takes TypeScript-assembled public inputs and a proof, then
verifies them with the native Rust verifier and the embedded verifying keys at the same revision, so
that a TypeScript-only encoding error cannot pass by agreeing with a TypeScript-generated
expectation.

### G4-2 No live prove-to-chain evidence (`blocker`)

Scheduled: phase 5, owned by
[PKP-07](proof-and-key-parity.md#pkp-07-add-real-prove-to-chain-acceptance). PKP-07 already delivers
the pinned prover and local stack plus stub-free action and instruction flows, and the
[P5 suite](proof-and-key-parity.md#p5-end-to-end-proof-flows) already lists the required assertions.
No second packet is created for it.

The two live E2E suites reach a real validator, but neither carries a proof through the shielded
pool. `sdk-libs/ts/e2e/instructions/live.test.ts` proves one negative: a transfer message signed by
the wrong key is rejected and the balance is unchanged.

```69:72:sdk-libs/ts/e2e/instructions/live.test.ts
      await expect(harness.rpc.sendTransaction(signed)).rejects.toMatchObject({
        code: "CLIENT_RPC_ENVELOPE",
      });
```

`sdk-libs/ts/e2e/actions/live.test.ts` covers registration, merge opt-in idempotence, and
associated-token-account creation. Those are real submissions, but none of them carry an SPP proof.

Impact: no test demonstrates that a TypeScript-built `transact` lands. The most consequential
integration claim in the port has no evidence.

Closing this requires: a deposit, transact, and withdraw sequence against the same-revision local
stack with a proof produced from TypeScript-assembled inputs, asserting state transitions rather
than only rejection.

### G4-3 Adversarial and tamper coverage is thin (`medium`)

Scheduled: phase 5, owned by the
[PKP-06](proof-and-key-parity.md#pkp-06-add-native-verification-certification) tamper matrix, with
the [`testing-and-conformance.md`](testing-and-conformance.md#property-and-mutation-gates) mutation
gates recording the requirement. The G5-2 code split is a prerequisite: a matrix cannot assert a
named rejection while several causes share one code.

Proof tests focus on agreement with fixtures. Coverage of a mutated proof point, a public input
substituted between assembly and submission, a nullifier replay, or a shape mismatch is sparse
relative to the Rust integration suites in `sdk-libs/client/tests`.

Closing this requires: a tamper matrix with one negative case per public input and per proof
component, each asserting a specific typed rejection rather than any failure.

## G5. Error taxonomy and secret redaction

### G5-1 Raw dependency errors are retained as `cause` (`high`)

Scheduled: phase 2, owned by
[`security-and-release.md`](security-and-release.md#secret-and-authority-boundary), which states the
redaction contract, and by [`review-checklist.md`](review-checklist.md) row `K10`, which carries the
code change.

```33:39:sdk-libs/ts/keypair/src/error.ts
export function wrapKeypairError(
  code: KeypairErrorCode,
  cause: unknown,
  details?: Readonly<Record<string, unknown>>,
): KeypairError {
  if (cause instanceof KeypairError) return cause;
  return new KeypairError(code, details, cause);
}
```

The original error from `@noble/curves` or `@noble/hashes` is attached unchanged. Those libraries
include operand material in some messages, and the keypair package operates on secret scalars.

Impact: a thrown keypair error can reach a log aggregator or error reporter with dependency-supplied
detail about secret-derived values. The redaction contract the port claims is not enforced at the
one place that would enforce it.

Closing this requires: a decision on whether `cause` is dropped, replaced by a stable marker, or
retained behind an explicit opt-in, plus a test asserting that no thrown keypair error's serialized
form contains input-derived bytes.

### G5-2 The keypair error taxonomy is collapsed relative to Rust (`high`)

Scheduled: phase 2, owned by [`review-checklist.md`](review-checklist.md) row `K10`. The
[K10 suite](proof-and-key-parity.md#k10-error-and-redaction-parity) consumes the resulting table in
phase 5.

`KeypairErrorCode` maps several distinct Rust `KeypairError` variants onto shared codes such as
`KEYPAIR_HASH`. Callers cannot distinguish an invalid-length input from a Poseidon failure from an
out-of-range scalar.

Impact: consumers cannot branch on failure mode the way the Rust API allows, and the tamper matrix
in G4-3 cannot assert a specific rejection reason while several causes share one code.

Closing this requires: a code-per-Rust-variant mapping table with an explicit, justified list of
intentional merges.

### G5-3 No cross-language error mapping fixture (`medium`)

Scheduled: phase 2, owned by
[`testing-and-conformance.md`](testing-and-conformance.md#differential-and-cross-package-tests).

Nothing generates the Rust error variant for a given malformed input and asserts the corresponding
TypeScript code. The mapping exists only in prose.

Closing this requires: extending the fixture generator to record `(input, rust_error_variant)` pairs
and a TypeScript test that asserts the mapped code.

## G6. Secret lifecycle and custody boundary

### G6-1 No zeroization of secret material (`medium`)

Scheduled: phase 2, owned by
[`security-and-release.md`](security-and-release.md#secret-and-authority-boundary) for the threat
statement and the clearing rule.
[PKP-04](proof-and-key-parity.md#pkp-04-enforce-capability-and-secret-boundaries) K8 certifies the
documented limits in phase 5.

Rust secret types are dropped and their memory cleared. TypeScript `Uint8Array` secrets persist
until collected, and the port has no explicit clearing step after use.

This is partly unfixable in JavaScript, since engine-internal copies are not reachable. The gap is
that the port does not state which mitigations it does apply, so consumers cannot reason about
residual exposure.

Closing this requires: a documented threat statement naming what is and is not mitigated, and
best-effort clearing where a secret buffer's lifetime is under SDK control.

### G6-2 Defensive-copy discipline is not uniformly verified (`medium`)

Scheduled: phase 2, owned by
[`testing-and-conformance.md`](testing-and-conformance.md#property-and-mutation-gates).
[PKP-04](proof-and-key-parity.md#pkp-04-enforce-capability-and-secret-boundaries) K8 extends the
same test shape to the secret-bearing constructors in phase 5.

`copyBytes` is used on several return paths, for example `P256PublicKey.toBytes`, which is correct.
Whether each constructor and accessor that receives or returns secret-adjacent bytes copies rather
than aliases has not been audited exhaustively.

Closing this requires: an aliasing test per public accessor that mutates the returned buffer and
then asserts internal state is unchanged.

### G6-3 The custody abstraction may be too narrow for a hardware signer (`medium`)

Scheduled: phase 5, owned by
[PKP-04](proof-and-key-parity.md#pkp-04-enforce-capability-and-secret-boundaries) K9, which already
requires conformance adapters for a local authority, an asynchronous mock HSM, a remote signer, a
viewing-only authority, and a native Solana transaction signer.
[`security-and-release.md`](security-and-release.md#secret-and-authority-boundary) records whether a
signing-only custodian is supported.

```77:86:sdk-libs/ts/keypair/src/shielded.ts
export interface ShieldedKeypairLike {
  shieldedAddress(): ShieldedAddress;
  sign(message: Uint8Array): Bytes64 | Promise<Bytes64>;
  nullifier(utxoHash: Bytes32, blinding: Bytes31): Bytes32 | Promise<Bytes32>;
}

export interface ViewingKeyLike {
  publicKey(): P256PublicKey;
  transactionViewingKey(firstNullifier: Bytes32): ViewingKey | Promise<ViewingKey>;
}
```

These are the seams an external custodian would implement. `nullifier` requires the implementer to
hold nullifier-key material, and `transactionViewingKey` requires viewing-key material, so a signer
that exposes only a signing operation cannot satisfy them.

Ruled by the protocol owner: that is intended. A signing-only custodian is not a supported
configuration, and a custodian holds nullifier and viewing key material. The disposition is recorded
under
[the custody seam](security-and-release.md#custody-seam-width),
and `sdk-libs/ts/keypair/src/shielded.ts` states the requirement at both interface definitions.

What remains is evidence rather than a decision: the
[PKP-04](proof-and-key-parity.md#pkp-04-enforce-capability-and-secret-boundaries) K9 adapters still
have to show the seam holds for a custodian that does hold the material, such as an asynchronous
mock HSM or a remote signer.

## G7. Specification authority conflicts

These are not TypeScript defects. They are places where the specification and the implementations
disagree, so no port can be certified against both. Each needs a recorded ruling before the
dependent rows can be closed.

### G7-1 Owner-hash encoding: specification includes y-parity, implementations omit it (`blocker`)

Scheduled: phase 3, owned by
[PKP-00](proof-and-key-parity.md#pkp-00-resolve-authorities-and-freeze-scope). The same conflict is
already the first entry in the
[known-conflicts list](proof-and-key-parity.md#authority-and-conflict-policy) and already holds the
checklist rows adverse; this register adds the phase, not a new owner.

`docs/spec.md` lines 265 to 284 define a single `pk_field` and use it inside `owner_hash`. For P256
it is `Poseidon(y_is_odd, Poseidon(x_low_128, x_high_128))`, described at line 267 as "the canonical
form used wherever a pubkey appears inside a Poseidon hash anywhere in this spec", and line 283
gives `owner_hash := Poseidon(pk_field(signing_pk), nullifier_pk)`.

The implementations use two distinct encodings, and the owner-identity one drops the parity layer:

```32:37:program-libs/interface/src/merge_utils.rs
/// Owner-identity `pk_field` of a SEC1-compressed P256 public key: the parity-free
/// `Poseidon(x_low_128, x_high_128)` (the y-parity is carried in the encrypted data,
/// not the owner identity), so a P256 owner has the same pk_field shape as an ed25519
/// owner. Matches the circuit `OwnerPkFieldGadget` and keypair
/// `PublicKey::owner_pk_field`. The compressed prefix is still validated.
```

So `owner_hash` in the shielded pool, the circuit gadget, `PublicKey::owner_pk_field` in
`sdk-libs/keypair`, and the TypeScript port use the parity-free form, while the specification's
stated composition implies the parity-inclusive one. The specification's claim at line 278, that the
P256 and Ed25519 encodings cannot collide because of the extra parity layer, does not hold for the
encoding actually used for owner identity.

Impact: any parity review of owner-hash derivation has to choose which document to trust. The code
paths agree with each other, so nothing is broken at runtime. The specification text is the
divergent artifact, and it is the one the review process treats as primary.

Closing this requires: a ruling that the specification is amended to describe both encodings and
name which one enters `owner_hash`, plus a restatement of the collision-resistance argument for the
parity-free form.

### G7-2 Two authority orders exist and neither carries per-conflict rulings (`blocker`)

Scheduled: phase 3, owned by
[`proof-and-key-parity.md`](proof-and-key-parity.md#authority-and-conflict-policy), which holds the
longer order, reconciled against [`README.md`](README.md#source-precedence), which holds the shorter
one.

Corrected since the finding was recorded. The original wording, that the order is asserted but not
written down, was wrong. Two orders are written down and they differ:

- `README.md` "Source precedence" lists five levels: `docs/spec.md`, then Rust at the frozen
  revision, then Rust fixtures, then the pinned examples, then PR #111.
- `proof-and-key-parity.md` "Authority and conflict policy" lists seven: `docs/spec.md`, then
  deployed or release-targeted shielded-pool behavior and circuit constraints, then the Go prover,
  then Rust and its tests, then fixtures, then TypeScript, then the planning inventories.

The shorter list omits the program and the prover, which are the two authorities that decide G2-1
and G7-1. A reviewer following `README.md` reaches Rust one step after the specification and has no
level at which to place the circuit.

What is missing in both is the ledger: neither document has one row per open conflict recording the
ruling and the artifact that changed. The known-conflicts list in `proof-and-key-parity.md` names
four disagreements without a ruling for any of them.

Impact: each conflict is resolved case by case, and a reviewer cannot tell whether a divergence is a
defect or an intended deviation. G7-1 shows the practical result: the code was trusted and the
specification was left stale.

Closing this requires: one reconciled order across the two documents, a stated resolution procedure,
and one row per open conflict with its ruling and the artifact that was changed.

## G8. Fixture and proving-key provenance

### G8-1 The manifest pins multiple source revisions (`high`)

Scheduled: phase 2, owned by
[`testing-and-conformance.md`](testing-and-conformance.md#fixture-layout-and-provenance), and proven
by a new phase-4 gate line.
[PKP-01](proof-and-key-parity.md#pkp-01-harden-fixture-provenance) extends the same rule to the
proof and key fixtures.

```2:7:sdk-libs/ts/fixtures/manifest.json
  "canonicalSourceRevisions": {
    "baseline": "43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f",
    "client": "3ba527850a7986f36c47ad2082598edff3e3e5b7",
    "interface": "14ad30017ef5b512548f65284eae0212684d8197",
    "merkleTree": "975783aa38b65734585f7749e347201fd67a2b71"
  },
```

Grown since the finding was recorded. It pinned three source revisions; a fourth, `client`, has been
added. With `frozenCommit`, `historicalBaselineCommit`, `photonSchemaRevision`, `specSha256`, and a
`provingKeyRelease` lock hash, the manifest now carries nine identity keys. Nothing in it states
which combinations are compatible or what invalidates a fixture.

Impact: a parity claim assembled from fixtures generated at different revisions is not a claim about
any single protocol version. The checklist already records drift in
`sdk-libs/merkle-tree/src/indexed.rs` relative to the freeze.

Closing this requires: a compatibility rule per revision key, a check that fails when a fixture is
consumed against an incompatible pin, and a documented regeneration trigger.

### G8-2 Verifying-key provenance is not tied to the fixtures (`high`)

Scheduled: phase 5, owned by
[PKP-01](proof-and-key-parity.md#pkp-01-harden-fixture-provenance), whose deliverables already list
"verifying-key identities and hashes" and whose
[fixture contract](proof-and-key-parity.md#shared-fixture-contract) already requires a
verifying-key module and SHA-256 per fixture. What this finding adds is the failure rule, now a
phase-4 gate line.

`provingKeyRelease` records a lock file path and hash. The proof fixtures do not record which
verifying key they were produced against, so a key rotation would not invalidate them.

Closing this requires: recording the verifying-key identity in each proof fixture and failing the
gate when it does not match the key the verifier loads.

## G9. Continuous integration and release gates

### G9-1 No workflow runs the TypeScript suite (`blocker`)

Scheduled: phase 2, first, owned by
[`testing-and-conformance.md`](testing-and-conformance.md#continuous-integration-tiers), and proven
by a new phase-4 gate line.

Re-confirmed at HEAD `b230b314`: `.github/workflows/` contains `async-prover.yml`,
`enforce-pr-only.yml`, `forester.yml`, `formal-verification.yml`, `photon-image.yml`, `photon.yml`,
`prover-server.yml`, and `rust.yml`. Only `photon.yml` references Node, and none of the eight run
the workspace scripts.

Impact: nothing prevents a merge that breaks the TypeScript build, types, lint, tests, or fixture
agreement. Each gate described in the planning documents is currently manual.

Applied: `.github/workflows/typescript.yml` runs `npm run check` on pull requests and on pushes to
`main`, split into a `static`, `suites`, `packaging`, `fixtures`, and `e2e` job by the services each
part needs, plus a `gate scope` job that fails when `check` grows a sub-script the workflow does not
run and a `merge gate` job that fails unless the five succeeded. The tier layout is recorded under
[continuous integration tiers](testing-and-conformance.md#continuous-integration-tiers).

Remaining: the gate is red at the revision that added it, on G8-1 fixture drift, the `lint:packages`
backlog, and a `globalThis.process` read in the client prover bundle. Those are the defects the gate
exists to surface, so each is reported rather than excluded.

### G9-2 The aggregate `check` script omits most certification gates (`blocker`)

Scheduled: phase 2, second, owned by
[`testing-and-conformance.md`](testing-and-conformance.md#continuous-integration-tiers), and proven
by a new phase-4 gate line. The tiering decision here settles first, because G9-1's workflow runs
whichever tier this produces.

Re-confirmed at HEAD `b230b314`: the script is unchanged.

```45:45:package.json
    "check": "npm run build && npm run typecheck && npm run lint && npm run format:check && npm run test:unit && npm run test:inventory && npm run test:exports && npm run test:dependencies && npm run api:check"
```

Defined but excluded: `test:vectors`, `test:property`, `test:cross`, `test:prover`, `test:browser`,
`test:e2e:actions`, `test:e2e:instructions`, `fixtures:check`, `pack:check`, and `lint:packages`.
The cross-language and prover suites, which are the ones that carry the parity argument, are exactly
the ones `check` does not run.

Impact: "check passes" is routinely read as "the port is consistent with Rust", and it does not mean
that.

Applied, per the protocol owner's ruling that one gate runs the list, the prover and both end-to-end
suites included: `check` now expands to `check:static && check:suites && check:packaging &&
check:fixtures && check:e2e`, and the ten excluded suites sit in those five sub-scripts. The
per-commit, per-pull-request, per-release tier split is withdrawn, since the ruling puts the
end-to-end suites in the merge gate rather than a release tier.

### G9-3 `format:check` covers a hand-maintained file list (`medium`)

Scheduled: phase 2, owned by
[`testing-and-conformance.md`](testing-and-conformance.md#continuous-integration-tiers).

```29:29:package.json
    "format:check": "prettier --check package.json package-lock.json eslint.config.js prettier.config.js tsconfig.json tsconfig.eslint.json vitest.config.js sdk-libs/ts/config sdk-libs/ts/{interface,keypair,transaction,indexer-api,api,client,wallet,merkle-tree,smart-account-client,test-kit}/{package.json,tsconfig.json} sdk-libs/ts/reports/packets/P01.json"
```

The list enumerates packages and even individual report files, so a new package or document stays
unformatted until someone remembers to add it. Planning documents are not covered.

Closing this requires: a glob-based list with explicit ignores, so new files are covered by default.

### G9-4 Browser support is checked statically, not in a browser (`medium`)

Scheduled: phase 2, owned by
[`testing-and-conformance.md`](testing-and-conformance.md#failure-lag-and-runtime-matrix), which
already requires Chromium execution, and proven by a new phase-4 gate line. The plan and the script
disagree; the script is the artifact that changes.

`sdk-libs/ts/config/browser-check.mjs` scans sources for forbidden Node constructs and bundles the
entry points with esbuild:

```37:41:sdk-libs/ts/config/browser-check.mjs
    const forbidden =
      /\bBuffer\b|\brequire\s*\(|["']node:|\bprocess\s*(?:\.|\[)|typeof\s+process|\b(?:globalThis|window|self)\.process\b/u.exec(
        source,
      );
    if (forbidden) throw new Error(`@zolana/${packageName} source contains ${forbidden[0]}`);
```

That proves the bundle builds and avoids the named Node globals. It does not execute anything in a
browser engine, so a runtime dependency on `crypto.subtle` availability, a `SharedArrayBuffer`
assumption, or a `BigInt64Array` gap would pass.

Closing this requires: running at least the keypair and transaction vector suites in a headless
browser, and a documented statement of which Web Crypto surfaces are required.

## Not in scope for this register

- Row-level verdicts for the 118-row inventory. `review-checklist.md` remains the authority. This
  register describes cross-cutting issues that no single row owns.
- Performance, bundle size, and API ergonomics.
- Anything requiring a protocol change rather than an alignment decision.

## What this register does not decide

The findings are sequenced, owned, and gated. Four limits remain.

It does not change a row verdict or status. A finding that overlaps a checklist row leaves that
row's verdict to the review and re-review workflow, which stays the authority.

It does not authorize the work. Scheduling places a finding in a phase; the fix workflow in
[`review-checklist.md`](review-checklist.md#fix-and-re-review-workflow) still requires the user to
authorize the fix and an independent reviewer to accept it.

It does not rule on the two authority conflicts. G7-1 and G7-2 name the artifacts that must change
and the phase in which they change. The ruling belongs to the protocol owner through
[PKP-00](proof-and-key-parity.md#pkp-00-resolve-authorities-and-freeze-scope).

It does not re-verify the findings it did not spot-check. Five claims were re-read at the snapshot
HEAD and two had drifted, which is the expected rate for a moving branch. Re-confirm a finding
against a clean tree before starting on it.
