# WASM differential oracle: broad parity coverage

## Status and purpose

This plan adds a WebAssembly build of the canonical Rust crates as an in-process test oracle, so
that TypeScript parity is checked against generated inputs rather than only against recorded fixture
cases. It is an implementation plan. It does not by itself upgrade any parity claim.

Verification snapshot:

- branch: `ts-sdk-port`;
- worktree HEAD when the plan was written:
  `7c697c2c7e63a824a383c29a7cbb940a0e9b4e92`;
- Rust toolchain pin: `1.97.0` (`rust-toolchain.toml`);
- fixture baseline: `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`;
- fixture count: 59 JSON files under `sdk-libs/ts/fixtures/`, up from the 57
  this plan was written against;
- verification date: 2026-07-25, with the two divergences below and the fixture
  count re-checked on 2026-07-26.

Companion documents: [`production-readiness-issues.md`](production-readiness-issues.md) holds the
issue register this plan draws on, and [`proof-and-key-parity.md`](proof-and-key-parity.md) holds
the certification packets. Where this plan and those disagree, treat
[`review-checklist.md`](review-checklist.md) as the authority for current feature status.

## Why the current evidence model needs this

The fixture system is sound in mechanism. Each fixture records `inputs`, `expected`, `rustPath`, and
`rustSymbol`, so it links back to the Rust symbol it certifies, and rejections are already recorded
as Rust error variants (`sdk-libs/ts/fixtures/keypair/error.json` holds `InvalidPublicKey`,
`InvalidSecretKey`, `InvalidSignatureType(9)`, and `NotEd25519`).

The gap is input breadth. `sdk-libs/ts/fixtures/keypair/hash.json` certifies `sha256`, `sha256_be`,
`split_be_128`, `PublicKey::hash`, and `owner_pk_field` from a single input, the four ASCII bytes
`73616d65`. Two known divergences survive that model:

1. `signedField` in `sdk-libs/ts/client/src/prover/assembly.ts` agrees with Rust on each recorded
   amount and wraps modulo the field above `i64::MAX`, where Rust's `signed_to_field(value: i64)`
   does not accept the value.
2. `hashField` in `sdk-libs/ts/keypair/src/hash.ts` agrees on the recorded 32-byte case and
   zero-extends a shorter input, where Rust's `hash_field(&[u8; 32])` does not compile.

So fixture agreement holds today while the port has live divergences. The property-test suites do
not close this either, because they assert internal round-trip properties rather than agreement with
an external reference. `sdk-libs/ts/keypair/test/property/keypair-property.test.ts` checks that
signing then verifying returns true, which would pass on a self-consistent implementation of the
wrong curve.

`fast-check` is already a devDependency and already used in four suites. What is missing is the
reference on the other side of the comparison.

## Why differential search finds what fixtures cannot

A fixture is a claim about one point. `hash_field` accepts 32 bytes, so its input space holds 2^256
values, and `keypair/hash.json` samples one of them. Passing that fixture constrains the TypeScript
implementation at a single coordinate and leaves it unconstrained everywhere else. That is not a
criticism of the fixture; it is what one recorded case can mean.

Two things make the recorded set systematically miss the interesting inputs.

First, the generator author picks the cases, and people pick cases from the behavior they intend.
Nobody writing a `hash_field` fixture records a 16-byte input, because Rust's `&[u8; 32]` makes that
input unthinkable on the Rust side. The bug lives precisely in the region the Rust type renders
invisible, so the fixture author has no prompt to go there. Same for `signed_to_field(i64)` and
`i64::MAX + 1`.

Second, a port's divergences cluster at domain edges rather than in the middle. The two known
divergences are both cases where Rust's type system refuses an input and TypeScript's does not, so
TypeScript reaches code Rust cannot reach. Agreement in the interior of the domain says nothing
about the boundary, and the boundary is where the type systems differ.

Generated inputs invert the selection. `fast-check` does not know what the author intended, so it
proposes lengths of 0, 1, 15, 16, 17, and 33 without being asked, and integers at `2^63` because
integer generators cluster at extremes. The reason this needs WASM specifically, rather than a
subprocess calling Rust, is cost: a property runs thousands of cases, and paying process startup per
case makes the technique unaffordable. In-process calls make it routine.

Three properties make the comparison meaningful, and each is a design constraint later in this plan:

**The oracle must be independent of the implementation under test.** Comparing TypeScript against
TypeScript-derived expectations proves self-consistency, which is what the current property suites
measure. The oracle has to be the canonical Rust, compiled, not a reimplementation.

**The comparison must include rejections.** A divergence where Rust refuses and TypeScript returns a
value is invisible unless refusal is a comparable outcome. This is why the error taxonomy is a
prerequisite rather than a parallel task.

**Counterexamples must shrink.** A raw failing case from a generator is usually large and
incidental. Shrinking reduces it to the minimal input that still diverges, which is what makes it
worth committing as a fixture, and what makes the underlying cause legible.

## Decision

Build the oracle as disposable search, and keep fixtures as the authority.

```text
fast-check generates inputs
  -> native TypeScript and Rust-via-WASM both evaluate
  -> outcomes compared
  -> divergence shrunk to a minimal case
  -> minimal case promoted into the xtask fixture generator
  -> committed fixture becomes the durable regression record
```

The two artifacts fail asymmetrically, and this ordering puts the fragile one where being wrong is
harmless. A stale WASM build yields weaker search, so bugs go undiscovered. A stale fixture yields a
false parity claim. Because divergences are promoted to fixtures, no certification claim rests on
the WASM build, and it needs no provenance pin in
[`manifest.json`](../../sdk-libs/ts/fixtures/manifest.json). That keeps this plan from adding to the
provenance problem recorded as G8.

The WASM artifact stays a `devDependency` and is excluded from published packages. If it reaches a
published artifact, the native TypeScript port has been abandoned without a decision.

## How the oracle works

WebAssembly lets the test process execute the canonical Rust rather than a description of it. A new
crate wraps the existing ones, `wasm-pack` compiles it for `wasm32-unknown-unknown`, and
`wasm-bindgen` generates the JavaScript bindings and TypeScript declarations that `vitest` imports.
Nothing in `sdk-libs/*` changes behavior; the wrapper only exposes entry points.

The wrapper is thin by design. For the hashing packet it looks like this, with the caveat that the
signature widens the Rust type on purpose and the widening is the point:

```rust
#[wasm_bindgen]
pub fn hash_field(value_hex: &str) -> JsValue {
    // Decode hex, then refuse anything the Rust signature refuses.
    match decode_exact::<32>(value_hex) {
        Err(error) => outcome_err("InvalidInputLength", error),
        Ok(value) => match zolana_keypair::hash::hash_field(&value) {
            Ok(bytes) => outcome_ok(&hex(&bytes)),
            Err(error) => outcome_err(error.variant(), error),
        },
    }
}
```

The TypeScript side calls it beside the native implementation and compares outcomes:

```ts
fc.assert(
  fc.property(fc.uint8Array({ minLength: 0, maxLength: 64 }), (value) => {
    expect(outcomeOf(() => hashField(value))).toEqual(oracle.hash_field(toHex(value)));
  }),
);
```

### The boundary encoding contract

The boundary uses the encoding the fixtures already use, so that a counterexample serializes into a
fixture without a translation step. The existing convention, read from the committed fixtures:

| Kind         | Encoding                          | Example from a committed fixture                                                        |
| ------------ | --------------------------------- | --------------------------------------------------------------------------------------- |
| Byte strings | lowercase hex, no prefix          | `"preimageBytes": "73616d65"`                                                           |
| Integers     | decimal strings, not JSON numbers | `"inputs": "2"`, `"invalidSignaturePrefix": "9"`                                        |
| Rejections   | `{ code, details }`               | `{ "code": "UnsupportedShape", "details": "UnsupportedShape { n_in: 99, n_out: 99 }" }` |

Two reasons this matters beyond tidiness. Integers cross as decimal strings because a JSON number
and a JavaScript `number` both lose precision above 2^53, and the values under test include
`i64::MAX` and field elements near 2^254. Passing those as numbers would corrupt the input before
either implementation saw it, and the test would compare two wrong answers.

Rejections cross as the Rust variant name plus the `Debug` payload because the payload carries the
discriminating detail. `UnsupportedShape { n_in: 99, n_out: 99 }` distinguishes which shape was
refused, not merely that a refusal happened. Comparing on both fields makes the tamper coverage in
G4-3 able to assert a specific rejection rather than any failure.

Because these are the fixture encodings, promotion is a serialization rather than a conversion, and
a shrunk counterexample can be pasted into an `xtask` generator case as-is.

### What crosses and what does not

The wrapper exposes pure functions taking explicit inputs and returning tagged outcomes. It exposes
no handles, no stateful objects, and no callbacks into JavaScript. Randomness, clocks, network
access, and file access stay out, which is why the coverage map below stops at the transport
boundary rather than trying to bring `reqwest` along.

## What the oracle establishes, and what it cannot

| Surface                                                                                                                                              | Oracle reach                                                                                                                                              |
| ---------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Deterministic pure functions: Poseidon, `hash_field`, `pk_field`, `owner_pk_field`, key derivation, codecs, Merkle operations, public-input assembly | Full. Approaching completeness is realistic here.                                                                                                         |
| Randomized operations: key generation, blinding, AES-CTR nonces                                                                                      | Only through deterministic seams. `SigningKey::from_bytes` and `ShieldedKeypair::from_ed25519` supply them.                                               |
| ECDSA and Ed25519 signature bytes                                                                                                                    | Byte-exact. `@noble/curves` defaults `extraEntropy` to false and the Rust `p256` crate uses RFC 6979, so the same key and message produce the same bytes. |
| Groth16 proving                                                                                                                                      | Out of reach. The prover is a Go server; neither Rust nor TypeScript generates proofs.                                                                    |
| Groth16 verification                                                                                                                                 | Not authoritative. See the substitution ledger below.                                                                                                     |
| Compute budget and shielded-pool state transitions                                                                                                   | Out of reach by any offline method.                                                                                                                       |

Four things the oracle cannot decide, recorded so that a green run is not misread:

**Specification conflicts.** Where Rust and TypeScript agree and the specification differs, a
differential run reports agreement. G7-1 is exactly this shape: the shielded pool, the circuit
gadget, `PublicKey::owner_pk_field`, and the TypeScript port use the parity-free owner encoding,
while `docs/spec.md` line 283 builds `owner_hash` from the parity-inclusive `pk_field`. The
fixture set already holds both encodings side by side in `keypair/hash.json`, where
`p256OwnerFieldBytes` and `p256PublicHashBytes` differ while the Ed25519 pair is identical. No
amount of fuzzing surfaces this.

**Policy questions whose authority sits above Rust.** G2-1 asks whether high-S ECDSA signatures are
acceptable. The authority is the SPP circuit's ECDSA gadget and the Go prover. If Rust's choice is
wrong, a matching TypeScript reproduces it faithfully and the oracle stays green.

**TypeScript-only surface.** G1-3 declares a 34-byte value as `Bytes33`. Both implementations return
byte-identical output, so a differential test passes while the branded-length defence stays broken.
Error `cause` redaction (G5-1), zeroization (G6-1), and API shape are equally invisible.

**Shielded-pool acceptance.** Covered only by G4-2, the live prove-to-chain sequence.

## Substitution ledger

The oracle does not run the same machine code as the deployed program. Two substitutions are load
bearing and are recorded here rather than left implicit.

Poseidon is target-gated in `program-libs/hasher`. On SBF it is the `sol_poseidon` syscall
(`program-libs/hasher/src/syscalls/definitions.rs`). Off SBF, including `wasm32`, the `poseidon`
feature routes to `light-poseidon` with `ark-bn254`:

```28:33:program-libs/hasher/Cargo.toml
[target.'cfg(not(target_os = "solana"))'.dependencies]
ark-bn254 = { workspace = true, optional = true }
sha2 = { version = "0.10", optional = true }
sha3 = { version = "0.10", optional = true }
ark-ff = { workspace = true, optional = true  }
```

So the oracle certifies against `light-poseidon`, which is the same implementation the Rust host
tests and the fixture generator already use. It does not certify against the syscall.

Groth16 verification has the same shape. `sdk-libs/client/tests/prover.rs` already runs
`groth16_solana::Groth16Verifier` off SBF against the committed keys in
`zolana_interface::verifying_keys`, using the pure-Rust arithmetic path rather than the `alt_bn128`
syscalls the program uses. A native Rust harness is therefore both simpler and closer to the program
than a WASM rebuild would be, so **verification is out of scope for this plan** and stays with G4-1.

## Coverage map

Feasibility below was read from the manifests at this revision, not attempted. Confirm by building
before committing to a packet.

| Crate                    | `wasm32` status                   | Evidence                                                                                                                                                                                    | TypeScript counterpart     |
| ------------------------ | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------- |
| `program-libs/hasher`    | Clean                             | `light-poseidon`, `ark-bn254`, `sha2`, `sha3`, `num-bigint`, `tinyvec`, each pure Rust                                                                                                     | inlined across TS packages |
| `sdk-libs/merkle-tree`   | Clean, lowest risk                | deps are `zolana-hasher`, `thiserror`, `num-bigint`, `num-traits`, `zolana-indexed-array`; `rand` is dev-only                                                                               | `sdk-libs/ts/merkle-tree`  |
| `program-libs/interface` | Likely                            | `bytemuck`, `solana-address`, `solana-pubkey`, `wincode`, `groth16-solana`; data types and pure math                                                                                        | `sdk-libs/ts/interface`    |
| `sdk-libs/keypair`       | Needs a `getrandom` change        | `p256`, `ed25519-dalek`, `aes`, `ctr`, `hkdf`, `sha2`, `zeroize` are fine; `rand` 0.8.5 and `solana-keypair` pull `getrandom` 0.2, which needs the `js` feature on `wasm32-unknown-unknown` | `sdk-libs/ts/keypair`      |
| `sdk-libs/transaction`   | Needs the same `getrandom` change | adds `borsh`, `wincode`, `solana-signature`, `async-trait`, `light-poseidon`, `ark-bn254`; no IO                                                                                            | `sdk-libs/ts/transaction`  |
| `sdk-libs/client`        | Blocked as published              | `reqwest` with `blocking`, `tokio` with `rt`, and `solana-rpc-client-api` are non-optional dependencies                                                                                     | `sdk-libs/ts/client`       |
| `sdk-libs/wallet`        | Blocked, inherits from client     | depends on `zolana-client`                                                                                                                                                                  | `sdk-libs/ts/wallet`       |

The `sdk-libs/client` block matters more than the others, because the prover assembly path is where
the G3 and G4 issues live. The coupling is narrow. Of 4181 lines under
`sdk-libs/client/src/prover/`, only `client.rs` at 1145 lines references `reqwest`, `tokio`, or
`RpcClient`. The remaining 3036 lines (`field.rs`, `inputs.rs`, `json.rs`, `merge.rs`,
`merge_zone.rs`, `proof.rs`, `zone_authority.rs`, and `transact/` entire) are pure computation.

So reaching the prover surface needs an extraction rather than a feature flag scattered through call
sites. That is packet W-01.

## Prerequisites and ordering

Three items gate the rest. Starting a coverage packet before these are done produces an oracle that
cannot see the bugs it exists to find.

**W-00. Make the error taxonomy lossless.** The comparison must be over outcomes, not values, or the
fuzzer treats "Rust rejected, TypeScript returned a value" as uninteresting and misses the entire G1
class. That requires a one-to-one Rust variant to TypeScript code mapping. The current mapping is
many-to-one:

```91:102:sdk-libs/ts/keypair/test/vectors/keypair-vectors.test.ts
function mappedCode(rustCode: string): KeypairError["code"] {
  switch (rustCode) {
    case "InvalidPublicKey":
      return "KEYPAIR_INVALID_PUBLIC_KEY";
    case "InvalidSecretKey":
      return "KEYPAIR_INVALID_SECRET_KEY";
    case "InvalidSignatureType":
    case "NotEd25519":
      return "KEYPAIR_INVALID_SIGNATURE_TYPE";
    default:
      throw new Error(`unmapped Rust error code: ${rustCode}`);
```

`InvalidSignatureType` and `NotEd25519` collapse into one code, so a test cannot detect TypeScript
throwing the wrong one of the two. This is G5-2, and it is a blocking dependency rather than a
parallel task.

Before: many-to-one mapping, rejection reasons partly indistinguishable. After: one code per Rust
variant, with any intentional merge listed and justified in `security-and-release.md`.

**W-01. Extract the prover core into a leaf crate.** Move the 3036 pure lines under
`sdk-libs/client/src/prover/` into a new crate that depends only on `zolana-interface`,
`zolana-hasher`, `zolana-keypair`, `zolana-transaction`, `num-bigint`, and `p256`. Leave `client.rs`
in `zolana-client` as the transport. `zolana-client` then depends on the new crate and re-exports,
so its public API does not change.

Before: prover assembly is unreachable from `wasm32` because the crate pulls `reqwest` and `tokio`.
After: assembly, public-input hashing, and proof compression build for `wasm32`, and the transport
stays native.

**W-02. Add the `getrandom` `js` feature for the `wasm32` target.** Scoped to the oracle build so
the published Rust crates are unaffected.

Before: `sdk-libs/keypair` and `sdk-libs/transaction` fail to link for `wasm32-unknown-unknown`.
After: both build; randomness is unused in the oracle because each entry point takes explicit seeds.

## Boundary design rules

These are the rules that decide whether the oracle is worth trusting. Each exists because breaking
it produces a green run over a real divergence.

**Compare outcomes.** Each exported oracle function returns a tagged result, either `Ok` with bytes
or `Err` with the Rust variant name and payload. The TypeScript side is compared on both arms. A
mismatch in which arm was taken is a failure.

**Do not widen Rust's domain silently.** `hash_field(&[u8; 32])` cannot accept sixteen bytes, so
fuzzing variable-length input requires the wrapper to take `&[u8]`. If the wrapper zero-pads to
reach 32 bytes, it reimplements the TypeScript defect inside the oracle and the test passes. The
wrapper rejects, and that rejection is the expected outcome. The same applies to
`signed_to_field(i64)`: the wrapper takes a wide integer and returns the rejection the Rust
signature implies.

Because a widened wrapper encodes a judgment about what Rust would have done, each widening is
recorded in the packet that introduces it, with the reasoning. These are specification decisions
wearing the costume of observation.

**No normalization, no convenience.** The wrapper does no hex parsing, endianness flipping, length
coercion, or default filling. Anything the wrapper does is behavior the oracle can no longer
observe.

**Deterministic seams only.** Entry points take explicit seeds and nonces. No oracle function calls
a random source.

## Coverage packets

Each packet lands a differential suite, then promotes any divergence it finds into the fixture
generator. A packet is complete when the suite runs in CI and each divergence it found exists as a
committed fixture.

**W-03. Hashing and field encoding.** `hash_field`, `split_be_128`, `pk_field_compressed`,
`owner_pk_field_compressed`, `pack33`, `sha256_be`, `asset_field`, and `signed_to_field`. Generators
cover byte arrays at each length from 0 to 64, values around the BN254 modulus, and integers around
`i64::MIN` and `i64::MAX`. This packet is expected to reproduce G1-1 and G1-2 on its first run,
which is the acceptance criterion: if it does not, the boundary was widened wrongly.

**W-04. Key derivation and addresses.** Signing key from seed, nullifier key from signing key,
viewing key derivation, `owner_hash`, shielded address encoding, and the 33-byte and 34-byte public
key encodings. Generators cover the full scalar range including 0 and the curve order, both
compressed prefixes, and invalid prefixes.

**W-05. Signatures.** Byte-exact comparison of P256 and Ed25519 signing over generated messages and
seeds, plus verification acceptance on both sides. Record, rather than resolve, any low-S
divergence, since G2-1 belongs to the circuit.

**W-06. Encryption and viewing.** AES-CTR with HKDF derivation, view tags, transaction viewing keys,
and the encrypt-then-decrypt path with injected nonces. Cover the ciphertext length boundaries.

**W-07. Merkle operations.** Path computation, root derivation, and indexed-array behavior. This is
the lowest-risk crate to build first, so it doubles as the toolchain shakedown, and it covers the
`sdk-libs/merkle-tree/src/indexed.rs` drift the checklist already records.

**W-08. Codecs.** Instruction and account serialization round-trips through `wincode` and `borsh`
against the TypeScript codecs, including malformed input rejection. Generators produce both valid
structures and mutated bytes.

**W-09. Prover assembly.** Depends on W-01. Public-input hash construction and witness assembly for
each of the five Rust entry points (`transact/eddsa`, `transact/p256_and_eddsa`,
`transact/zone_eddsa`, `transact/zone_p256`, `zone_authority`), across the shapes in
`SPP_SUPPORTED_SHAPES`, plus proof parsing and compression. This is the packet that gives G3-1 a
reference to build the three missing TypeScript circuits against.

## Promotion into fixtures

The fixture schema already carries what promotion needs, so this adds cases rather than a format. A
promoted case sets `inputs` and `expected` from the shrunk counterexample, `rustPath` and
`rustSymbol` from the diverging function, and `owningPacket` from the packet that found it.
Generation stays in the existing `xtask` modules (`ts_fixtures_keypair.rs`,
`ts_fixtures_transaction.rs`, `ts_fixtures_client.rs`, `ts_fixtures_merkle.rs`,
`ts_fixtures_api.rs`, `ts_fixtures_wallet.rs`), so `npm run fixtures:check` keeps verifying that
committed fixtures match freshly generated Rust output.

A promoted fixture records the input that broke, not a summary of the run. Fuzz seeds are not
evidence and are not committed as such.

### Worked example: the public amount divergence

Tracing G1-1 through the loop, because the value of each step is easier to judge on a real defect
than in the abstract.

**Today.** `signedField` reduces its input modulo the BN254 modulus. Rust's `signed_to_field` takes
an `i64`, so `i64::MAX + 1` does not reach it. There is no fixture for that value, `npm run check`
passes, and a caller passing `9223372036854775808` receives a proof request for a different amount
than it requested, with balance conservation intact so nothing downstream complains.

**Step 1, search.** W-03 generates integers with `fc.bigInt`, whose distribution favors extremes,
and compares outcomes. The oracle wrapper takes a decimal string and refuses anything outside the
`i64` range, because that is what the Rust signature does. TypeScript returns `Ok` with a field
element; the oracle returns `Err`. The arms differ, so the property fails.

**Step 2, shrink.** `fast-check` reduces the counterexample to the smallest diverging input,
`9223372036854775808`, which is `i64::MAX + 1`. That number names the cause: the bound is the `i64`
range, not the field modulus. A raw counterexample of `2^200 + 7` would have found the same bug and
taught nobody where the edge was.

**Step 3, promote.** A case is added to `ts_fixtures_transaction.rs` with input
`"9223372036854775808"` and an expected rejection, generated by Rust so the expectation is not a
guess. Two neighbors go in with it, `"9223372036854775807"` accepted and `"-9223372036854775808"`
accepted, so the fixture pins the edge from both sides rather than one point beyond it.

**Step 4, fix and lock.** `signedField` rejects outside the `i64` range with a typed error before
the field map. The new fixture now fails until that lands and passes afterward.
`npm run fixtures:check` keeps it honest by regenerating from Rust.

**Afterward.** The fixture is the durable artifact and runs with no Rust toolchain, no WASM build,
and no fuzzing. If the oracle is deleted tomorrow, the regression stays caught. That is the
asymmetry the Decision section rests on, made concrete: search is disposable, and the fixture it
produced is not.

## CI placement

The oracle needs the Rust toolchain, `wasm-pack`, and a build step, so it does not belong in the
fastest tier. Proposed placement, which depends on the tier split that G9-2 leaves unresolved:

- per-commit: unchanged, no WASM;
- per-pull-request: the differential suites at a bounded case count, plus `fixtures:check`;
- nightly: the same suites at a high case count, with any counterexample opened as a promotion task;
- per-release: full run, and the exemption ledger below verified.

The dependency this section used to name is closed, and the paragraph is kept in corrected form
because the reasoning still decides where the suites go. It said that `test:property` and
`test:cross` were excluded from `check` and that no workflow ran the TypeScript suite, so an oracle
that nothing executes would change nothing. Both halves have since been fixed:
`check:suites` runs `test:property` and `test:cross`, and `.github/workflows/typescript.yml` runs
one job per sub-script of `check` behind a `merge gate` job, with a `gate scope` job that fails if
the two drift apart. G9-1 and G9-2 are satisfied rather than pending, so this plan now has somewhere
to run and the tier question above is a scheduling choice rather than a blocker.

## Completeness as an exemption ledger

Completeness is not provable, so the deliverable is an explicit and enforced statement of what is
uncovered. The scaffolding exists: a row inventory, 145 rows since the coverage audit of 2026-07-25
raised it from the 118 this plan was written against, plus `test:inventory`, `test:exports`, and
`api:check`.

Add one gate: each public TypeScript export is differentially covered, fixture covered, or listed in
an exemption ledger with a reason and an owner. Expected permanent entries include the four
non-decidable categories above, the transport and RPC surface, and anything whose authority is the
circuit or the program rather than Rust.

The exemption ledger then is the parity statement, in a form a reviewer can diff.

## How this reaches the two goals

The goals are feature parity and production readiness. They are different claims with different
evidence, and this plan carries one of them further than the other.

### The parity argument

Parity is a claim about a relation between two implementations over a domain. Stated so it can be
checked, rather than asserted: for the surfaces in the coverage map, native TypeScript and canonical
Rust produce the same outcome, including the same rejection, on the recorded cases and on generated
inputs to the sampled depth.

Four premises carry that, and each has a named owner in this plan:

1. The reference is the canonical Rust, compiled rather than reimplemented, so the comparison cannot
   be satisfied by two implementations sharing a mistake. Owner: the wrapper crate and the coverage
   map.
2. Rejections are comparable, so silent normalization is a failure rather than a skipped case.
   Owner: W-00.
3. The generated domain reaches the edges where the two type systems differ, and the wrapper does
   not flatten those edges away. Owner: the boundary rules, with W-03 as the acceptance test.
4. What the search finds becomes a committed fixture, so the claim survives the oracle. Owner: the
   promotion loop and `fixtures:check`.

The conjunction is what makes this stronger than either half alone. Fixtures give authoritative
expected values over a set chosen by a person; search covers what a person would not choose but
leaves nothing durable behind. Running them in sequence means the recorded set stops being a guess
about which inputs matter and becomes a record of which inputs actually broke something.

The honest limit is the phrase "to the sampled depth." This yields well-tested equivalence, not
proof. Anyone writing a release note should say equivalence on the sampled domain, and should not
write "verified parity" without the exemption ledger attached.

### The production-readiness argument

Parity with Rust is necessary and not sufficient, because Rust is not the top authority. The
register lists six blockers, and it is worth being exact about which this plan moves:

| Blocker                                       | Effect of this plan                                                                                                 |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------- |
| G3-1 missing zone and zone-authority circuits | Substantially advanced. W-01 and W-09 supply the reference the three missing TypeScript circuits are built against. |
| G4-1 no verification of TypeScript artifacts  | Not addressed, deliberately. A native Rust harness is closer to the program than a WASM rebuild.                    |
| G4-2 no live prove-to-chain evidence          | Not addressed. Needs the local stack.                                                                               |
| G7-1 owner-encoding conflict                  | Not addressed, and would be masked. Rust and TypeScript already agree.                                              |
| G7-2 unwritten authority order                | Not addressed, and made more urgent, since this plan installs Rust as a mechanical authority.                       |
| G9-1 and G9-2 absent CI and partial gate      | Not addressed, and a hard dependency. Nothing here has value until a workflow runs it.                              |

So the contribution to production readiness is narrower than the contribution to parity: it closes
the G1 and G5 classes, materially advances G3, and leaves the rest untouched. Sequenced against the
register, that puts it after the CI work rather than before, because the oracle's output needs
somewhere to run.

The second contribution is less obvious and may matter more. Right now the port's evidence and its
confidence are mismatched: `npm run check` passes on a branch with two known silent divergences, so
a green build reads as stronger than it is. Adding search plus an exemption ledger changes what a
green build means. It stops meaning "the recorded cases agree" and starts meaning "the recorded
cases agree, generated inputs found nothing new, and here is the written list of what remains
unchecked." That list is the part a reviewer can argue with, which is the property the current gate
lacks.

## What remains open after full coverage

Completing the packets here yields one claim: the TypeScript implementation is equivalent to Rust
on the sampled domain, for the surfaces listed as reachable. Still open at that point:

- the G7-1 owner-encoding conflict, which needs a specification amendment;
- the G2-1 malleability policy, which needs the circuit's position;
- G4-1 native verification of TypeScript-produced artifacts;
- G4-2 live prove-to-chain evidence;
- G1-3, G5-1, and G6-1, which have no Rust counterpart to differ from.

None of those are addressed by this plan, and none should be described as covered by it.
