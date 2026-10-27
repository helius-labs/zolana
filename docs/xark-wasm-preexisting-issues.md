# Pre-existing issues found during Xark WASM integration

Date: 2026-10-27. Consumer baseline: `b1f843381`.
Implementation branch: `feat/xark-wasm-composition`.

These findings existed before the composition changes. Reproduced failures are
distinguished from findings confirmed by reading the baseline source. This is a
record of issues encountered in this work, not a complete audit of either project.
No trusted circuit, key, or transaction fixture was regenerated to hide a failure.

## 1. Browser prover receives inputs in the wrong representation

**Evidence:** Reproduced in an isolated copy of the original browser harness.
Escrow fails with `unknown input program.private.tokenUtxosAssetA[0].amount`;
withdraw similarly fails at `program.private.escrow.asset`.

`web/worker.js` passes the natural camelCase objects returned by the SDK directly
to Xark's low-level `proveStreamingPreloaded`. The low-level solver expects its
encoded inputs, not those natural application objects.

**Impact:** Normal browser transaction proofs fail before proving.

**Fix in this branch:** Load the existing circuit `schema.json` and call Xark's
existing `Schema.encodeInputs` before low-level proving. Preserve the SDK object
shape and the trusted fixtures.

## 2. ProofBundle is sent across a worker boundary as a WASM handle

**Evidence:** After fixing input encoding in the isolated baseline, verification
fails with missing proof/public-input bytes and `UnexpectedEof`.

`worker.js` returns Xark's wasm-bindgen `ProofBundle` instance directly to
`postMessage`. Structured cloning copies its handle, not its getter-backed proof
contents or methods. Successful benchmark calls also discard bundles without
freeing them.

**Impact:** The main thread receives an unusable proof, and repeated successful
proof calls can retain WASM allocations.

**Fix in this branch:** Copy proof/public-input bytes into an ordinary object
before posting it, then free the bundle. Free discarded benchmark bundles too.

## 3. Withdraw round-trip test treats padding as an encrypted output

**Evidence:** With the two caller fixes above, native transaction equality and
independent proof verification pass. The extra output-hash assertion still fails:
withdraw's finalized transaction has its real hash followed by a zero padding
hash, while `encrypted.utxoHashes` contains only the real encrypted output.

**Impact:** A valid transaction fails the browser test.

**Fix in this branch:** Compare encrypted output hashes against the corresponding
prefix. Keep the full transaction comparison, which checks the expected padding.

## 4. Ownership-tampering test mutates a nonexistent path and immutable text

**Evidence:** Reproduced in the browser suite as
`Cannot read properties of undefined (reading '1')`.

`tampering.spec.ts` uses `token_utxos_asset_a` even though the natural object uses
`tokenUtxosAssetA`. It also treats `owner.key.bytes` as a mutable byte array, while
the fixture represents it as `0x`-encoded text.

**Impact:** The test throws before asking the circuit to reject the mutation.

**Fix in this branch:** Mutate the correct property and replace one encoded byte
in the hex string. Keep the original valid input and fixtures unchanged.

## 5. Accepted WASM CLI flags have no effect, and verifier help is inaccurate

**Evidence:** Baseline `build/mod.rs::bridge` reads `wasm_features`, target, and
optimization, but ignores `no_prover`, `verifier`, `single_threaded`, and `nightly`.
`CompileOptions::threads()` is unused. Help advertises `verifyProof`, which is not
an implemented export.

**Impact:** Users cannot rely on advertised input-only/threading/verifier modes;
help describes an obsolete verifier interface.

**Fix in this branch:** Select actual runtime/helper features, record pool mode in
the package, describe the real verifier conversion helpers, and reject unsupported
custom nightly selection. The JS pool uses separate single-threaded instances.

## 6. Custom circuit output paths bypass Xark's helper-source inference

**Evidence:** Source-confirmed in Xark's `commands/client/mod.rs::crate_dir` and
reproduced by generating both clients from the existing artifacts. It recognizes
`<crate>/target/xark/<name>`, while this SDK uses `target/zk/<package>/<entry>`.
Both generation commands finish without producing a `client.wasm`.

**Impact:** Moving helpers into `#[input] impl` alone would not cause them to be
built in this pipeline. It also means the baseline has one application WASM
build, rather than two application builds.

**Disposition:** The selected composition route uses the application's existing
WASM root. Generated circuit clients explicitly omit a separate helper build;
Xark's general path-inference limitation is unchanged.

## 7. Native custom-codec test still depends on removed conversion APIs

**Evidence:** Source-confirmed in `program/tests/encryption_codec.rs`: imports
`zolana_program::conversion::{Allocator, ProofInput}` and calls `.instantiate()`.
Those conversion APIs no longer exist in the baseline SDK. The test also expects
serde serialization of the circuit state, which is no longer its current API.

**Impact:** This legacy test cannot validate the current circuit implementation
and prevents a successful full native test build when selected.

**Status:** Open; migration of this obsolete test is separate from composition.
It was not treated as a new compiler/runtime regression.

## 8. Existing generated-declaration check already fails SDK exports

**Evidence:** Running `node sdk-libs/program/tests/wasm/tools/check-dts.mjs` in the
original checkout fails on six existing functions, including `escrowTransaction`,
`compactCounterDataUtxo`, and the proof/VK conversion helpers. Their JsValue
parameters/results appear as `any` in the original generated declarations.

**Impact:** The existing blanket claim that every export is typed does not hold.
Adding the stock Xark runtime also exposes its intentional low-level JsValue
interfaces; those are not newly introduced serialization bugs in Xark.

**Status:** Open. The checker has not been weakened to hide this baseline failure.
A complete typed application facade needs a separate design using the existing
generated types; this task does not add a new Xark serialization framework.

## 9. WASM documentation describes removed prover and thread APIs

**Evidence:** Baseline `sdk-libs/program/README.md` advertises generated
`<Name>Prover`, zkeys, `verifyProof`, and `initThreadPool`, while the migrated SDK
uses Xark's binary artifacts and JS worker pool.

**Impact:** Following those instructions selects nonexistent APIs.

**Fix in this branch:** Update the feature table and WASM integration section to
the actual exports and supported runtime/pool loading. Other historical sections
remain candidates for a separate documentation sweep.

## 10. Node output can be interpreted as ESM instead of CommonJS

**Evidence:** Source-confirmed: the build uses `wasm-pack --no-pack`, which omits
package metadata, while the enclosing consumer/test package declares
`"type": "module"`. The nodejs-target glue uses CommonJS, including when the
existing pool worker loads an injected module through `require`.

**Impact:** Node can reject a valid generated module because of its enclosing
package's module type.

**Fix in this branch:** Emit `package.json` with `"type": "commonjs"` for nodejs
output only. Web output remains an ES module.

## 11. Failed WASM builds can leave a mixed output package

**Evidence:** Source-confirmed: baseline wasm-pack writes directly into the final
output directory. A later binding-generation or optimization failure need not
leave its JS, WASM, and declarations from the same successful generation.

**Impact:** A failed rebuild can replace part of the previously working package.

**Fix in this branch:** Build the complete package in a sibling staging directory
and rotate it into place only after success, with rollback on replacement failure.
This is not claimed to be an atomic transaction across two directory renames.

## 12. Explicit local Xark branches are rejected by revision checks

**Evidence:** Source-confirmed: baseline `tools/xark/build.sh` rejects every HEAD
other than `b443d83`; `compiler()` also requires that literal revision in version
output, even when deliberately using a local branch.

**Impact:** A local implementation branch cannot use the normal build entrypoint.

**Fix in this branch:** An explicit `XARK_SOURCE` selects a compatible local
checkout. The default path retains the pinned revision check and required patches.

## 13. Setup cache does not validate setup mode or verifying-key presence

**Evidence:** Source-confirmed in baseline `setup_one()`: it returns early when
the circuit digest matches metadata and `pk.bin` exists. It does not require
`vk.bin` or compare the requested test/production setup mode.

**Impact:** A missing verifying key is not repaired, and `--test` cannot reliably
select a different setup mode for an already-cached circuit as help implies.

**Status:** Open. Setup/key policy was not changed as part of WASM composition.

## 14. Check mode can still launch an SBF build

**Evidence:** Source-confirmed in baseline `build()`: it calls `compile()` and
then runs `cargo build-sbf` whenever `skip_sbf` is false, without checking
`compile.check`. Help states that check mode skips WASM and SBF builds.

**Impact:** A read/check operation can unexpectedly trigger a program build.

**Status:** Open; no SBF build was needed to validate this composition.

## 15. Existing test dependencies produce three high-severity audit findings

**Evidence:** `npm audit --json` against the unchanged WASM-test package lockfile
reports `bfj` and `jsonpath` through `underscore <=1.13.7`. The underlying advisory
is [GHSA-qpx9-hpmf-5gmw](https://github.com/advisories/GHSA-qpx9-hpmf-5gmw), covering
unbounded recursion/denial of service in Underscore flatten/equality operations.

**Impact:** The test tool dependency graph contains an existing vulnerable
transitive dependency. This observation does not establish application exposure.

**Status:** Open; dependency upgrades were not mixed into the composition change.
Audit details are time-dependent and should be regenerated when triaging.

## 16. Installed default macOS SDK cannot be linked by the installed CLT

**Evidence:** Fresh host build-script links fail parsing MacOSX27.0 SDK TAPI files
with an unsupported `arm64e.x1` architecture. The same builds succeed with
`SDKROOT=/Library/Developer/CommandLineTools/SDKs/MacOSX26.5.sdk`.

**Impact:** Cold Cargo/WASM builds fail on this machine before application code
is checked.

**Workaround for validation:** Set SDKROOT to the installed compatible SDK. This
is an existing machine toolchain mismatch, not a source defect or a repository
configuration change.

## Inherited Xark fixes already present before this implementation

- Region removal invalidated parent indices during input renumbering. The
  existing `input-region-indices.patch` retains indices and adds a regression test.
- Browser deterministic proof seeds were unrestricted. The existing
  `proof-randomness.patch` gates deterministic seeds behind `test-randomness` and
  rejects zero blinding values.

Both fixes were carried to the local Xark branch in a separate baseline commit.
They are not counted as new composition API changes.
