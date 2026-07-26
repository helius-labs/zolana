# P4. Cryptographic verification

Suite P4 of [proof-and-key-parity.md](../proof-and-key-parity.md): TypeScript
builds a balanced witness and prover request, the pinned local prover returns a
real proof, TypeScript parses it, and a test-only Rust oracle verifies the
artifact through the same `groth16-solana` decompress and
`Groth16Verifier::new` / `new_with_commitment` path and embedded release
verifying keys the program uses. Rejection mutations then require stable failure
codes (`encoding`, `rail_mismatch`, `verification_failure`, `unknown_vk`) rather
than library message text.

## Bottom line

**P4 certifies cryptographic verification for the fast-gate shapes and rails
listed below, through the real prover and the real `groth16-solana` path.** It
does not certify on-chain program execution of a TypeScript-built instruction,
and it does not yet run the full supported shape matrix in CI.

The evidence rating is **strong for prove-and-verify on the fast gate, moderate
overall** because program execution (steps 6–8 of the overlay) is an honest gap,
TypeScript G2 compression often falls back to Rust `alt_bn128_g2_compress_be`,
and `ZOLANA_TEST_P4_FULL=1` was not executed in this pass.

Fast gate (`ZOLANA_TEST_P4=1`), all green against prover
`http://127.0.0.1:3301` (`ZOLANA_PORT_OFFSET=300`): confidential Ed25519 1×1 and
2×3; confidential P256 2×3; zone Ed25519 1×1; zone-authority 1×1; merge 8×1.
Always-on oracle self-check and rail/shape mismatch cases run without a prover.
The full confidential and zone shape matrix, remaining zone-authority shapes,
and merge-zone are implemented behind `ZOLANA_TEST_P4_FULL=1` and belong in the
prover integration / slower job, not the always-on PR gate.

## What this suite added

`xtask/src/bin/groth16-verify` is the test-only verifier. It selects embedded
VKs from `zolana_interface::verifying_keys`, decompresses compressed points with
`groth16_solana`, accepts uncompressed wire points of the lengths the program
verifier sees after decompress, and dispatches on commitment presence the same
way the two rails do: P256 and merge families use
`Groth16Verifier::new_with_commitment`; Ed25519 transfer and zone-authority use
`Groth16Verifier::new`. A `compress` op wraps
`solana_bn254::alt_bn128_g1/g2_compress_be` so the suite can obtain program-
compatible compressed wire bytes when TypeScript’s noble path refuses a point.

`sdk-libs/ts/client/test/vectors/cryptographic-verification.test.ts` plus
helpers `p4-witnesses.ts`, `p4-prove-indexer.ts`, `p4-live-prover.ts`, and
`groth16-verify-oracle.ts` own the loop. Witnesses are built in TypeScript with
real Poseidon Merkle and indexed-nullifier proofs (not the unbalanced
`prover-shapes-v1.json` rows, which the prover rejects). Each live case verifies
uncompressed then compressed artifacts. The confidential Ed25519 2×3 case runs
the fuller rejection matrix; other live cases run the core A/B/C bit-flips,
wrong public-input hash, wrong shape key, and rail commitment presence checks.

Scripts: `npm run test:p4` (always-on), `test:p4:live`, `test:p4:full` under
`@zolana/client`. No committed proof fixtures and no `fixtures-check.mjs`
registration — proofs are randomized.

## Control edits

Two temporary edits were made to `verify` in `groth16-verify.rs`, each watched
failing the oracle’s own teeth, then reverted before commit.

Accepting every request at the top of `verify` (`return Ok(())` before VK and
rail checks) made commitment-on-Ed25519 and zero-point Ed25519 both return
`{"ok":true}`, and `--check` failed with `garbage proof verified; oracle has no
teeth`. That proves the always-on `rail_mismatch` and garbage-rejection cases
depend on those guards rather than on a stub that always rejects.

Skipping only the pairing path after the rail/commitment guards still returned
`rail_mismatch` for commitment-on-Ed25519, but accepted a zero-point Ed25519
proof and again failed `--check`. That proves the `verification_failure` path
(and the self-check’s garbage reject) depend on calling `Groth16Verifier`, not
merely on rail classification.

No production circuit, verifying key, or program edit was required. No control
edit was left in the tree.

## Gaps

Program execution against the same-revision shielded-pool SBF binary was not
run. The live witnesses use synthetic trees whose roots are not on a local
validator; depositing, indexing, and transacting is P5-shaped local-stack work.
Wrong-public-input and wrong-family rejections cover the “valid proof claimed
for different public inputs” threat at the verifier. They do not substitute for
an instruction that lands and fails or succeeds on chain.

TypeScript `compressProof` / noble G2 `assertValidity` rejected some live G2
points that Rust `alt_bn128_g2_compress_be` accepted. The suite falls back to
the oracle’s `compress` op and still requires compressed verification to pass.
That is a P3 handoff on production compression parity, not a silent P4 “fix”
of the TypeScript compressor. Uncompressed verification still goes through
TypeScript parse and the real verifier without that fallback.

`ZOLANA_TEST_P4_FULL=1` was not run here. The fast subset deliberately covers
both rails, the smallest and a mid confidential shape, one zone and one
zone-authority case, and merge, matching the overlay’s “one prove-and-Rust-
verify case per family” intent for a PR-adjacent live gate while keeping key
load time bounded. Full shape coverage remains the slower prover integration
job.

Changing a nullifier or other public leaf and rebuilding only a production
instruction was not exercised against the program. Cryptographically, flipping
the public-input hash under an otherwise valid proof is the corresponding
oracle case.

Workspace `npm run check:static` still reported unrelated errors under
`sdk-libs/ts/transaction` owned by a parallel Rust/TS CI worker; P4 files were
clean under `lint:packages`. Do not treat those transaction diagnostics as P4
failures.

## Handoffs

P2 owns prover-request, prover-inputs, prover-poll, and zone-oracle vector
files; this suite did not touch them. P3 owns
`proof-compression.test.ts`, `proof-canonical-oracle.test.ts`,
`prover-edge-cases.test.ts`, `p256-malleability.test.ts`, and production
`client/src/prover/` parse/compress — including the noble G2 rejection versus
`solana_bn254` acceptance finding above. Parallel Rust CI fixes in
`sdk-libs/client`, `indexer-api`, and `keypair` were left alone.

## Verdict

P4 is complete for the cryptographic claim the overlay defines on the fast
gate: a TypeScript-built witness yields a real prover proof that verifies under
embedded release keys through `groth16-solana`, and the rejection matrix has
teeth under the two control edits above. It is not a program-execution or full-
shape certification. Those remain explicit gaps for P5 and the slower prover
job.
