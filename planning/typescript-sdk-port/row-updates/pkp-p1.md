# P1. Public-input assembly

Suite P1 of [proof-and-key-parity.md](../proof-and-key-parity.md): for each
circuit family, rail, shape, and the required mixed-owner case, one canonical
logical input is assembled through production Rust and independently through the
public TypeScript interfaces, and every named intermediate is compared before
the final `public_input_hash`.

## Bottom line

**P1 certifies for the confidential, zone, zone-authority, and merge families
covered by the committed fixtures.** TypeScript reproduces every named
confidential chain element Rust emits for all ten supported shapes on both
rails, the mixed P256/Ed25519 owner case, the zone and zone-authority root and
owner chains, and the distinct default versus zone merge owner-binding tails.
No Rust-versus-TypeScript divergence turned up in those layers.

The evidence rating is **strong for assembly parity, not for proof
verification**. This suite never asks a prover for a proof and never runs the
shielded-pool verifier. It would catch a TypeScript assembler that built a
different public-input statement (including the threat-model case of a proof
bound to the wrong public inputs), and it does not stub proving or
verification because it does not reach those layers. Live prove-and-verify
remains later in the certification sequence.

## What already covered P1 clauses

Several vector suites were already in place and were folded in by reference
rather than rewritten.

`prover-inputs.test.ts` against `prover-shapes-v1.json` already compared the
complete confidential witness, prover JSON, instruction bytes, and the final
`publicInputHashBytes` for every supported shape on both rails. It did not
compare the named intermediate chains, so a failing final hash named no layer.

`zone-oracle.test.ts` against the cargo-test oracle already compared many
payload fields, nullifiers, output hashes, root indexes, the final hash, and
request bodies for every zone and zone-authority shape. It did not assert
`nullifierChain`, `outputHashChain`, `utxoRootChain`, `nullifierRootChain`, or
`inputOwnerChain`, even though the first two were already in the oracle. The
zone-authority shorter-chain and P256 zero-sentinel owner tests already spoke
to “owners private / absent from the public hash” and “non-zero zone field”.

`merge-oracle.test.ts` already compared final hashes, nullifiers, ciphertext,
and request bodies for default merge and merge-zone. It did not name the
owner-binding tails that distinguish the two rails.

`two-inputs-hash-chain.test.ts`, `program-libs-hash-chain.test.ts`,
`field-alignment.test.ts`, and `proof-canonical-oracle.test.ts` cover hasher
and field primitives the assembly path depends on, not public-input assembly
itself.

## What this suite added

`xtask/src/bin/public-input-assembly` (with `--check`, registered in
`fixtures-check.mjs`) calls production `assemble`, `MergeProver::build`, and
`MergeZoneProver::build`, then records every named confidential chain element
via `create_hash_chain_from_slice` / `hash_field`, plus the merge head and the
two owner-binding tails. The committed fixture is
`sdk-libs/ts/fixtures/client/public-input-assembly-v1.json`. Its confidential
final hashes match `prover-shapes-v1.json` on the shared seeds, so the two
fixtures describe the same logical inputs.

`sdk-libs/ts/client/test/vectors/public-input-assembly.test.ts` rebuilds those
inputs through `buildProofInputs` / `assemble` and the merge assemblers, then
compares each intermediate independently before the final hash. It also
re-folds the fifteen confidential elements from the assembled leaves so a
stubbed final hash that ignored an intermediate still fails. The mixed-owner
row places one P256 and one Ed25519 real input on the P256 rail and checks both
the owner chain and the per-input signer indexes.

The zone oracle’s `chain_json` / `p256_chain_json` now also emit
`utxoRootChain`, `nullifierRootChain`, `inputOwnerChain`, and
`p256MessageDigestField`. The existing zone suite asserts those chains by
computing them from the assembled payload, requires a non-zero zone field, and
shows that folding the authority rail’s witness owners into the twelve-element
preimage does not reproduce the authority public-input hash.

## Control edits

Three production edits were made, each watched failing, then reverted.

Swapping the confidential appendix order (`p256SigningField` before
`outputOwnerChain`) failed twenty confidential rows at
`publicInputHash`. That is the “valid proof for different public inputs”
failure mode at the assembly layer: the leaves can look right while the folded
statement moves.

Forcing both merge rails onto the default owner-identity tail failed the zone
merge row at `publicInputHashBytes` while the default merge still passed. The
suite therefore separates the two tails rather than only checking that some
hash exists.

Replacing the confidential zero zone field with `1n` in the hash while leaving
`payload.zoneProgramId` at zero failed at the final hash. The payload still
reported a zero zone field, so a test that only checked that field would have
passed; comparing the hash (and re-folding from the payload) caught the
mismatch.

## Gaps

Zone and zone-authority named intermediates still live in the cargo-test oracle
(`ts_zone_oracle`) rather than in the new xtask binary. They are gated by
`ts_zone_oracle_is_current` and by the TypeScript zone suite; they are not in
`fixtures-check.mjs`. Extending that binary to re-emit zone chains would
duplicate an oracle that already works.

No mixed-owner case was added for the zone rails. Confidential mixed-owner is
covered; zone mixed-owner remains a later row if the certification sequence
asks for it.

P1 does not certify prover request JSON (P2), proof parsing or compression
(P3), or Rust/program verification of a TypeScript-produced proof. Those are
later suites. The “tests pass because proving is stubbed” threat is out of
scope here in the sense that this suite never reaches a prover; within its
scope, the re-fold and per-intermediate checks refuse a stubbed final hash.

## Verdict

P1 is complete for the assembly claim the overlay defines: named intermediates
and final hashes agree across Rust and TypeScript for confidential (all shapes,
both rails, mixed owners), zone, zone-authority, and merge (default and zone
tails). The honest rating is strong assembly evidence, not a proof-certification
verdict.
