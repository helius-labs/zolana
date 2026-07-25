# 2026-07-25 23:05 UTC | prover subtree batch, C06 through C20 judged | `sdk-libs/client/src/prover/`

- Baseline: HEAD `c29d2f63`; oracles `client/test/oracles/prover-edge-cases-v1.json` and `field-alignment-v1.json`; batch commits `281491a6`, `52ca1e25`, `423ddd79`, `d9bd0eb2`, `102ef4bf`
- Worker: Opus 5 reconciliation subagent, judging [row-updates/prover-subtree.md](../row-updates/prover-subtree.md)
- Explanation: Fifteen rows, three closed. The batch claimed five at `PARITY`; I accepted three and held two, and the two I held are held for reasons the batch itself supplied, which is a sign the report was written to be checked rather than to be believed.
- Evidence: `sdk-libs/client/tests/ts_prover_oracle.rs` runs the production Rust `assemble` and the production `prover::field` helpers and writes what they returned into the two oracles. It fails when the committed file is stale, so the fixture cannot drift away from the Rust that produced it, and regeneration takes an explicit `ZOLANA_UPDATE_TS_ORACLES=1`. The TypeScript side rebuilds the same inputs from the same seeds. I ran `npx vitest run` over `client/test/vectors/prover-edge-cases.test.ts`, `client/test/vectors/field-alignment.test.ts`, `client/test/prover/circuit-types.test.ts`, and `client/test/prover/client.test.ts` at this HEAD: four files, 27 tests, passing.

## Three assembly rows close

- Verdicts: `PARITY` for `C10`, `C11`, `C12`

The existing twenty-shape sweep looked broad and was not: each shape had one real input in slot 0, dummies padding the tail, and a SOL-only public leg, so the branches where the two languages could most plausibly disagree sat outside it. The four new cases go where it could not, and one pair among them is a discriminator rather than another sample. A dummy slot inherits the first real input's signer, so an interior dummy between two mixed-scheme inputs must produce different `eddsaSignerIndexes` depending on which scheme comes first. A port that consumed `realInputs[realSignerIndex++]` in map order would produce the same list for both cases and would pass a fixture built any other way.

The comparison is per field rather than per digest: each `TransferInput` and `TransferOutput` on both rails, the public input hash, the per-slot signer index, the nullifiers, the root indexes, and the serialized instruction bytes. That reach is what lets me accept `C10`'s deliberate difference, where `validateSpendProof` rejects a mismatched leaf at assembly and Rust reaches the same refusal later during proving. The two stop in different places and accept the same set.

## Two `PARITY` claims held

- Verdicts: `PARTIAL` for `C06` and `C07`

`C06` is claimed at parity on alignment, decode, and the length bound, with one asymmetry pinned. The eight-input oracle is real and it closes the over-32-byte rejection that neither language tested before. The asymmetry is that at the BN254 modulus and at `0xff..ff`, Rust returns the number and `bytesField` raises `CLIENT_INVALID_FIELD`. The batch argues no such value reaches `bytesField` from a path Rust would carry to a proof, and the argument looks right. It is still a difference in an exported helper, argued unreachable rather than shown absent, and the row's inventory item is untouched besides. `PARTIAL` says both of those; `PARITY` would say neither.

`C07` is claimed at parity for the dummy witness, and for the dummy witness it is. The row is `inputs.rs`, which also declares `MergeInputs`, and no Rust-generated vector compares that. The residual the row named, a single dummy case in `proof-input-v1`, is closed.

## The deferral, as a property rather than a promise

- Verdicts: `MISSING` for `C13`, `C14`, and `C18`, unchanged

`circuit-types.test.ts` asserts that no `.ts` file under `client/src` contains the literal `"transfer-zone"`, `"transfer-p256-zone"`, `"transfer-zone-authority"`, or `"address-append"`, and that `proverRequest` produces the two transfer rails through the real `assemble`. The deferral now fails a test the moment a source file can name one of the four, which is a stronger thing than a row saying the code is absent today. It is also the evidence behind `C07`'s `BatchAddressAppendInputs` disposition and behind `C19`'s six missing entry points.

`C18` carries a consequence the queue should not lose: the transaction and interface packages already build `PreparedZoneAuthority` and its instruction data, so a TypeScript caller can assemble a zone-authority transaction and then find no way to prove it. The completeness audit found the same thing independently.

## Rows advanced, still adverse

- Verdicts: `DIVERGENT` for `C08`; `PARTIAL` for `C09`, `C15`, `C16`, `C17`, `C19`, `C20`

`C08` had three cases of TypeScript refusing input Rust accepts, each reachable because `parseProof` ships publicly while `proof_from_gnark_json` is `pub(crate)`. The three are fixed. The fourth is deliberate and points the other way: TypeScript refuses an eddsa request answered with a commitment-bearing proof, which Rust accepts and turns into a proof that cannot verify on chain. The row stays `DIVERGENT` against a Rust defect.

`C16` is the one where the batch corrected the row's reasoning as well as its code. The row said Rust has no aliasing hazard because `MergeProofResult` owns its nullifiers by value; the batch pointed out that `instruction_data(&self)` reads them too, so a `mut` binding has the same reach, and the real reason to copy is that the TypeScript surface is frozen and claimed an immutability it did not have.

`C09` is blocked by a visibility modifier rather than by difficulty: `to_json_merge` and `to_json_merge_zone` are `pub(crate)`, so no integration test can reach them. Making them `pub` closes the row in a few lines.

- Gap and smallest fix: `C09`, make the two merge JSON functions reachable from an integration test. `C15`, `C17`, and `C20`, correct `inventory.json`, which names three files the package does not ship, and generate the two merge fixtures; both need the `xtask` owner. `C08`, a Rust-side ruling on rail inference. `C06`, either accept the range check as a recorded asymmetry with a stated reason or drop it
- Row transitions: `needs_fix -> done` for `C10`, `C11`, `C12`; `needs_fix -> needs_re_review` for `C06`, `C07`, `C08`, `C16`, `C19` against landed fixes; evidence recorded on `C09`, `C13`, `C14`, `C15`, `C17`, `C18`, `C20` with no verdict change
- Progress: `67/145` after this entry
- Exact next file: `planning/typescript-sdk-port/row-updates/quality-and-completeness-audit.md`, rows `H01`, `H04`, `H05`, `E03`, then `keypair-error-redaction.md` row `K10`
- Full SDK parity claim: unsupported
