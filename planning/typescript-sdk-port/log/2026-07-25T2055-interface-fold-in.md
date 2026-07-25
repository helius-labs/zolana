# 2026-07-25 20:55 UTC | interface parity batch folded into the table | `program-libs/interface/`

- Baseline: HEAD `ce2612d2`; fixture `43fde8e45d3b1d78aa4c7517a07d6a9675d9bf9f`; Rust drift `none new this entry`
- Worker: Opus 5 reconciliation subagent, folding [row-updates/interface-parity.md](../row-updates/interface-parity.md); batch merged at `abe3663a`
- Explanation: The interface batch reviewed all 37 rows against a generated Rust oracle instead of reading the two languages side by side, and it changed no file under `sdk-libs/ts/interface/src/**`. That is the substantive finding: the rows were open for want of evidence rather than for want of correctness, and the same reading that had twice recorded parity on a real asymmetry is what the oracle replaces.
- Evidence: `xtask/src/bin/ts-interface-oracle.rs` links against the real `zolana-interface` crate and prints what it does as JSON: every constant and tag, all 26 error codes and messages, the shape list in order, `ciphertext_hash`, `pk_field` and `pack33` across chunk boundaries, every PDA and bump, the `bytemuck` image of each state account, `wincode` bytes per instruction-data type, the full `Instruction` for every builder with account metas and flags, `external_data_hash`, the accept or reject verdict of each Rust decoder on hand-built non-canonical input, and the scraped `pub use` list per `mod.rs`. Its output is committed at `interface/test/rust-oracle.json` and consumed by 41 tests in `interface/test/vectors/rust-oracle.test.ts`. Two guards make it hard to satisfy dishonestly: the generator panics when a Rust builder re-export has no instruction vector, so a new builder breaks generation rather than passing quietly, and the re-export ledgers assert set equality against an explicit name mapping. I ran the suite rather than relaying its counts, and I read `decodeAcceptance` in the committed JSON and the prefix guards at `codecs/index.ts:454` and `:525` to settle which rows the one divergence actually reaches.

## Twenty-nine rows close on the oracle

- Verdicts: `PARITY` for `I01`, `I02`, `I03`, `I04`, `I05`, `I06`, `I10`, `I11`, `I12`, `I13`, `I14`, `I15`, `I16`, `I17`, `I18`, `I22`, `I23`, `I24`, `I25`, `I27`, `I28`, `I29`, `I30`, `I31`, `I32`, `I33`, `I34`, `I35`, `I36`

Four of those are the repointed rows, and the repointing is preserved: `I02` at `shape.ts`, `I03` at `merge-utils.ts`, `I30` and `I34` at `state.ts`. `I34` is worth a sentence, because `index.ts` does re-export its constants, so reviewing at the root would have confirmed that a name is exported rather than that its value matches Rust. The oracle compares values.

Two rows close because their authority conflict is settled rather than because anything was rebuilt. `I10` and `I22` were `BLOCKED` on a protocol-config contract the spec described as a full rewrite; `58b2be6a` recorded the update as single-field, and the oracle then matched all seven variants, their indices, and the incoming-authority co-signature that applies to `protocolAuthority` alone.

Three rejection findings and one leniency are pinned where the languages agree, so later work cannot move them unnoticed: trailing bytes after a deposit payload, a non-canonical bool inside a merge payload, and a protocol-config account with a wrong discriminator or short buffer are refused by both, while `state > accepts the nonzero flag bytes Rust decodes as true` holds TypeScript to Rust's own leniency. Tightening that last one would be the same error as the divergence below.

## The merge prefix asymmetry, on four rows rather than three

- Verdicts: `DIVERGENT` for `I08`, `I09`, `I20`, `I21`

TypeScript refuses a merge payload the Rust decoder reads. Given a `MergeTransactIxData` or `MergeZoneIxData` whose `encrypted_utxo` first byte is not `2`, Rust deserializes it, because the prefix is not part of the wire format and the shielded-pool program is what rejects the payload with `InvalidMergeOutputScheme` (7014). The TypeScript codecs throw `INTERFACE_CODEC`, on decode at `codecs/index.ts:525` and on encode at `:454`. Nothing valid is lost, since such a payload is refused on either path; what a TypeScript client cannot do is read or construct one, which matters for indexing and for debugging a failed transaction.

The batch pinned this rather than repairing it, in a test that fails if Rust starts rejecting the bytes or TypeScript starts accepting them. That is the right call: both behaviours are defensible and the choice belongs to the protocol owner. These rows are restated because `I08`, `I20`, and `I21` were recorded `DIVERGENT` on this exact conflict at `11:40` and `PARITY` at `12:07` with no fix commit between, which is what closing a divergence by tightening rather than by testing looks like from the outside.

`I09` is mine rather than the batch's. It counted `merge_zone.rs` among its 33 closures on exact `wincode` bytes, while its own pinning test asserts that `mergeZoneAcceptsNonCanonicalPrefix` is true in Rust and that `mergeZoneInstructionDataCodec.decode` throws. A row whose codec is proved to differ from Rust is not parity, so `I09` joins the other three. The builders `I20` and `I21` are here for the encode-side guard: they reuse the codec, and `MergeTransactIxData::serialize` writes whatever the caller holds, so TypeScript will not build a payload Rust builds.

These four take the new `pinned_divergence` status, added to the vocabulary in the same commit and documented under Vocabulary. `needs_fix` would promise a fix nobody is authorized to make, and `needs_re_review` would promise a reading that has already happened twice.

## Four rows close only partially

- Verdicts: `PARTIAL` for `I07`, `I19`, `I26`, `I37`

`I07`, `I19`, and `I26` move off `BLOCKED`, because the `docs/spec.md` deposit conflict is settled at `b97b2a88` and the discovery-tag ruling is applied at `1ff51a4c` and `114a5140`. Their layout, codec, and builder parity is closed with exact `wincode` bytes and exact builder output on the SOL and SPL rails across both the outer and CPI routes. One residue keeps all three short of parity: nobody has confirmed that the regenerated wallet deposit fixtures write the ruled-on tag. The interface cannot answer that, because both languages treat the tag as an opaque 32-byte field, `DepositIxData::view_tag: [u8; 32]` against `writer.bytes(value.viewTag, 32, "viewTag")`, and neither derives, validates, nor interprets it. I carried the batch's own hedge here rather than counting these as closed.

`I37` keeps the residue the row already named: the frozen-revision fixture gate still fails with `baseline fixture sources differ from revision 43fde8e4`, which is G8-1 and belongs to the fixture-gate worker.

- Gap and smallest fix: `I07`, `I19`, `I26`, confirm the regenerated wallet deposit fixtures write the signing-pubkey tag. `I37`, re-pin the baseline manifest, which is G8-1 and not scoped to interface behaviour. `I08`, `I09`, `I20`, `I21`, an owner ruling on whether a TypeScript client should be able to read and build a merge payload the program will reject
- Row transitions: `-> done` for the 29 rows above; `needs_re_review -> pinned_divergence` for `I08`, `I09`, `I20`, `I21`; `needs_re_review -> needs_re_review` for `I07` and `I19` with the verdict moved off `BLOCKED`; `needs_fix -> needs_re_review` for `I26`; `needs_fix -> needs_fix` for `I37`
- Progress: `48/145` after this entry; the interface package is `29 of 37` closed, with 4 pinned and 4 partial
- Exact next file: `K01 sdk-libs/keypair/src/constants.rs`
- Full SDK parity claim: unsupported. The interface package now rests on a generated oracle rather than on side-by-side reading, which is the pattern the other packages need
