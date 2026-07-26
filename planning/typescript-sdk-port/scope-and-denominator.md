# Scope and denominator

What this branch can finish, what it cannot, and the number the entry criterion
actually runs against. Counted at `2026-07-26 00:35 UTC` against HEAD
`3cacdb4c`, and re-run against the gate at `01:40` on 2026-07-26 with each
figure below unchanged: 145 rows, 90 closed on parity, 6 on a
`NOT_APPLICABLE` disposition, 45 adverse.

The counts have held while the code moved underneath them, which is worth
saying plainly. Several of the rows counted adverse here now have a committed
fix on a batch branch that the checklist has not absorbed, so the denominator
measures what the reconciler has recorded rather than what has been written.
[`remaining-work.md`](remaining-work.md) tracks which those are.

## The headline

**None of the 145 rows is terminal.** The 49 open rows can be closed from
this branch. The three the coordinator nominated as needing a change outside
`sdk-libs` do not need one, and the check that produced that answer is recorded
below so it can be repeated rather than believed.

The denominator for the entry criterion, that adverse rows are implemented and
re-reviewed, is **45**. Not 145, and not a smaller number arrived at by setting
hard rows aside.

## The scope rule this pass applied

A row is terminal when closing it requires editing `programs/`,
`program-libs/` Rust, `prover/`, or a circuit. Editing Rust inside `sdk-libs`
is in scope: this port has changed Rust SDK code when Rust was the wrong side,
at `M01` and at the merge oracle generators. Confusing "Rust" with "out of
scope" is what made three rows look terminal, and it is the single correction
this document exists to make.

Two things that also do not make a row terminal:

- A specification amendment. `docs/spec.md` is the protocol's source of truth
  and this branch does not edit it, but the owner has amended it three times
  during this port when the document lagged the implementation. A row waiting
  on an amendment waits on a person, not on a component.
- A decision between two defensible behaviours where both fixes are SDK-side.
  That is the `pinned_divergence` status, and it costs a sentence from the
  owner rather than a pull request against `main`.

## The three candidates, checked

| Row | Nominated as | What the check found | Now |
| --- | --- | --- | --- |
| `T21` | Needs a `program-libs/interface` change | Ruled at `3cacdb4c`. The program keeps truncating the `ExternalDataHash` length prefix and both SDKs refuse the oversized input loudly. The work is a guard in `sdk-libs/transaction` matching one TypeScript already has, plus the boundary vector at `0xffff` neither language holds | `needs_fix` / `PARTIAL`, in scope |
| `T23` | Rust lacks canonical BN254 range validation | The specification conflict is settled by the amendment at `1d6b9873`, which described the implementations rather than moving code or keys. The residual is `internal.ts:117` refusing a field input at or above the modulus while `spp_proof_inputs.rs` range-checks nothing. Both files are `sdk-libs` | Half fixed. `d3514b24` made the proof-coordinate parser canonical and modulus-checked; `spp_proof_inputs.rs` still range-checks nothing, so the row stays `needs_fix` / `DIVERGENT` |
| `C08` | Fourth strictness finding needs a protocol-owner ruling | Ruled at `3cacdb4c`, and the ruling corrects the nomination by name: the rail-inference defect is in `sdk-libs/client/src/prover/proof.rs`, an SDK crate, and no program or circuit is involved | Fixed at `d3514b24`, which passes the requested rail through the parser instead of inferring it. Still reads `needs_fix` / `DIVERGENT` until the reconciler folds it in |

Extending the list was the other half of the task. I grepped the 49 open rows
for `programs/`, `program-libs/`, `prover/`, and circuit references and read
each hit. The candidates it surfaced beyond the three were `I07`, `I19`, `I26`,
and `X01`, where current Rust and TypeScript agree with each other and
`docs/spec.md` describes something else, so each needs an amendment rather than
a component change; and `C06`, `C15`, `C19`, `C20`, `C21`, `C22`, whose hits
are the path `sdk-libs/client/src/prover/`, which is an SDK crate that happens
to be named after the prover.

## The 145, sorted by what they need

| Class | Rows | Count |
| --- | --- | --- |
| Closed | | 96 |
| Closed on demonstrated parity | | 90 |
| Closed on a confirmed `NOT_APPLICABLE` disposition | | 6 |
| Open, ordinary work | see below | 41 |
| Open, awaiting one ruling, fix in scope either way | `I08` `I09` `I20` `I21` | 4 |
| Open, disposition needing a confirming artifact rather than code | `E03` `E05` `E06` `H08` | 4 |
| Terminal | none | 0 |

The 41 by package: interface 4 (`I07` `I19` `I26` `I37`), keypair 4
(`K11`-`K14`), merkle-tree 1 (`M02`), transaction 15, client 13, wallet 2
(`W02` `W04`), indexer-api 1 (`X01`), smart-account-client 1 (`S01`).

**The denominator is 45**: the 41 plus the 4 pinned, which are adverse and must
be implemented and re-reviewed like the rest once the ruling names a side. The
four disposition rows are not adverse; they owe an artifact, not an
implementation.

## The four pinned rows, since one sentence clears them

**The sentence has been said, and this section is kept for the reasoning rather
than the status.** See step 2 of [`remaining-work.md`](remaining-work.md) for
where the four rows now stand, and
[`row-updates/merge-prefix.md`](row-updates/merge-prefix.md) for the decision.

`I08`, `I09`, `I20`, and `I21` are the same finding on four surfaces:
TypeScript refuses a merge payload whose `encrypted_utxo` first byte is not
`2`, which the Rust decoder reads because the prefix is not among the bytes
the decoder parses and the shielded-pool program is what rejects it, with
`InvalidMergeOutputScheme` (7020). No valid transaction is lost either way.
What TypeScript could not do is decode such an instruction while indexing or
debugging a failed transaction.

Both fixes were in scope: drop the guard from `sdk-libs/ts/interface`, or add
the matching guard to `program-libs/interface`, which this branch would not do.
The standing instruction, that a port stricter than its original silently
breaks callers, pointed at dropping the guard, and that is what happened. The
worker on `port/merge-prefix` reached it through the Light Protocol rule rather
than through a fresh ruling, and went one step further than this section
recommended by relaxing the encode side too, on the ground that Light treats
both ends the same way. The fix is `78039fe9`.

## Findings whose fix is genuinely outside, and the route each should take

The distinction the coordinator asked for, separate pull request against `main`
against accepted limitation, applied to the items that are actually outside.
Choosing the route is the owner's; the recommendation is mine and marked as
such.

| Item | Divergence | Component that must change | Route |
| --- | --- | --- | --- |
| `PD-1` | A padding dummy input's public nullifier column is unconstrained in the circuit and the program inserts it anyway. A chosen padding nullifier can wedge the nullifier queue and freeze shielded balances pool-wide | Circuit, `prover/server/circuits/`, and the program's insert path | Recommend its own pull request. This is a liveness risk with an executed reproduction, not a boundary out of a caller's reach |
| `PD-2` | `merge_transact` does not tie its `user_record` to the owner whose UTXOs are merged, so a delegate holding the `nullifier_secret` and blindings can substitute a record | `programs/shielded-pool` loader, plus a signature over the record at `register` and `update_keys` proving the caller holds `owner_p256` | Its own pull request, already taken: branch `fix/merge-user-record-binding`, commit `a811b20e`, PR #160. **Correction to the standing precedent: #160 is open, not merged, and `a811b20e` is not an ancestor of `main` at this HEAD.** The route is the precedent; the merge has not happened |
| `address-append` | TypeScript ships no forester, so the builder had neither a producer nor a proof path | Nothing. Producing the proof needs witness generation and gnark proving | Accepted limitation, ruled `2026-07-25`: withdraw the builder from the public surface, do not port the witness. Tracked as ordinary work on `C07` |
| Zone-authority key coverage | `ZoneAuthorityProver::build` resolves against ten `SPP_SUPPORTED_SHAPES` while `program-libs/interface/src/verifying_keys/` holds four zone-authority keys, so both SDKs will build a 2x3 request the prover server cannot serve | Either none, by narrowing the accepted set in both SDKs, or `prover/` and `program-libs/interface` to generate the six missing keys | Needs the owner's answer before the cryptographic phase. If the shapes should be servable it is a separate pull request; if not, the narrowing is in scope and belongs on a row that does not yet exist. Recorded today only inside the closed `C18` |

## How to recount

```bash
node sdk-libs/ts/config/review-checklist-check.mjs   # rows, done/PARITY, verdict attribution
```

The gate counts `done` with `PARITY` and reports 90; the six
`done` / `NOT_APPLICABLE` rows are closed but excluded from that figure by
design, which is why 96 and 90 both appear above and neither is wrong.
