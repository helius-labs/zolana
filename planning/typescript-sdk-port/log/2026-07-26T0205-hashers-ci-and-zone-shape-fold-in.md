# 2026-07-26 02:05 UTC | the hasher, CI and zone-shape batches: two rows close, one reopens | C18, H08, M02, K13, K14

- Baseline: HEAD `c06abb97` on `port/reconcile`
- Worker: reconciler
- Explanation: folds the last three unreconciled row-update files, [hashers-b.md](../row-updates/hashers-b.md), [ci-green.md](../row-updates/ci-green.md), and [zone-authority-shape-narrowing.md](../row-updates/zone-authority-shape-narrowing.md). The third is a work request rather than a report of finished work, and it is the one that moves a row backwards.
- Evidence: `npm run check:packaging` and `npm run typecheck` at `ecfda044`, both clean; `docs/spec.md:1013-1020` read directly; the verifying-key directory and `interface/src/shape.ts` listed; the `zolana-batched-merkle-tree` dependents enumerated from the workspace manifests

## C18 reopens, and the reason is worth stating carefully

The row closed at `1b10b87c` recording the zone-authority shape mismatch as a hazard that needed an owner decision before the cryptographic phase. Reading the specification removes the need for a decision, which converts the hazard into a divergence.

`docs/spec.md:1013-1020` gives the zone-authority instantiation four supported shapes, 1x1, 2x2, 3x3 and 4x4. Four verifying keys exist and match. `SPP_SUPPORTED_SHAPES` holds ten, and the six extra are exactly the non-square members. The specification explains why the set is square: the rail proves no owner authorization and cannot move value out of the zone, so it reshuffles a fixed set of UTXOs instead of splitting or merging them.

The verdict needs reading precisely, because it is not the usual shape of a finding in this queue. TypeScript agrees with Rust here; both accept ten. They diverge from the specification together, and `docs/spec.md` outranks current Rust, so `DIVERGENT` records the difference from the specification rather than a difference between the two languages. The evidence that closed the row, comparing the twelve-element chain and the absent input-owner chain against Rust, is unaffected and stays credited for the four square shapes.

I reopened a closed row on a file that proposes work nobody has done. That is the right direction of error for this gate: a caller can assemble a 2x3 zone-authority request today and find out at proving time that no key can verify it.

## M02 and H08 close

`M02` named its own closing condition, rerun the export, browser and packed-artifact gates against a commit and record the result. `check:packaging` runs those three, alongside the inventory, dependency and api checks, and passes at `ecfda044`. The packed-artifact failure that was also holding it turned out to be one environment read in `@zolana/client`, not a `merkle-tree` behaviour and not a gate defect.

`H08` moves to `done` on a disposition, not a parity claim. Its reasoning improved from "no SDK caller", which the audit rightly called weak, to a reachability argument I could reproduce. One correction to the batch's phrasing: it says no `sdk-libs` crate depends on `zolana-batched-merkle-tree`, true directly but not transitively, since `program-libs/interface` does and the SDK depends on that. The conclusion survives on the narrower claim, that what `zolana-interface` takes from that crate is instruction data and a tree-init struct, neither of which computes `hashed_pubkey`.

## The two keypair rows keep their verdicts

`hashers-b.md` says no verdict change for `K11` through `K14` and I agree. What changed is factual: `K13` recorded the packed-package failure as "a defect in the packed-artifact gate or a freshly resolved dependency", and it was neither. `K14` claimed the keypair inventory names fixture paths that no longer exist; ten are named and ten exist. Both cells are corrected. `K13` stays `PARTIAL` on the absent trait fixture, `K14` on the `constants.rs` disposition.

- Verdicts: `DIVERGENT` for `C18`; `PARITY` for `M02`; `NOT_APPLICABLE` accepted for `H08`; `PARTIAL` unchanged for `K13` and `K14`
- Gap and smallest fix: `C18` owes a four-shape restriction in both languages with a named error and a shared vector, inside `sdk-libs`; adding the six missing keys is a `prover/` change and is wrong on the merits
- Row transitions: `C18` `done` to `needs_fix`, `PARITY` to `DIVERGENT`; `H08` `needs_re_review` to `done`; `M02` `needs_re_review` to `done`, `PARTIAL` to `PARITY`; `K13` and `K14` unchanged
- Progress: `95/145`
- Exact next file: none held; the oracle-strength audit of the `PARITY` rows resumes, and `C18` needs a fix worker
- Full SDK parity claim: unsupported
