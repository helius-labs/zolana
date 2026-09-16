# Combining clustered membership, GKR and on-chain spentness

The two ideas fit together as alternative proof implementations over one payment/admission protocol. Adding the current GKR Merkle compressor to an already compact clustered proof is counterproductive in circuit size. Applying GKR to scattered-note membership after removing in-circuit nullifier nonmembership is more promising.

## Compilation experiment

Source: `experiment/merge/second-gkr`, commit `402540cdc`. A temporary Go overlay extends the existing experimental `compactPayment` helper with the production GKR compressor. Both implementations reuse the same ownership, value, nullifier derivation and payment bindings. The circuit authenticates complete privately positioned groups and uses external nullifier admission in every row. Two outputs and 512 real inputs are fixed throughout; group size one permits independent scattered positions.

| Note group size | Conventional constraints | GKR constraints | Conventional FFT | GKR FFT |
| ---: | ---: | ---: | ---: | ---: |
| 1 (scattered) | 4,522,594 | 1,754,023 | 2²³ | 2²¹ |
| 16 | 873,506 | 1,433,348 | 2²⁰ | 2²¹ |
| 512 | 668,507 | 1,350,524 | 2²⁰ | 2²¹ |

The standard GKR transcript has enough fixed cost to outweigh the saved hash constraints for these clustered shapes. This is a constraint/FFT comparison, not a measured proof-time regression. GKR helps the scattered variant by 2.58× in constraints. Relative to the currently integrated 3,345,785-constraint GKR512 payment, external admission brings it to 1,754,023 and halves the FFT domain. No new proving keys or proof-time measurements were produced.

The compilation test passed. Separate eight-note witness checks passed with group sizes 1, 4 and 8 and rejected changed roots, positions and amounts. This is a small correctness check, not full protocol validation. External historical spentness remains a required program rule; the compact pending-nullifier table is only a recent-spend guard and cannot replace it by itself.

The overlay leaves the implementation worktree unchanged. Reproduction patch: [hybrid-cluster-gkr.patch](../prover/server/benchmarks/hybrid-cluster-gkr.patch). Apply to an isolated checkout of the source commit, then run from `prover/server`:

```sh
GOMAXPROCS=4 GOMEMLIMIT=16GiB go test ./circuits/direct_spend \
  -run '^TestHybrid(Screen|Witness)$' -count=1 -timeout 5m -v
```

[Raw output](../prover/server/benchmarks/hybrid-cluster-gkr.log) · [Machine-readable counts](../prover/server/benchmarks/hybrid-cluster-gkr.json)

## Architecture to test

Use compile-time proof variants selected for the actual note layout: ordinary compact proofs for complete owned groups; GKR membership for large scattered sets. Keep positions private within each variant. A selector can reveal the broad circuit/layout class, so it should not expose individual group positions. Mixed layouts need their own measured shapes; selecting modes inside one fixed circuit does not remove the unused mode's constraints.

Move historical nullifier admission on-chain once for both variants, with exact spentness or an append-only Bloom-negative path plus exact positive fallback. Every spending route must update the same authoritative history and enforce atomic duplicates. Start in a new empty domain or authenticate complete legacy history before allowing fast negatives. Never treat an empty recent-spend table or a reset filter as complete history.

This also removes nullifier-tree witness retrieval on the negative fast path. Cluster witnesses should retrieve group paths rather than hundreds of individual paths. The current SDK can start uploading the proof-independent statement prefix while proving: its payload serializes the statement before the proof, and the program already supports append-only uploads. Removing a confirmation barrier per upload requires additional submission/buffer design and measurement; the existing ordered-offset writes cannot simply be assumed to land in order when broadcast concurrently.

## What 10× requires

Against the measured resident-key PR #320 median of 21.846 s at 512 inputs, the target is at most 2.185 s through recipient decryption. Current GKR leaves a median 5.331 s after subtracting proving. The combined design therefore must improve witness retrieval and submission as well as circuit cost. Neither the old 14.02× native proving result nor this compilation experiment establishes that end-to-end target.

The first useful integration experiment is the scattered GKR plus authoritative on-chain spentness path: it tests the shared architectural gain without depending on favorable wallet layout. Add the ordinary clustered variant for eligible wallets, then measure resident-key complete payments with proof/upload overlap. Apply equivalent scheduling improvements to the PR #320 comparator. For a stronger structural reduction, future notes could represent an atomic private bundle with one spend identifier per bundle; that changes note issuance and partial-spend semantics and cannot reduce legacy note/nullifier counts for free.
