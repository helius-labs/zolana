# Split spend: private membership, public non-membership

Non-membership is a statement about public data: the nullifiers are published and the indexed nullifier tree root is public. It does not need to live inside the private proof. This experiment splits a 512-input spend into two proofs with independent verifying keys and no shared witness:

- private half: `direct-payment-admitted` (membership, ownership, nullifier derivation, balance; unchanged from the admission branch),
- public half: `nullifier-freshness-gkr` (non-membership of the same nullifiers against a nullifier root).

The public half can be proven by anyone, so it can run concurrently with the private half on another core or machine, or later by a forester. The on-chain design that consumes the two proofs (stage with a pending-table reservation, finalize with the non-membership proof, then enqueue and append) is not part of this experiment. Only the prover side is measured here.

## Circuit

`GKRFreshnessCircuit` in `prover/server/circuits/direct_spend/freshness.go` is the existing `FreshnessCircuit` statement with every nullifier-tree hash routed through the existing GKR compressor. The public input hash is identical: `HashChain4(FreshnessDomain, tree id, root, count, HashChain4(nullifiers))`. The tree id is range-checked and bound into the statement; the program ties it to the root, as it does for the plain freshness circuit. The service circuit type is `nullifier-freshness-gkr`, shapes 144 and 512, key files `nullifier-freshness-gkr_<n>_0.key`.

Tests in `split_nip_test.go`: the circuit accepts padded and full freshness witnesses; it rejects a spent nullifier, a wrong root, a corrupted path, a wrong low-element index, a substituted nullifier, a wrong count, a next element below the nullifier, and a padding gap. `SPLIT_NIP_INPUTS=8` runs a real Groth16 setup, three proofs and verification (752,648 constraints; three verified proofs at 12.7–13.5 s on a 2-core, 7 GiB container).

## Constraint counts

Compiled with Go 1.27.1, gnark 0.16.3, `WithCompressThreshold(300)`:

| Circuit | Inputs | Constraints |
| --- | ---: | ---: |
| nullifier-freshness-gkr | 8 | 752,648 |
| nullifier-freshness-gkr | 144 | 1,425,372 |
| nullifier-freshness-gkr | 512 | 2,579,487 |
| direct-payment-admitted (private half) | 512 | 1,754,522 |

The public half is larger than the private half. Isolated gadget counts explain where it goes at 512 inputs:

| Term | Per input | Total | Share |
| --- | ---: | ---: | ---: |
| `AssertStrictlyOrdered` (low < nullifier < next, full field) | 2,048 | 1,048,576 | 41% |
| GKR fixed cost and transcript for 20,480 hashes | — | ~1,200,000 | ~46% |
| `IndexedLeafHash` (native Poseidon) | 241 | 123,392 | 5% |
| index bits, selects, count | ~400 | ~200,000 | ~8% |

Once GKR takes the hashing, the ordering comparison is the largest per-input term, and the transcript is the largest fixed term. Neither is a hash of a tree node. A separate GKR pool also costs one extra transcript compared with the admission branch's single pool; the branch's pool partition experiment measured the same effect (1,696,484 shared versus 2,657,255 split at 144 inputs).

## Measurements

Apple M5 Pro, 18 CPUs, Go 1.27.1, gnark 0.16.3, `GOMAXPROCS=18`, `GOMEMLIMIT=32GiB`, resident keys, three samples per row, every proof verified. Setup of the 512 public key took 61.5 s real. Prove times include witness solving, GKR and Groth16; witness construction (1.9 s private, 1.2 s public in this fixture), key loading and verification are outside the timer. Raw values in [`split-nip-results.json`](../prover/server/benchmarks/split-nip-results.json).

| Mode | Half | Constraints | Median prove | Wall |
| --- | --- | ---: | ---: | ---: |
| alone | public | 2,579,487 | 3.648 s | — |
| sequential | private | 1,754,522 | 3.000 s | 6.833 s |
| sequential | public | 2,579,487 | 3.833 s | |
| concurrent | private | 1,754,522 | 3.553 s | 5.664 s |
| concurrent | public | 2,579,487 | 5.659 s | |

Concurrency on one machine saves 17% of wall-clock, not the 44% that a free second proof would give: the public half slows from 3.83 s to 5.66 s and the private half from 3.00 s to 3.55 s while they share 18 cores. Groth16 already saturates most of the machine, so the gain is the unused remainder. With two prover instances the wall-clock is the slower half, 3.83 s.

Against the branch's 512-input reference points (same class of machine, resident keys): the PR #320 comparator's proof stage is 12.147 s across 16 proofs, the admission route's is 2.837 s for one proof. The split design's proof stage is 5.66 s on one machine and 3.83 s on two, that is 2.1× or 3.2× faster than the comparator and 1.3–2.0× slower than admission. These are proof-stage numbers; the split design also adds one transaction round to settlement, and the localnet harness has not been run for it.

## Assessment

The public half is exact and anonymous where admission is probabilistic and needs an owner signer, and it keeps the nullifier tree, the batch circuit and all spend routes unchanged. It costs one extra GKR transcript and, until the ordering comparisons are cheaper, more constraints than the private half, so the parallelism only pays on separate machines. The result is between the two existing designs: about half the comparator's proof time on one box, a third on two, and not a replacement for admission on raw latency.

## Reproduction

From `prover/server` with `proving-keys/direct-payment-admitted_512_2.key` present:

```sh
scripts/split_nip_bench.sh 512 3
```

The script generates `nullifier-freshness-gkr_512_0.key` when missing, runs `TestSplitNipProving` (public half alone, three verified proofs) and `TestSplitNipConcurrentProving` (both halves sequentially, then concurrently, each proof verified) and writes logs to `benchmarks/split-nip-*.log`. `GOMAXPROCS` and `GOMEMLIMIT` default to 18 and 32 GiB.

## Next levers

Reducing the public half means attacking the two non-hash terms. A nullifier tree keyed on a 253-bit truncation of the nullifier would allow range-checked differences instead of full-field comparisons (a protocol change to the tree and the batch-append circuit). Deriving GKR layer challenges from the BSB22 commitment with a cheap in-circuit PRG instead of a Poseidon2 sponge per layer would remove most of the transcript cost (a soundness argument to write down). Both apply equally to the private half.
