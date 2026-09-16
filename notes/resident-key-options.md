Resident-key precomputation is a valid optimization to investigate, but current evidence does not establish a general 10× payment improvement. This review performed no builds or benchmarks and changed no proving code.

The following counts come from reading serialized key headers and seeking over point vectors without decoding points. Affine memory includes the four Groth16 G1 vectors, the G2 vector, and BSB22 bases where present; it excludes the constraint system, FFT tables, working memory, and small fixed elements.

| Key | File bytes | Affine vector memory | 16-fold shifted-base table |
| --- | ---: | ---: | ---: |
| Admitted 512×2, full height | 574,137,510 | 0.607 GiB | 9.71 GiB |
| DAG10 512×2, conditional | 267,031,229 | 0.295 GiB | 4.72 GiB |
| PR #320 merge 36×1 | 240,902,581 | 0.275 GiB | 4.40 GiB |
| PR #320 cached transfer 36×2 | 251,172,476 | 0.283 GiB | 4.53 GiB |

Full-height admitted has 6,852,727 G1 vector points and 1,664,602 G2 points. The comparator needs only two unique keys: its merge table is reused across all 15 merges. Their combined affine memory is 0.558 GiB. Expanded tables can fit this 48 GiB host, subject to active proof workspaces and other resident keys. They must be shared across requests and evaluated under the same memory budget for both routes.

Native `gnark@v0.16.3/backend/groth16/bn254/prove.go` runs four large G1 MSMs and one G2 MSM, plus commitment work. `gnark-crypto@v0.21.0/ecc/bn254/multiexp.go` chooses Pippenger windows from 4–16 bits and rebuilds scalar digits and buckets per call. There is no reusable fixed-basis table option in that API. `BatchScalarMultiplicationG1` handles many scalars against one base; it is not a replacement for these many-base MSMs.

A shifted-base table is secure and key-compatible: precompute public multiples of the fixed key points and split each scalar across them. However, expanding bases by factor `f` while reducing scalar length by `f` leaves approximately `n × 254 / window` bucket insertions. It mainly reduces window reductions and changes scheduling/cache behavior. A subset-sum table for groups of `k` bases needs roughly `2^k / k` stored points per original point and `254 / k` online additions per original point. The feasible range near `k=9–10` does not beat the approximate addition count of current 16-bit Pippenger. These are arithmetic models, not measured speedups or impossibility proofs.

FFT twiddle and coset tables already come back at key loading: all inspected keys have `withPrecompute=true`, as defined by `gnark-crypto@v0.21.0/ecc/bn254/fr/fft/domain.go`. Key-only MSM tables also leave most witness solving and GKR work intact. The [diagnostic profile](../prover/server/benchmarks/admitted-payment-profile-512.log) recorded 0.962 s of solver/GKR work before 1.820 s of subsequent Groth16 work. In the earlier [paired localnet run](../docs/admitted-payments.md), upload took 3.554 s and already exceeded the overlapping 3.011 s proof. Faster MSM alone could not remove that upload bottleneck.

Receiving-time certificates are a different optimization. [Prepare](../programs/shielded-pool/src/instructions/direct_spend/prepare.rs) verifies membership only while the receipt is unprepared; later refreshes verify freshness without rechecking the original state root. [Commit](../programs/shielded-pool/src/instructions/direct_spend/commit.rs) accepts prepared receipts with live freshness and a balance proof. State-root history currently has [500 entries](../program-libs/tree/src/smt.rs), so an off-chain certificate cannot simply ignore root expiry: it must be registered while its root is accepted, or use a new permanent-anchor mechanism.

Complete on-chain nullifier history could support a new admitted-certificate path that removes freshness refresh. Overlapping certificates would still require a disjoint selected cover and duplicate-nullifier rejection. This could shorten an already prepared wallet's send path, but receiving-time proofs and uploads are amortized work, not a faster cold spend of arbitrary existing notes. A fair comparison must let PR #320 consolidate on receipt too. If certificates are instead prepared after Send, their full work belongs inside the timer, even when overlapped with uploads.
