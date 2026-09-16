# Merge and direct-spend experiments

The best integrated result is GKR direct spend: **2.19× faster than PR #320 at 512 inputs, with 71% fewer total compute units**. The 14.02× result is a separate, conditional proving experiment. We have not demonstrated 10× end-to-end payment latency.

## What the measurements support

All payment comparisons below use resident proving keys. Loading keys, deposits and setup are excluded. Timing includes witness construction through recipient decryption of the complete balance. Each cell contains three CPU localnet payments; this is not a production latency distribution or a GPU benchmark.

| Inputs | PR #320 cache | Conventional direct | GKR direct | GKR speedup vs PR #320 |
| ---: | ---: | ---: | ---: | ---: |
| 144 | 6.792 s | 5.785 s | 4.662 s | 1.46× |
| 512 | 21.846 s | 19.503 s | 9.983 s | 2.19× |

At 512 inputs GKR uses one proof and six transactions, versus 16 proofs and 15 transactions for PR #320. Total CU falls from 4,581,152 to 1,334,190. The GKR final transaction consumes about 1.322M CU, leaving limited room below the current 1.4M limit. The circuit preserves the existing note and nullifier trees, private paths and payment checks. The complete comparison, authorization differences and submission schedule are documented in [the localnet report](docs/gkr-localnet.md).

The older **14.02× proving result** is 40.313 s → 2.875 s for 512 inputs, two outputs, resident keys and `GOMAXPROCS=4`, with three verified proofs per design. It requires one complete, aligned subtree of owned UTXOs and external historical nullifier admission. The clustered circuit and admission filter were separate prototypes; the measured time does not include an integrated on-chain admission path. Sequential nullifier-tree leaves alone do not establish this result. [Original experiment](https://github.com/helius-labs/zolana/blob/experiment/merge/10x-proving/docs/direct-spend-cold-proving.md).

## Combining the ideas

The latest compilation experiment reuses the compact payment statement and the GKR Merkle compressor. Every row below assumes external nullifier admission and has 512 inputs and two outputs.

| Note layout | Conventional constraints | GKR constraints |
| --- | ---: | ---: |
| Independent scattered positions | 4,522,594 | 1,754,023 |
| Complete groups of 16 | 873,506 | 1,433,348 |
| One complete group of 512 | 668,507 | 1,350,524 |

GKR helps the scattered case. Once clustering removes most membership hashes, the standard GKR transcript costs more constraints than it saves and doubles the FFT domain in the tested clustered shapes. These are compilation results, not proof-time measurements. The gains cannot be multiplied. [Reproduction patch, checks and raw results](docs/hybrid-cluster-gkr.md).

Use a common payment/admission protocol with separate fixed circuit variants: compact ordinary proofs for complete owned groups, and GKR for sufficiently large scattered sets. An explicit circuit selector can reveal the broad layout class; private positions still belong inside the proof. Mixed layouts need measured shapes of their own.

Historical nullifier admission is the main remaining protocol change. The existing pending-nullifier table guards recent spends only. Removing in-circuit nonmembership requires authoritative complete history: an exact spent set, or a monotone Bloom-negative check with an exact positive fallback. Every spending route must update that history and reject duplicates atomically. A new domain can start empty; legacy history needs authenticated migration. This integration is not complete.

## Where to spend the next effort

First integrate scattered GKR with authoritative historical admission, since it tests the shared gain without requiring favorable wallet layout. The compilation result reduces today's GKR512 circuit from 3,345,785 to 1,754,023 constraints and halves its FFT domain. Then add the compact clustered variant for eligible wallets.

Optimize the payment path alongside the prover: omit nullifier-tree witness fetches on the admission fast path, retrieve compact group witnesses, upload the known statement while proving, and reduce confirmation barriers. The current append-only buffer can accept the statement prefix before the proof; broadcasting its ordered writes concurrently does not guarantee arrival order. Apply equivalent scheduling improvements to the PR #320 comparator.

A 10× result against the measured PR #320 baseline requires at most **2.185 s** through recipient decryption. Current GKR512 leaves a median **5.331 s outside proving**. Holding those costs fixed, even instantaneous proving would reach only about 4.10×. Another circuit optimization alone cannot meet the target.

For future issuance, an atomic private bundle with one spend identifier per bundle could reduce both proof inputs and nullifier uploads. That requires new note and partial-spend semantics; it cannot regroup legacy notes for free. It is a research direction, not a measured result.

Keep the shared GKR hash pool and `GOMAXPROCS=18` for this machine. One active proof gives the lowest measured request latency. Under load, the best observed backend throughput used four concurrent 144-input proofs and two concurrent 512-input proofs. These settings were tested separately from HTTP admission and queues; [all 54 backend proofs verified](prover/server/benchmarks/gkr-service.md).

## Branch map

The two primary branches are `experiment/merge/second-gkr` and `experiment/merge/10x-settlement`. The remaining branches preserve earlier experiments; their exploratory timings are superseded by the aligned matrix above.

| Branch suffix under `experiment/merge/` | Contents |
| --- | --- |
| [second-gkr](https://github.com/helius-labs/zolana/tree/experiment/merge/second-gkr) | Integrated GKR payments, final localnet matrix, tuning and this assessment |
| [10x-settlement](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-settlement) | PR #320 comparator used in the final matrix |
| [10x-proving](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-proving) | Clustered proofs and the 14.02× native proving experiment |
| [10x-nullifier-filter](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-nullifier-filter) | Standalone historical-spentness filter prototype |
| [second-private-dag](https://github.com/helius-labs/zolana/tree/experiment/merge/second-private-dag) | Private shared Merkle-path experiment |
| [direct-spend](https://github.com/helius-labs/zolana/tree/experiment/merge/direct-spend) | Initial direct-spend implementation |
| [pr320-e2e-bench](https://github.com/helius-labs/zolana/tree/experiment/merge/pr320-e2e-bench) | Initial PR #320 benchmark harness |
| [10x-direct](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-direct) | Earlier direct-spend localnet measurements |
| [10x-cache](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-cache) | Earlier completed cached-transfer benchmark |
| [10x-settlement-direct](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-settlement-direct) | Earlier direct settlement and wire comparison |

The integrated branch passed 18 measured localnet payments and real-proof rejection/replay checks. Development proving keys are local artifacts and are not published here. Production key generation, release integration and protocol review remain before deployment. The archived branches are research snapshots, not ten independently release-tested implementations.
