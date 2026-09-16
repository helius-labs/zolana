# Merge and direct-spend experiments

The latest integrated experiment completes a 512-note payment in **6.586 s versus 17.033 s for an optimized PR #320 comparator: 2.59× faster, with 71.9% fewer total compute units**. This is one measured resident-key CPU localnet payment per route, so the result is preliminary. We have not demonstrated 10× end-to-end latency. The earlier 14.02× result remains a separate, conditional proving experiment.

## Latest admission experiment

The new circuit retains private UTXO membership, ownership, nullifier derivation, ranges and value conservation. It removes the nullifier-tree proof. SPP instead requires a negative check against complete historical nullifier coverage and the existing pending table. Ordinary exact-proof spending records into the same history and remains the fallback for filter positives. The known statement uploads while proving runs.

The comparator also improves: it schedules the final transfer proof first, keeps proof workers busy and submits completed merges while other proofs run. Comparing against this faster comparator matters; the old 21.846 s baseline is not the denominator for the new claim.

| 512 inputs | Admission | Optimized PR #320 |
| --- | ---: | ---: |
| Complete payment | 6.586 s | 17.033 s |
| Witness construction | 1.836 s | 3.195 s |
| Proving | 3.011 s | 12.255 s |
| Statement prefix upload, overlapping proving | 3.554 s | — |
| Proofs | 1 | 16 |
| Transactions | 7 | 15 |
| Total CU | 1,287,625 | 4,581,518 |

Both timers end after the recipient decrypts the full balance. Keys stay resident after an excluded warmup, and no spend-specific proof or witness is prepared before timing. Both use the same CLI/Photon artifacts, dev-profile clients, 18 Go CPUs, four proof permits, 25 ms confirmation polling and 500 ms indexer polling. Cases ran sequentially without other proof or build workloads. Selected notes alternate with other-owner notes in a small occupied tree prefix; this is not a mature, randomly populated 32-bit tree or a GPU/production-network benchmark. PR #320 retains its Squads/registry authorization; admission uses the owner's transaction signature. These remain different authorization paths.

The admission final transaction used 1,275,280 CU, leaving about 125k CU below the configured 1.4M limit. Protocol allocation and funding are excluded from online payment timing: the measured admission fixture reported 427.269 s of setup with sequential growth of its 4 MiB filter. A subsequent setup-pipeline change is not represented in this timing row. Filter rent is about 29.19 SOL. This is shared infrastructure, not a free first-use optimization.

The published source also contains a subsequent mixed-tree account-capacity fix and additional comparator assertions after the payment timer. The saved manifest identifies the artifacts used for the table; later correctness checks do not replace that measurement.

A final matched 144-input smoke passed on this source, including the pipelined setup, recipient decryption, cache contents/frozen state and all cache-route nullifier PDAs. Its single resident rows were 3.757 s for admission and 6.031 s for cached transfer. This validates the final changes; it is not a repeated performance matrix. [Smoke artifacts](prover/server/benchmarks/admitted-localnet-smoke.json).

The filter is currently enabled only on compact trees that have never processed a spend; existing deposits qualify. It cannot safely start empty on an already-spent tree. Historical migration is designed but unimplemented. A fixed-size filter also loses its fast-negative path as it fills. Its exact fallback and irreversible retirement preserve correctness, but mature-history lifecycle and all-route integration coverage remain release gates. Development keys and unaudited protocol changes make this an experiment, not a deployment recommendation.

[Raw timing rows and artifact manifest](prover/server/benchmarks/admitted-localnet-512.json), [architecture](docs/admitted-payments.md), [coverage audit](notes/admission-filter-audit.md), and [migration design](notes/admission-history-migration.md).

## Assessment

This architecture improves the measured online path over the original cache proposal and reduces proofs and chain work substantially. It also adds a new circuit and a protocol-wide historical-spentness invariant. Keep the original exact proof path available while those changes are validated.

Reaching 10× against the optimized comparator would require about **1.703 s** through recipient decryption. The current witness stage alone takes 1.836 s; the overlapping upload stage takes 3.554 s and proving takes 3.011 s. Further prover tuning by itself cannot meet that target. The next useful work is to reduce client witness construction, remove ordered upload confirmation barriers with a properly authenticated chunk protocol, and measure compact membership circuits for eligible layouts. None of those prospective gains is included above.

For new issuance, private note bundles could reduce both Merkle work and the number of uploaded nullifiers. They change note and partial-spend semantics and cannot regroup existing balances without paying for consolidation. No general 10× architecture has yet been demonstrated.

## Earlier aligned measurements

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

The admission experiment above integrates the monotone Bloom-negative approach with exact fallback for previously unspent domains. The existing pending-nullifier table guards recent spends only; it cannot replace complete history. Every spending route must update that history and reject duplicates atomically. Legacy history still needs authenticated migration.

## Circuit and service evidence

The integrated admitted circuit now has 1,754,522 constraints versus 3,345,785 for the earlier GKR512 circuit, halving its FFT domain. Three verified resident backend samples give a 2.916 s median. Compact clustered variants remain a separate follow-up; the compilation table above predates the final admitted statement binding.

Keep the shared GKR hash pool and `GOMAXPROCS=18` for this machine. One active proof gives the lowest measured request latency. Under load, the best observed backend throughput used four concurrent 144-input proofs and two concurrent 512-input proofs. These settings were tested separately from HTTP admission and queues; [all 54 backend proofs verified](prover/server/benchmarks/gkr-service.md).

## Branch map

The current pair is `experiment/merge/10x-admission` and `experiment/merge/10x-cache-scheduling`. The previous three-sample matrix remains on `experiment/merge/second-gkr` and `experiment/merge/10x-settlement`. Other branches preserve earlier experiments.

| Branch suffix under `experiment/merge/` | Contents |
| --- | --- |
| [10x-admission](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-admission) | Historical admission, staged uploads, current preliminary result and this assessment |
| [10x-cache-scheduling](https://github.com/helius-labs/zolana/tree/experiment/merge/10x-cache-scheduling) | PR #320 comparator with work-conserving proof scheduling and streamed merges |
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

The earlier GKR branch passed 18 measured localnet payments and real-proof rejection/replay checks. Current admission validation is recorded in the linked audit and architecture notes. Development proving keys are local artifacts and are not published here. Production key generation, release integration and protocol review remain before deployment. The archived branches are research snapshots, not independently release-tested implementations.
