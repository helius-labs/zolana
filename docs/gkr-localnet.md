# GKR payment integration and localnet comparison

The GKR payment now runs through the prover service, SPP, Photon and recipient decryption at both 144 and 512 inputs. It batches the existing Poseidon membership and nullifier nonmembership hashes in one private GKR computation inside Groth16. The note tree, nullifier tree, private paths and payment statement stay the same. The implementation reuses the existing payment constraints and commitment-aware verifier.

`direct-payment-gkr` selects one of two fixed circuit shapes on the server. The request cannot override the transcript or GKR configuration. The SDK carries the existing compressed Groth16 proof plus its BSB22 commitment and proof of knowledge in a spend buffer. SPP checks the selected shape, accepted roots, owner signature, payment statement and proof before updating the pending-nullifier table and output tree. Photon reconstructs the output records for wallet decryption.

The 512-input payment still uploads its nullifiers across several transactions. The final transaction verifies the proof and applies the spend atomically; uploads alone do not spend notes. Its measured final transactions use about 1.322M CU, below the 1.4M limit with limited headroom.

## Resident-key results

GKR is faster in this localnet comparison, but does not reach the 10× goal. At 512 inputs it reduces the median complete-payment latency by 54.3% versus PR #320 and total compute units by 70.9%. Loading keys is excluded from every number below.

| Inputs | Route | Median payment | Observed range | Proofs | Transactions | Median total CU |
| ---: | --- | ---: | ---: | ---: | ---: | ---: |
| 144 | PR #320 cache | 6.792 s | 6.755–7.162 s | 5 | 5 | 1,340,893 |
| 144 | Conventional direct | 5.785 s | 5.696–5.815 s | 9 | 3 | 1,147,365 |
| 144 | GKR | 4.662 s | 4.572–4.665 s | 1 | 2 | 567,449 |
| 512 | PR #320 cache | 21.846 s | 21.807–23.288 s | 16 | 15 | 4,581,152 |
| 512 | Conventional direct | 19.503 s | 19.352–19.512 s | 31 | 8 | 3,880,116 |
| 512 | GKR | 9.983 s | 9.967–9.988 s | 1 | 6 | 1,334,190 |

The GKR speedup is **1.46× / 2.19× versus PR #320** and **1.24× / 1.95× versus conventional direct**, at 144 / 512 inputs respectively. All 18 measured payments passed recipient decryption and full-balance assertions. Individual resident-key samples, summaries and the binary manifest are saved in [gkr-localnet-resident.json](../prover/server/benchmarks/gkr-localnet-resident.json). The original paired logs retain startup diagnostics; those cold rows are excluded from this report and the resident result file.

| Inputs | Route | Witness median | Proving median | Submit + confirm median |
| ---: | --- | ---: | ---: | ---: |
| 144 | PR #320 cache | 0.949 s | 3.619 s | 1.891 s |
| 144 | Conventional direct | 0.600 s | 3.563 s | 1.089 s |
| 144 | GKR | 0.629 s | 2.655 s | 0.764 s |
| 512 | PR #320 cache | 3.259 s | 12.269 s | 5.954 s |
| 512 | Conventional direct | 2.247 s | 13.293 s | 3.444 s |
| 512 | GKR | 2.211 s | 4.657 s | 2.603 s |

Stage medians are calculated independently and need not sum to the total median. The total also includes recipient indexing and decryption. At 512 inputs GKR cuts proving time by 2.63× versus the cache route, while witness construction, buffer uploads and confirmation still account for much of the payment. Subtracting proving from each GKR512 sample leaves a median 5.331 s. Holding those other costs fixed, even instantaneous proving would cap the speedup versus PR #320 at about 4.10×. Reaching 10× therefore also requires changing the witness and submission path. Overlapping uploads with proving and reducing witness round trips are separate, unmeasured follow-ups.

## Measurement method

The comparison uses one Apple M5 Pro with 18 logical CPU cores and 48 GiB RAM, local Surfpool and one shared Photon binary. Both prover processes use `GOMAXPROCS=18`, a 24 GiB Go memory limit and four synchronous proof permits. Both multi-proof clients request four proofs at a time. Rust test clients and Photon use dev builds with the workspace's crypto optimization overrides. Submission uses packed v1 transactions under the repository's local validator configuration. These are CPU measurements; no GPU prover, competing traffic or remote RPC latency is modeled.

Every route transfers the complete balance of 144 or 512 plain Ed25519-owned notes to one recipient. Selected notes alternate with other-owner decoys in the same tree. This is a noncontiguous wallet within a small tree prefix, not uniformly random 32-bit positions. The separate native benchmark in [gkr-scattered-spend.md](gkr-scattered-spend.md) covers randomly scattered positions.

Timing starts before witness construction and ends when the recipient decrypts the full balance. It includes every required proof, transaction submission, confirmation and recipient indexing. Deposits, protocol setup, key generation/downloads and later diagnostic assertions are excluded. No certificates are prepared before the timer. Setup uses identical eight-output deposits packed four instructions per transaction. Confirmation polling is 25 ms; indexer retries retain their 500 ms interval.

These harnesses collect all proofs before submitting packed transactions sequentially. They do not overlap proving with buffer uploads or stream completed merges onto the chain. The results compare these implementations at the stated configuration, rather than every possible submission schedule.

The performance comparison uses resident keys only, matching servers that load keys at startup and keep them in memory. Each pair starts a new prover and performs an excluded warmup spend. The measured spend then uses fresh validator state, owners, notes and nonces on that same prover. No witness or proof is reused. Three repetitions per route and input count give 18 measured payments, plus 18 excluded warmups retained in the raw logs. An audit of all 18 measured prover logs found no additional key loads or prover restarts. Key loading contributes nothing to the reported payment latency. Cases run sequentially without concurrent compiler or prover experiments; three samples per cell provide medians and ranges, not a production latency distribution.

PR #320 retains its registry and Squads merge authorization; direct and GKR use the owner's transaction signature. At 144 inputs the cache route uses four 36-input merges and a cached 4×3 final transfer. At 512 it uses fourteen 36-input merges, one 8-input merge, and a cached 36×2 transfer with 21 dummy slots. The added SDK padding follows the existing cached circuit and historical-root rules. Each route pays one real recipient, while physical dummy-output encodings differ.

The shared Photon is built from the PR #320 comparison worktree with direct-spend event support added. An older Photon rejected the cached circuit selector despite successful on-chain execution; that failed smoke is excluded. Regression tests cover its captured cached36×2 instruction and direct-spend source binding.

## Prover tuning

The batching experiment keeps membership and freshness hashes in one shared GKR pool. Splitting them into separate pools raises constraints from 1,696,484 to 2,657,255 at 144 inputs and from 3,345,785 to 4,334,237 at 512 inputs. Both split variants cross the next FFT-domain boundary. This is a circuit-size result; no split-pool latency claim is made. Both variants use the same payment constraints.

The separate resident-key service experiment also favors the `GOMAXPROCS=18` setting already used above. Each cell is the median of three freshly computed, verified proofs through the service's proof-request backend. Compilation, fixture construction, key loading and proof verification are outside the timer. This fixture uses scattered 32-bit note positions; it is a backend measurement, not a second localnet comparison.

| Inputs | GOMAXPROCS=4 | GOMAXPROCS=8 | GOMAXPROCS=18 |
| ---: | ---: | ---: | ---: |
| 144 | 6.597 s | 4.195 s | 2.687 s |
| 512 | 12.994 s | 7.905 s | 4.889 s |

For one payment, retain one active proof with `GOMAXPROCS=18`. Under load, four concurrent 144-input proofs raise observed backend throughput from 0.372 to 0.517 proofs/s, while request latency rises from 2.687 to 5.951 s. For 512 inputs, two concurrent proofs give the best observed throughput, 0.250 proofs/s versus 0.205 alone, with median request latency 6.616 s. Four reach only 0.244 proofs/s and 11.064 s latency. These are three waves per setting, with overlapping throughput ranges at 512; they suggest a capacity setting rather than establish a universal optimum. HTTP admission, queues and deduplication are outside this experiment. All 54 proofs verified. Detailed ranges and counts are in [gkr-service-results.json](../prover/server/benchmarks/gkr-service-results.json).

## Validation and reproduction

Real-proof rejection tests cover altered commitments, commitment proofs of knowledge, circuit shape, output commitments, duplicate or modified nullifiers, expired historical roots and replay. Each rejection checks state rollback. Restoring an already-consumed buffer after a successful spend still rejects the proof through the pending-nullifier check. Both saved GKR keys exactly match normalized R1CS digests of freshly compiled service circuits.

The [benchmark runner](../tools/bench-direct-spend.md) records binary hashes, per-payment prover logs, individual timing rows and summaries. All 11 artifact hashes still matched after the matrix. The PR #320 comparison source is saved locally on `codex/10x-settlement` at `aab26b696`; the GKR implementation and this report are on `codex/second-gkr`. The [service notes](../prover/server/benchmarks/gkr-service.md) record key generation and prover experiments. Keys are local development artifacts; the new shapes need production key generation and release integration before deployment.
