# GKR for scattered legacy notes

Spending hundreds of notes repeats the same Poseidon hash thousands of times along their Merkle paths. This experiment collects the binary hashes from both the note tree and the nullifier tree into one GKR computation. The outer Groth16 circuit verifies that computation and binds its results to the payment, avoiding a separate full Poseidon constraint expansion for every hash. The measured complete 512-input proof takes 12.43 seconds instead of 40.66 seconds on the same four CPU threads: 3.27× faster.

The compressor computes the exact existing iden3 Poseidon permutation. During partial rounds, it derives the two linear state lanes from a three-step scalar recurrence, reducing the work GKR must prove. Gnark commits to the statement and each input/output and uses its standard Poseidon2 transcript. The payment reuses the certificate, freshness, and balance constraints rather than maintaining a second payment implementation.

The existing 32-level note membership, 40-level indexed-nullifier nonmembership, ownership, value conservation, and output construction remain enforced. Notes can be scattered anywhere in the tree; the design needs neither clustered notes nor certificates prepared before the spend. The 3.27× result measures proving with resident keys, not end-to-end settlement or a comparison against parallel PR #320 merges.

All positions, paths, and intermediate hashes remain private. SPP already has a commitment-aware verifier for P256 proofs, and this circuit matches its supported shape: one BSB22 commitment, no committed public inputs, and three VK IC entries. The full 512-input circuit commits 153,089 private/internal values. The subsequent [localnet integration](gkr-localnet.md) adds the circuit selector, key/export metadata and direct-spend support for the existing 64-byte BSB22 pair, reusing that verifier. The measurements below describe the original native experiment.

Settlement must still validate accepted roots, reject duplicate input nullifiers, and prevent concurrent spends through the normal on-chain checks. Keeping nullifier nonmembership inside the circuit does not replace those checks.

## Constraint measurements

| Statement | Conventional | GKR | Ratio |
|---|---:|---:|---:|
| 512 private 32-level paths to one root | 3,982,336 | 1,213,765 | 3.28× |
| Complete 512-input, 2-output payment | 10,728,434 | 3,345,785 | 3.21× |

Gnark's constraint profiler attributes 1,068,942 of the membership circuit's 1,213,765 constraints to Poseidon2 transcript hashing: 88.07%. The remainder is 144,823. These are constraint measurements, not speed claims.

The installed gnark/gnark-crypto versions expose matching BN254 Poseidon2 permutations at widths 4, 8, 12, and 16 with published constants. They do not expose matching field-sponge transcript wrappers; the registered default is the width-2 Merkle–Damgård hash. A separate experimental adapter uses those permutations with two capacity elements, explicit domains, delimiter/length finalization, non-destructive Sum, and canonical native field framing. It is excluded from the proof timings below.

| Experimental transcript | 512-path membership constraints |
|---|---:|
| Width 4, rate 2 | 1,306,423 |
| Width 8, rate 6 | 1,021,105 |
| Width 12, rate 10 | 923,746 |
| Width 16, rate 14 | 977,878 |

Width 12 is best among these configurations. It reduces the membership FFT domain from 2²¹ to 2²⁰. In the full 512-input payment, however, it reduces 3,345,785 constraints to 3,009,893 and leaves the FFT domain at 2²². We did not generate another large key or claim a runtime improvement from that 10% count reduction. The new transcript construction still requires cryptographic review before deployment; parity and tamper tests alone do not establish its security.

## Proof measurements

Machine: Apple M5 Pro, 18 CPU cores, 48 GiB RAM. Go 1.27.1, gnark 0.16.3, gnark-crypto 0.21.0, BN254 Groth16, GOMAXPROCS=4, GOMEMLIMIT=16GiB. Prove timings include constraint solving, all GKR work, and the outer Groth16 prover; verification is performed after each sample. Key setup/load and witness construction are reported separately.

| Complete 512-input, 2-output payment | Trial 1 | Trial 2 | Trial 3 | Median |
|---|---:|---:|---:|---:|
| Conventional | 41.066 s | 40.587 s | 40.662 s | 40.662 s |
| GKR, standard transcript | 12.576 s | 12.363 s | 12.433 s | 12.433 s |

The measured improvement is **3.2704×**, with all six proofs verified. Sampled Go heap was about 14.14 GB conventionally and 4.50–4.96 GB with GKR. No swap-in or swap-out occurred; macOS memory compression was active. This is a resident-key proving comparison, not a localnet latency result or a demonstrated 10× improvement.

Fixture construction took 1.956 s. Conventional compilation took 22.597 s; read-only key loading and mathematical R1CS digest validation took 96.296 s. GKR compilation took 6.083 s and its transient key setup took 184.332 s. Setup and load are excluded from the proof table. The normalized baseline R1CS digest matched `f86cf9f8f251517c15131e3d39fb6c91a1da19b9c95eaa724b145c13847e6fc8`.

The first straightforward GKR implementation was measured on 32 scattered paths: conventional median 1,142.147 ms versus GKR 5,132.836 ms. All six proofs verified. That implementation had 1,054,476 outer constraints versus 248,896 conventionally; it motivated the scalar-recurrence implementation measured above. This small-batch result must not be extrapolated to the optimized full payment.

The complete payment fixture has 512 real notes at deterministic random 32-bit positions in one valid state tree and 64 historical nullifiers in a valid indexed tree. Both proving modes use the identical witness and statement. The conventional proving key is loaded read-only from the existing direct-payment_512_2.key; its normalized mathematical R1CS digest is checked against a fresh compilation. Only the GKR key is generated, in memory.

## Validation and reproduction

The compressor matches 24 native legacy hashes, including zero, p−1, and random full-field inputs. Negative tests reject a changed hash output, root, leaf, index, or sibling. Full-payment tests cover active and padded inputs and reject inflation, a corrupted note path, and a nonmembership interval whose predecessor equals the spent nullifier. The native Groth16 membership benchmark also rejects proofs against an altered public root. Wide-transcript tests cover all four widths, native/circuit parity at block boundaries, repeated/intermediate Sum, zero extension, empty writes, canonical-field rejection, domain separation, and wrong digests.

Run from prover/server with the repository's configured Go toolchain:

```sh
GOMAXPROCS=4 go test ./circuits/gadget ./circuits/direct_spend -run '^(TestLegacyGKRHashes|TestScatteredMembershipGKR|TestScatteredGKRPayment)$' -count=1 -v

go test ./circuits/transcript -count=1

GOMAXPROCS=4 GOMEMLIMIT=16GiB GKR_COMPILE_ONLY=1 GKR_INPUTS=512 GKR_PAYMENT_INPUTS=512 go test -p 1 ./circuits/gadget ./circuits/direct_spend -run '^(TestScatteredMembershipProving|TestScatteredGKRPaymentProving)$/gkr=true$' -count=1 -v

GOMAXPROCS=4 GOMEMLIMIT=16GiB GKR_PAYMENT_INPUTS=512 go test ./circuits/direct_spend -run '^TestScatteredGKRPaymentProving$' -timeout 20m -count=1 -v
```

The last command generates transient keys for both modes. To reproduce the measured run's baseline key reuse, also set `GKR_BASELINE_KEY` to an existing `direct-payment_512_2.key`; the benchmark validates its shape and mathematical constraint digest before use. No proving keys are included in this commit.

Raw measurement logs are in [prover/server/benchmarks](../prover/server/benchmarks). To regenerate the local constraint profile, set `GKR_CONSTRAINT_PROFILE` to an output path and run `go test ./circuits/gadget -run '^TestGKRTranscriptConstraints$' -count=1`. Service integration and localnet measurements are documented separately in [gkr-localnet.md](gkr-localnet.md).
