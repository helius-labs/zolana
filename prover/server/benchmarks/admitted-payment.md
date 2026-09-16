# Admitted payment prover

`direct-payment-admitted` accepts 144 or 512 input slots and two outputs. It keeps private 32-bit note positions, legacy Poseidon membership, ownership, amount ranges, nullifier derivation, value conservation, and output binding. The service selects standard `POSEIDON2` GKR; requests cannot override the circuit configuration.

The public scalar is `HashChain4([0x44535032, ...Certificate.fields, ...Balance.fields])`, containing 14 fields. The certificate ID, value commitment, and asset bind to the single balance value. Historical nonmembership is omitted. The program must atomically enforce complete nullifier history and reject duplicates within the payment. The circuit alone does not establish freshness.

| Inputs | Constraints | FFT domain | Development key bytes | Setup + write |
| --- | ---: | ---: | ---: | ---: |
| 144 | 1,232,023 | 2²¹ | 428,121,658 | 36.250 s |
| 512 | 1,754,522 | 2²¹ | 574,137,510 | 43.229 s |

These setup durations are operational timings. Keys were generated independently with BN254 Groth16, Go 1.27.1, `GOMAXPROCS=18`, and `GOMEMLIMIT=24GiB`. Each raw verification key is 1,040 bytes and uses one private BSB22 commitment. Files remain local in `proving-keys`; no download manifest was changed.

The resident-key backend benchmark includes request decoding, witness conversion, solver/GKR/Groth16 work, and proof JSON serialization. Keys, fixture construction, digest compatibility checks, and verification are outside the timer. The fixture uses fully active notes at random private 32-bit positions. HTTP queueing and ledger transactions are not measured.

| Inputs | Verified samples | Median request | Range |
| --- | ---: | ---: | ---: |
| 144 | 3 | 2.202502 s | 2.184033–2.211825 s |
| 512 | 3 | 2.915759 s | 2.891182–2.942909 s |

`GOMAXPROCS=18` limits parallel Go execution, not OS thread count. Requests ran sequentially. Both factory circuit digests matched the resident keys. The 512 proof alone exceeds the 2.185-second whole-payment target; these results do not establish a 10× payment speedup.

The existing benchmark accepts `GKR_SERVICE_CIRCUIT=direct-payment-admitted`. All other options and timing boundaries remain shared with the GKR baseline. Logs and structured results are in `admitted-payment-{validation,setup-144,setup-512,proving-144,proving-512}.log` and `admitted-payment-results.json`.

## Moving GKR verification on-chain

The current gnark GKR proof cannot be published without changing the privacy protocol. Its native verifier takes the full input/output wire assignments and directly evaluates their multilinear extensions (`gnark/internal/gkr/bn254/gkr.go`, `Verify` and `verifyFinalEval`). Its sumcheck polynomials and final evaluations have no zero-knowledge masking layer. Groth16 currently hides this transcript and the assignments.

A separate verifier would need a hiding polynomial commitment, authenticated multilinear openings, and zero-knowledge sumcheck. The existing BSB22 commitment only binds inputs to the initial Fiat–Shamir challenge; it has no multilinear opening API. Replacing the in-circuit transcript with unconstrained public challenges would be unsound. No such replacement is implemented here.

The compiled native GKR transcript contains 5,343 field elements for 144 inputs (170,976 bytes), or 5,738 for 512 (183,616 bytes), before any additional zero-knowledge/opening protocol. This also creates a substantial transaction-upload cost if moved on-chain.

## Diagnostic profile and prefix screen

One separately profiled 512-input request verified in 2.804 seconds. The solver, including GKR, took 0.962 seconds; subsequent Groth16 work took 1.820 seconds. This instrumented sample is excluded from the three-sample latency table. In the CPU profile, base-field multiplication accounts for 34.7% and subtraction for 22.3%; G1/G2 affine-batch MSM paths account for roughly 70% cumulatively. Elliptic-curve work dominates the measured backend CPU cost. Raw files: `admitted-payment-profile-512.log` and `admitted-payment-profile-512-top.txt`.

The test-only prefix variant authenticates one upper path with canonical empty-subtree siblings and constrains each private note index to `H` bits. The accepted full 32-level root therefore certifies that no leaves exist outside the first `2^H` positions. This supports arbitrary wallet positions within a publicly bounded tree occupancy. It does not cover every possible 32-bit position. Historical roots remain usable without consulting the current tree size. Certificate and balance constraints are shared with production; the service still uses full 32-bit paths and the standard transcript.

| H | Standard transcript constraints | Experimental width-12 constraints |
| --- | ---: | ---: |
| 10 | 1,616,250 | 1,344,807 |
| 16 | 1,721,755 | 1,431,736 |
| 20 | 1,729,947 | 1,439,928 |
| 32 | 1,754,523 | 1,464,504 |

Every row still needs FFT domain 2²¹. The H=32 wrapper adds one equality to the production circuit. These counts supersede the initial private-upper-sibling screen in `admitted-payment-prefix-validation.log`. No prefix or wide-transcript keys were generated.

The alternative test-only Merkle DAG computes each shared parent hash once and authenticates private parent references through lookup tables. A second lookup table propagates actual leaf indices, binding each private note position as well as its hash. Upper siblings are fixed to canonical empty roots, giving the same occupied-prefix guarantee. This variant uses ordinary Poseidon constraints rather than GKR.

| 512-input DAG | Constraints | FFT domain | Private committed variables |
| --- | ---: | ---: | ---: |
| H=10 | 835,655 | 2²⁰ | 10,939 |
| H=16 | 1,614,449 | 2²¹ | 38,533 |

Both DAG shapes use one private BSB22 commitment. Positive tests cover scattered positions and padded inputs. Negative tests reject changed roots, nodes, parent and leaf references, private positions, and index overflow. Both prefix and DAG variants reject an otherwise valid root with an unrelated nonzero leaf outside the advertised prefix. Existing admitted ownership, range, conservation, output, and domain negatives also pass.

H=10 crosses one FFT-size threshold and is a candidate for a later proof benchmark. It applies only when the accepted root has no leaves beyond position 1,023. Constraint counts are not latency measurements: no DAG keys were generated and no integrated payment uses this prototype. Raw log: `admitted-occupancy-dag-validation.log`.

Both saved production keys still match the current factory R1CS digests after shared-helper extraction. Actual key-load compatibility checks are in `admitted-payment-key-compatibility.log`; focused factory, strict decoder, shape, key-path, and queue-routing checks are in `admitted-service-validation.log`. Existing ordinary/GKR payment positives and negatives also pass after the helper refactor (`admitted-shared-gadget-regression.log`). Loading remains excluded from payment performance measurements.

## Rejected segmented GKR

Splitting each Poseidon permutation into shorter state transitions passed native-hash parity and full-payment/path-tamper checks. However, expanded GKR inputs and constant round metadata outweighed the reduced transcript depth. Full 512-input payment counts were 9,260,498 constraints for 16-round segments, 8,849,126 for 24, and 8,706,342 for 32. All required FFT domain 2²⁴.

No keys were generated. The rejected constructor and tests were removed from active source and retained as `admitted-segment-rejected.patch`, which applies to this worktree. Logs: `admitted-segment-parity.log`, `admitted-segment-counts.log`.

## MSM task-budget screen

A separate temporary gnark build changed only the task budget supplied to G1/G2 MSMs. It used the same resident 512-input key and matched the factory R1CS digest. Task budgets 9, 18, 36, and 72 took 3.268, 3.088, 3.196, and 3.217 seconds respectively; each setting has one verified sample. The default budget remained fastest in this screen, so no production patch or repeated measurements followed.

These task counts are internal MSM scheduling parameters, separate from `GOMAXPROCS=18`. Go rejects overlays under its module cache, so the experiment used an isolated module copy and temporary `-modfile` under ignored `target/admitted-bench/msm`. The shared module cache, production dependency files, and prover binary were not changed. The benchmark's `GKR_SERVICE_MSM_TASKS` option requires that temporary patched backend; it is not a production tuning setting. Raw log: `admitted-msm-screen.log`.
