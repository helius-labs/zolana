# Experimental GKR service

`direct-payment-gkr` accepts 144 or 512 input slots and exactly two output slots. It uses the existing payment statement, original Poseidon Merkle roots, private indices, original nullifier non-inclusion checks, and standard `POSEIDON2` GKR transcript. The circuit kind selects GKR on the server. Witness JSON cannot select `GKR` or `Transcript`.

The proof uses the existing `common.Proof` format, including one BSB22 commitment and its proof of knowledge. No separate proof codec was added. The service supports synchronous and queued dispatch, existing lazy key loading, and the existing direct-spend setup command.

Local development keys were generated with Go 1.27.1, gnark 0.16.3, BN254 Groth16, `GOMAXPROCS=4`, and `GOMEMLIMIT=16GiB`:

| Circuit | Constraints | Key bytes | Compile + setup + write |
| --- | ---: | ---: | ---: |
| GKR 144 × 2 | 1,696,484 | 513,910,041 | 108.80 s |
| GKR 512 × 2 | 3,345,785 | 939,605,925 | 209.95 s |
| PR #320 cached transfer 36 × 2 | 812,159 | 251,172,476 | 58.67 s |

These are operational setup timings, not controlled proving comparisons. The 144 setup child succeeded; `/usr/bin/time -l` returned an error afterward because sandboxed `sysctl kern.clockrate` was unavailable. Both generated files were present and the raw verification key exported successfully.

The two GKR keys are under this worktree's `prover/server/proving-keys`. Baseline certificate36, freshness36, and balance16 keys are individual symlinks to the existing direct-spend key directory. The cache key was generated with the PR #320 service in `zolana-10x-settlement`, whose key directory links to `zolana-10x-cache`. No experimental keys were added to the download manifest.

The generated Rust modules are `direct_payment_gkr_144_2.rs` and `direct_payment_gkr_512_2.rs` in this worktree, plus `transfer_confidential_cached_36_2.rs` in the cache comparison worktree. The setup command can export its raw verification key without loading the large proving key again:

```sh
./light-prover setup-direct-spend --circuit direct-payment-gkr \
  --n-inputs 144 --n-outputs 2 \
  --output proving-keys/direct-payment-gkr_144_2.key \
  --output-vkey proving-keys/direct-payment-gkr_144_2.vk.bin
```

Focused tests cover shape selection, both request sizes, rejected configuration overrides, malformed witnesses, queue routing, request metadata, key filenames, and real committed-proof JSON round-trip verification. Removing either commitment field fails decoding.

The opt-in `TestGKRServiceProving` benchmark compiles the current factory circuit and checks its normalized R1CS digest against a saved key loaded through the real lazy key manager. It times request decoding, witness conversion, all solver/GKR/Groth16 work, and proof JSON serialization through `directprover.ProveRequest`. It then decodes and verifies every proof. Fixture construction, key loading, and verification are outside the proving timer and are separate from localnet timings. Concurrent runs repeat full payments with a shared resident key; they do not combine smaller payments or rely on cached proof results.

```sh
GOMAXPROCS=4 GOMEMLIMIT=24GiB \
GKR_SERVICE_KEYS="$PWD/proving-keys" GKR_SERVICE_INPUTS=512 \
GKR_SERVICE_THREADS=4,8,18 GKR_SERVICE_CONCURRENCY=1 GKR_SERVICE_SAMPLES=3 \
go test ./circuits/direct_spend -run '^TestGKRServiceProving$' -count=1 -timeout 20m -v
```

`GKR_SERVICE_THREADS` sets `GOMAXPROCS`, the maximum parallel Go execution slots, not the number of OS threads. `GKR_SERVICE_CONCURRENCY=1,2,4` measures concurrent full-payment proof requests. `GKR_POOL_COMPILE=1` with `TestGKRPoolPartition` compares one shared GKR hash pool against separate certificate and freshness pools for the same payment statement; this is a compilation experiment, not a latency result.

## Pool partition result

| Inputs | Shared constraints | Split constraints | Shared FFT domain | Split FFT domain |
| --- | ---: | ---: | ---: | ---: |
| 144 | 1,696,484 | 2,657,255 | 2²¹ | 2²² |
| 512 | 3,345,785 | 4,334,237 | 2²² | 2²³ |

Separate certificate and freshness pools increase constraints by 56.6% and 29.5%, respectively, and cross the next FFT-domain boundary for both shapes. The service retains one shared pool; no split-pool keyset or latency claim was produced. Both variants reuse the same private payment constraint helper, including all statement bindings. Raw compiler results are in `gkr-pool-partition.log`.

Both saved keys matched freshly compiled service circuits after extracting the shared constraint helper. The normalized R1CS digests (debug symbols removed) are:

- 144: `d923f81f717865d6bde3a871884c8725ffa1694f427630330f74343fbec0a05c`
- 512: `90211240d2c37a319fb5a4a9108bff07a05694c2c61c85e36840fc25a6a803af`

The digest checks ran in validation-only mode and did not produce latency samples. Logs: `gkr-key-compatibility-144.log`, `gkr-key-compatibility-512.log`.

## Resident-key backend measurements

Key loading is excluded from every result below. Before timing, the key is loaded and retained, its normalized R1CS digest is checked against the current factory circuit, and the fixture is built. Verification is also outside timing. Timed work includes JSON witness decoding, witness conversion, all GKR/solver/Groth16 work, and proof JSON serialization.

The backend fixture contains fully active notes at unique random 32-bit Merkle positions, 64 historical nullifiers, and two outputs. It differs from the interleaved localnet fixture. The benchmark calls the real prover core but bypasses HTTP, queue admission, and proof deduplication. It measures proof latency and throughput, not ledger transaction throughput or payment completion time.

All 54 proofs verified. `GOMEMLIMIT=24GiB`; `GOMAXPROCS` denotes parallel Go execution, not OS thread count. Each row contains three waves. Parentheses show minimum–maximum, not confidence intervals. Request latency aggregates every request in those waves; throughput is the median of proofs divided by elapsed time for each wave.

| Inputs | GOMAXPROCS | Concurrent requests | Verified proofs | Request latency, s | Throughput, proofs/s |
| --- | ---: | ---: | ---: | ---: | ---: |
| 144 | 4 | 1 | 3 | 6.597 (6.578–6.606) | 0.152 (0.151–0.152) |
| 144 | 8 | 1 | 3 | 4.195 (4.189–4.426) | 0.238 (0.226–0.239) |
| 144 | 18 | 1 | 3 | 2.687 (2.653–2.693) | 0.372 (0.371–0.377) |
| 144 | 18 | 2 | 6 | 3.512 (2.777–4.351) | 0.462 (0.460–0.473) |
| 144 | 18 | 4 | 12 | 5.951 (3.045–7.743) | 0.517 (0.517–0.517) |
| 512 | 4 | 1 | 3 | 12.994 (12.925–13.055) | 0.077 (0.077–0.077) |
| 512 | 8 | 1 | 3 | 7.905 (7.899–7.960) | 0.127 (0.126–0.127) |
| 512 | 18 | 1 | 3 | 4.889 (4.765–4.974) | 0.205 (0.201–0.210) |
| 512 | 18 | 2 | 6 | 6.616 (5.337–8.008) | 0.250 (0.250–0.257) |
| 512 | 18 | 4 | 12 | 11.064 (5.736–16.870) | 0.244 (0.237–0.260) |

`GOMAXPROCS=18` was the fastest tested setting for both shapes: 2.45× faster than four slots for 144 inputs and 2.66× for 512. The end-to-end localnet matrix already used 18, so this is not an additional gain over that matrix.

For 144 inputs, concurrency four raised backend throughput by 39% over concurrency one, while request latency rose from 2.687 s to 5.951 s. For 512 inputs, concurrency two raised throughput by 22% and request latency from 4.889 s to 6.616 s. Concurrency four offered no consistent throughput advantage over two for 512 inputs and increased median latency to 11.064 s. One active request gives the lowest measured request latency; the throughput tradeoff depends on shape. These settings do not establish a 10× end-to-end speedup.

The largest recorded post-wave Go `runtime.Sys` was 9.80 GiB. This is runtime allocation data, not measured process RSS or a sampled peak. The JSON artifact retains post-wave memory data, request/wave timing ranges, counts, and source log paths.

Artifacts: `gkr-service-results.json`, `gkr-service-{144,512}-threads.log`, `gkr-service-{144,512}-concurrency.log`. Final focused common/factory/queue unit tests passed: eight top-level tests, including malformed-witness subtests, with logs in `gkr-service-unit-tests.log`. Only owned Go files were formatted. No raw-key loading experiment was run or retained.
