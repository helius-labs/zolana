# Native Rust forester prover

The local backend generates Groth16 BN254 batch address-append proofs with the
existing pinned gnark key files. All witness execution, FFTs, point decoding,
MSMs, blinding, and proof verification run in Rust. No Go archive is linked.
The circuit and trusted setup remain unchanged.

The supported keys are `batch_address-append_40_10.key` and
`batch_address-append_40_4999.key`. Every file is hashed before its query offsets
or constraint system are used. The resulting proof must pass both the original
verifying key and the checked-in Solana verifier before it is returned.

## Memory and disk

The large key has a 2^28 FFT domain. One full scalar vector would occupy 8 GiB;
the implementation keeps the witness and A/B/C evaluations in scratch files.
The solver has fixed page caches totaling 1,728 MiB, MSMs decode fixed point
chunks, and FFTs use at most 128 MiB of buffers rather than domain-sized twiddle
tables.
Each local client executes its jobs sequentially to bound memory and disk.

The 4,999 key occupies 73,905,435,543 bytes. Allow approximately 32 GB of
additional scratch space while solving, plus 4 GiB of free reserve. Circuit
calldata streams directly from the key in original instruction order; only the
smaller instruction columns are spooled. Those columns are removed before FFT
processing, which needs three 8 GiB evaluation files.
Completed and failed proofs remove their scratch directory so a retry does not
accumulate another large temporary copy. The run reports its scratch directory
and checks the available space before executing.

The prover explicitly reads and writes bounded file blocks throughout.
A completed small proof does not establish the large proof's memory requirement;
measure the complete 4,999 run with the watchdog below.

## Measured 4,999-item proof

On October 24, 2026, the complete height-40, batch-4,999 proof ran on an Apple
M5 Pro with 18 worker threads and 48 GiB of physical RAM. The release binary at
commit `53164098243b256b967563ec02902862520c4f40` used the existing proving key
with SHA-256 `367fd7d2f534810ec684b7dbbadfd90dc65550d26989a2f2945d4719702001de`.

| Measurement | Result |
| --- | --- |
| Elapsed time | 3,956.22 seconds (65 min 56 sec) |
| Peak aggregate process-family RSS | 1,861,844,992 bytes (1.862 GB) |
| macOS peak memory footprint | 1,867,482,840 bytes (1.867 GB) |
| Memory limit | 10,000,000,000 bytes (10 GB) |

The proof passed the original verifying key and the checked-in Solana verifier;
a changed public input was rejected. Scratch files were removed after success.
This single run includes input construction, key authentication, witness
generation, proving, and verification using the fixture described below.
No competing builds or benchmarks ran during measurement.

## Standalone proof

Build once, then measure the binary separately from compilation:

```sh
cargo build --release -p zolana-forester-prover --bin forester-prove
python3 protocol-ops/forester-prover/tools/run-memory-limited.py \
  --limit-bytes 10000000000 --report /path/to/memory.json -- \
  /usr/bin/time -l target/release/forester-prove \
  --keys-dir /path/to/pinned-keys --batch-size 4999 --threads 18 \
  --scratch-dir /path/to/scratch --output /path/to/proof.json
```

The command inserts every value from 1 through the batch size into the initial
nullifier tree and proves the complete batch. It writes the roots, public input,
key digest, proof bytes and verification results to JSON. It also checks that a
changed public input is rejected. No Solana transaction is submitted.

The watchdog records peak resident memory and terminates the process group if
its sampled aggregate RSS reaches the limit. On macOS it also records the
kernel's child peak RSS; `/usr/bin/time -l` provides peak footprint in the log.
The limit is decimal 10 GB (10,000,000,000 bytes).

`ProverClient::local_with_scratch(keys, scratch)` exposes the same backend to
forester. `ProverClient::local(keys)` uses a directory under the system temporary
directory. The existing HTTP client remains available for remote proving.

## Validation

Unit tests cover key encodings, streamed integer decoding and witness semantics,
and disk-backed FFTs against polynomial identities and arkworks transforms.
The native witness solver has also been compared scalar-for-scalar against the
existing small-key gnark test oracle; that oracle is not part of the runtime.

```sh
cargo test -p zolana-forester-prover
FORESTER_TEST_KEYS_DIR=/path/to/pinned-keys cargo test \
  -p zolana-forester-prover pinned_40x10 -- --ignored
FORESTER_TEST_KEYS_DIR=/path/to/pinned-keys cargo test \
  -p zolana-forester-prover --test local_batch_proof -- --ignored
```
