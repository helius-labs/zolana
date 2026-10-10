# Batch settlement through a batch account: results

Date: 2026-10-09. Branch `jorrit/spp-output-buffer-scaling` (cut from `main` at eb627964f), worktree
t3code-80fd8010. Nothing committed or pushed. No proving keys were rotated or uploaded.
Machine: Apple M5 Pro, 18 cores, 48 GB RAM. Prover on port 3701 (`ZOLANA_PORT_OFFSET=700`).

Every number is tagged **[m]** (measured) or **[e]** (estimated). CU figures come from the SPP
bench harness: litesvm builds the state, and mollusk replays the instruction against the profiling
`.so`. Real Groth16 proofs throughout. The 1x128, 1x150 and 16x142 keys are local single-party
setups (`light-prover setup-transfer`). The 49x2 key is the published one from the lockfile.

## Summary

- **Maximum outputs per settlement: 150 with 1 input, 142 with 16 inputs [m].** The binding
  limit is the 10,240-byte CPI instruction-data cap. 1x150 sends 10,231 bytes and settles.
  1x151 fails in the batch program's CPI with
  `Invoked an instruction with data that is too large (10297 > 10240)` [m]. 16x142 sends
  10,198 bytes and settles. 16x143 fails with `(10264 > 10240)` [m].
- Nothing else is close at the maximum:
  - CU: 677,946 for 1x150 and 695,779 for 16x142, both under half of 1.4M [m].
  - Output count field: u8, so 255.
  - Stack: no frame overflow after the heap moves.
  - Settlement transaction: 687 and 1,677 bytes, with 7 and 22 addresses [m].
  - Heap: the wide shapes need 48 KiB (1x150) and 46 KiB (16x142), above the 32 KiB default
    [m]. This is a v1 header request, not a limit. A 1x150 settlement in LiteSVM fails at
    47 KiB and succeeds at 48 KiB [m].
- The CPI data formula is `331 + 33*(inputs - 1) + 66*outputs` bytes [m] (it matches all 7 sizes
  measured). That gives at most `floor((10240 - 298 - 33*inputs) / 66)` outputs.
- Per-output CU is about 3.1k plus a quadratic term [m-fit]. The plan estimated 2.5k. 1x150
  costs 661k in SPP plus about 17k in the batch program [m], against the plan's estimate of
  about 510k.
- Circuits are cheap next to 49x2:
  - 1x150: 416,714 constraints, 120 MB key, 0.68 s prove [m].
  - 16x142: 748,178 constraints, 224 MB key, 1.06 s prove [m].
  - 49x2: 1,121,100 constraints, 362 MB key, 2.41 s prove [m].
- Verdict: one settlement transaction with one proof can pay 150 outputs (1 input) or
  142 outputs (16 inputs). Filling the batch takes 3 write transactions of 60 records each
  [m], plus the init transaction.

## Results table

All rows use distinct owners: one random Solana owner per output, zero-amount real outputs, dummy
inputs, an inline owner tag and no ciphertext. "SPP" is the profiled `process_transact_ix` inside
the settle CPI.

### CU per function, batch settle path [m]

| shape | tree append (`apply_output_tree`) | public input hash | owner hashes (`fill_output_owner_pk_hashes`) | inputs (`apply_input_trees`, incl. nullifier PDAs) | verify (`verify_groth16`) | SPP net (parse, ext. data hash, event CPI) | SPP total | batch program + CPI | settle total |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1x16 | 38,361 | 33,074 | 16,316 | 3,127 | 79,504 | 5,699 | 179,024 | 3,734 | 182,946 |
| 1x128 | 137,391 | 157,504 | 166,116 | 3,127 | 79,504 | 27,732 | 574,317 | 14,636 | 589,149 |
| 1x150 | 159,966 | 180,477 | 202,912 | 3,127 | 79,504 | 32,046 | 660,975 | 16,775 | 677,946 |
| 16x142 | 152,706 | 178,871 | 189,251 | 43,100 (PDAs 30,753) | 79,504 | 3,085 | 678,238 | 17,096 | 695,779 |
| 49x2 | 28,266 | 46,042 | 2,001 | 135,323 (PDAs 98,347) | 79,504 | 0 | 301,460 | 5,888 | 308,332 |

How to read the columns:

- `fill_owner_signer_hashes` (936) is part of the SPP total and is not listed.
- "Batch program + CPI" is the settle total minus the direct `transact` of the same data
  (1x150 direct: 661,171 [m]).
- The SPP event self-CPI is inside "SPP net". The profiler does not split it out.
- Full tables are in `program-tests/shielded-pool/CU_BENCHMARK_BATCH_SETTLEMENT.md`. The summary
  is in `program-tests/shielded-pool/OUTPUT_SCALING_SUMMARY.md`.

### Batch, transactions, circuit and verdict

| shape | CPI data bytes [m] | batch account bytes [m] | write txs [m] (60 records/tx) | settle tx bytes / addresses [m] | heap [m] | constraints [m] | prove time [m] | key size [m] | memory [m] | verdict, binding limit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 1x128 | 8,779 | 8,227 | 3 | 687 / 7 | 42 KiB | 348,442 | 0.49-0.76 s (server, warm) | 104,602,610 B | setup 837 MB; server with only this key 956 MB | works; nothing binds |
| 1x150 | 10,231 | 9,635 | 3 | 687 / 7 | 48 KiB | 416,714 | 0.684 s (Go bench); 0.52-0.57 s (server) | 120,304,928 B | setup 937 MB; prove process 1.19 GB; server 1.02 GB | **max for 1 input**; CPI data cap (9 bytes slack) |
| 16x142 | 10,198 | 9,123 | 3 | 1,677 / 22 | 46 KiB | 748,178 | 1.063 s (Go bench); 0.98-1.15 s (server) | 223,535,674 B | setup 1.79 GB; prove process 2.06 GB; server 2.11 GB | **max for 16 inputs**; CPI data cap (42 bytes slack) |
| 49x2 | 2,047 | 163 | 1 | 3,855 / 55 | 32 KiB | 1,121,100 | 2.410 s (Go bench); 1.80-1.89 s (server) | 362,114,005 B | prove process 3.18 GB; server 2.77 GB | works; the address count is the next limit (55 of 64) |
| 1x151 | 10,297 | 9,699 | 3 | 687 / 7 | - | - | - | - | - | **fails**: `data that is too large (10297 > 10240)` [m] |
| 16x143 | 10,264 | 9,187 | 3 | 1,677 / 22 | - | - | - | - | - | **fails**: `data that is too large (10264 > 10240)` [m] |

Notes:

- Write transactions: a `write_batch` transaction carries at most 60 records (64 bytes each)
  within 4,096 bytes [m, via `zolana_client::transaction_size`]. The init transaction comes on
  top. Batch program CU [m]: init 2,974 to 4,474 (PDA bump search), writes 198 to 203 each,
  settle overhead as above.
- Settle transaction size includes the v1 heap-request header field.
- Setup: `groth16.Setup` from system randomness, timed with `/usr/bin/time -l` [m]. 1x128 took
  11.0 s, 1x150 15.0 s and 16x142 27.8 s.
- "Go bench": `BenchmarkProveByShape`, average of 3 proofs after setup in the same process. Its
  peak RSS covers setup and proof together.
- "Server": the Rust `ProverClient` calling the prover server over HTTP, two proofs after a fresh
  server start with only that key loaded. The first proof includes loading the key: 1x128 1.79 to
  2.12 s, 1x150 0.57 to 2.03 s, 16x142 1.09 to 4.11 s, 49x2 1.82 to 6.68 s. The ranges cover
  three runs.
- The Go bench reports slightly different constraint counts: 1x150 420,331, 16x142 751,798,
  49x2 1,121,789. It compiles without `WithCompressThreshold(300)`. The table uses the production
  path (`R1CSTransfer`).

### Circuit sizing (task 2) [m]

| shape | constraints | per output vs 1x2 |
| --- | --- | --- |
| 1x2 | 30,922 | - |
| 1x16 | 59,546 | 2,045 |
| 1x64 | 170,906 | 2,258 |
| 1x128 | 348,442 | 2,520 |
| 1x150 | 416,714 | 2,607 |
| 16x142 | 748,178 | - |
| 49x2 | 1,121,100 | - |
| 1x256 (constraints only) | 800,666 | 3,031 |
| 1x500 (constraints only) | 2,027,410 | 4,072 |

The circuit grows faster than linearly in outputs. Every full insecure key the task asked for
(1x150 and 16x142, plus 1x128 for the bench) was practical: under 30 s and under 2 GB.

## Input limits (task 7) [m]

- Addresses:
  - The settle transaction carries 6 fixed addresses (payer = authority, batch account, batch
    program, SPP, tree, system program) plus one nullifier PDA per input.
  - 16x142 uses 22 and 49x2 uses 55 [m].
  - The batch path therefore caps inputs at 58 (64 - 6), against 60 for a direct `transact`.
    The supported shapes stop at 49 (`MAX_TRANSACT_INPUTS`), so this does not bind today.
- Instruction trace: the 49x2 settle uses 52 entries [m]: batch program, SPP, 49 system-program
  creates for the nullifier PDAs, and the event self-CPI. 16x142 uses 19 [m]. The limit is 64.
  The next limit after the address cap would be 61 inputs.
- `MAX_SIGNERS`: 16x142 has signer width 17 (1 + 16), within 29. No change needed.
- Nullifier queue: 49 insertions in one instruction are queued without error [m]. The queue
  batch size is 25,000.
- Input roots: one input tree. `MAX_INPUT_TREES` = 2 is unchanged. A second tree would add one
  account and 4 bytes of CPI data.
- No errors were hit on any input-side limit.

## Comparison with settling in place

Settling in place means the outputs go inline in the outer transaction's `transact` data, which
puts them under the 4,096-byte transaction limit. Measured with the same output encoding, the most
inline outputs one v1 transaction can carry is [m]:

| inputs | in place, max outputs per tx [m] | batch settle, max outputs [m] |
| --- | --- | --- |
| 1 | 52 (4,051 bytes; 53 needs 4,117) | 150 |
| 16 | 37 | 142 |
| 49 | 4 | 126 [e, formula] |

In-place shapes above 16 outputs do not exist today, and each would need its own key. For 150
payouts:

| | batch settlement | in place, ~45 per tx | in place, today's 1x16 |
| --- | --- | --- | --- |
| transactions | 1 init + 3 write + 1 settle (+1 close) [m] | 4 [e] | 10 [e] |
| proofs | 1 (0.57 s warm) [m] | 4 [e] | 10 [e] |
| total CU | about 685k [m: settle 677,946 + writes and init] | about 985k [e: 3 x ~270k + ~175k] | about 1.79M [e: 10 x 179,212 m] |
| CU per output | 4.5k [m] | about 6.0k [e] | 11.2k [m] |
| other costs | about 0.068 SOL of rent on the batch account while it is open [e] | needs a funded input per tx, or chained change | same |

The fixed cost per proof is about 128k CU [m-fit], which includes `verify_groth16` at 79,504
[m]. The batch path pays it once.

## Diff summary (prototype)

SPP and its libraries contain only shape and constant additions and stack-to-heap moves. There is
no new instruction, no buffer variant and no new event.

- `program-libs/interface/src/shape.rs`:
  - Adds `IN1_OUT128`, `IN1_OUT150` and `IN16_OUT142` to `SPP_SUPPORTED_SHAPES`, in cost order.
    Its length goes from 38 to 41.
  - Adds `AUTO_SELECT_MAX_OUTPUTS = 16`.
- `program-libs/interface/src/lib.rs`: `MAX_OUTPUTS` goes from 16 to 150.
- `program-libs/interface/src/state/cache.rs`: removes the `MAX_CACHE_WRITES >= MAX_OUTPUTS`
  assert. Cache writes stay at 16.
- `program-libs/interface/src/verifying_keys/`:
  - `circuit.rs` gets a `confidential_only` section in `circuit_key_item!` for the three shapes.
  - Three new generated vk files: `transfer_confidential_{1_128,1_150,16_142}.rs`, from the local
    keys through `light-prover export-vk` and `xtask bsb22-vk`.
  - `mod.rs` gets the modules and `UNPUBLISHED_PROVING_KEY_SHA256S`.
- `program-libs/interface/src/instruction/instruction_data/transact.rs`: `ExternalDataPreimage`
  slices move from `ArrayVec<_, 216>` to `Vec` (stack to heap). The bound check is kept.
- `program-libs/hasher/src/zero_suffix_hash_chain.rs`:
  - The `ZERO_SUFFIX_CHAINS` table goes from width 54 to 150 (19 to 51 entries). The original 19
    entries are unchanged.
  - New `PADDED_CHAIN_MAX_WIDTH = 54` keeps the stack buffer of `create_padded_right_hash_chain_4`
    at its old size.
- `programs/shielded-pool/src/instructions/transact/`. These are all stack-to-heap moves:
  - `event.rs`: `resolve_outputs` uses `Vec` instead of `ArrayVec<ResolvedOutput, MAX_OUTPUTS>`.
  - `verify.rs`:
    - `OwnerHashCache` uses a `Vec` with capacity `MAX_SIGNERS + n_outputs`.
    - `output_owner_pk_hashes` is a `Vec`.
    - New `padded_chain` pads output chains wider than 54 on the heap.
  - `processor.rs`: uses `with_output_capacity`.
- Clients:
  - `sdk-libs/client/src/prover/transact/assembly.rs`: output chains use a heap-padded fold
    (`padded_output_chain`).
  - `sdk-libs/transaction/src/instructions/transact/shape.rs`: `auto_shapes()` excludes shapes
    with more than 16 outputs.
- Go:
  - `prover/server/prover-test/spp/protocol/shape.go`: the shapes are added in cost order, and
    `AutoShapes` excludes more than 16 outputs.
  - `prover/server/prover/common/lazy_key_manager.go`: the shapes are added.
  - `prover/server/prover/transfer_eddsa_only/output_scaling_test.go`: new constraint-count test,
    which only runs when `SPP_OUTPUT_SCALING_SHAPES` is set.
- Batch test program `program-tests/spp-batch-program/`:
  - `init_batch`, `write_batch`, `settle` and `close_batch`.
  - PDA seeds `[b"batch", authority, batch_id]`. Header: `disc u8 | authority [32] | count u16`.
    Records: `utxo_hash | owner`, 64 bytes.
  - `settle` builds `tag | prefix | count | outputs | suffix` on the heap and CPIs SPP `transact`
    through `invoke_with_slice`.
  - Added to the workspace and to `tools/build-programs.sh`.
- Tests and bench:
  - `program-tests/shielded-pool/src/support/batch.rs`: builders, `SplitTransact`, `fill_batch`,
    v1 send with a heap request, and `ScalingSpend` (distinct owners, real proofs).
  - `tests/transact/batch_settlement.rs`:
    - New `[[test]] transact_batch_settlement`. It runs 1x16 end to end in LiteSVM: init, 4
      chunked writes, settle (the UTXO root equals the expected root over 16 leaves), and close
      to a dedicated rent recipient.
    - An ignored 1x150 / 16x142 v1-transaction test, ignored because it needs the local keys.
  - `tests/bench/output_scaling.rs`: `bench_cu_batch_settlement` (heap probe, direct and settle
    profiles, write counts, CPI-cap probes) and `in_place_output_capacity`.
  - `tests/bench/cu.rs`: `bench_cu_output_scaling` for direct shapes, from an env list.
- Test adjustments:
  - `interface/tests/{shape,circuit,transact,vk_proving_key_lock}.rs`.
  - `shielded-pool tests/transact/circuit_vectors.rs`: u8 overflow, since the owner array is now
    150 long.
  - `tests/verifying_keys/setup_markers.rs`: adds the unpublished markers.
  - `sdk-libs/transaction/tests/construction.rs`: only auto-selectable shapes.
  - `prover-test/spp/protocol/shape_test.go`.

### Existing shapes after the heap moves [m]

Direct `transact`, the original dummy-output bench (`CU_BENCHMARK_OUTPUT_SCALING.md` against
`CU_BENCHMARK.md`):

| shape | before | after | change |
| --- | --- | --- | --- |
| 1x2 | 136,612 | 136,839 | +227 (+0.17%) |
| 1x8 | 148,429 | 148,706 | +277 |
| 1x16 | 163,543 | 163,881 | +338 |
| 16x8 | 198,032 | 198,315 | +283 |
| 49x2 | 299,382 | 299,652 | +270 |

All of them still succeed. Task 1's baseline on the untouched branch matched `CU_BENCHMARK.md`
exactly: 1x2 136,612, 1x8 148,429 and 1x16 163,543, a 0.00% difference [m].

### Test status [m]

- **`just test-shielded-pool` passes on the scratch branch.** The counts are: zolana-interface and
  zolana-program 176 passed; shielded-pool-program 1; shielded-pool-tests (proofs) 427 passed with
  5 skipped; user-registry 1 and 6.
- The first two runs each had one failure, both fixed:
  - A u8 overflow in a circuit-vector test fixture.
  - The setup-marker test missing the three unpublished markers.
- `cargo test -p zolana-interface -p zolana-hasher` passes. `cargo nextest run -p zolana-client
  -p zolana-transaction -p zolana-program`: 425 passed.
- `transact_batch_settlement` passes, including the ignored wide test.
- Go `./prover-test/spp/protocol` passes.
- **Go `./prover/common` fails 2 tests on purpose:** `TestKeyFilesAreTheLockfileKeys` and
  `TestRPCPreloadsOnlyPublishedShapes`. The new key files are not in `proving-keys.lock`, and the
  ring and P256 rails list keys for the new shapes that do not exist. This is the rotation signal.
  These need publication, which this task did not allow.
- `cargo fmt --all --check` and clippy on the touched crates are clean.

## Changes needed for production

1. **Keys and rotation:**
   - Run a ceremony or rotation for the new shapes, or decide they are confidential-rail only.
     The Go key list currently names ring and P256 keys for them.
   - Update `prover/server/scripts/generate_keys_transfer.sh`, `proving-keys.lock` and the S3
     version folder.
   - Regenerate the vks with `regenerate_all_vkeys.sh`, which folds them into
     `PROVING_KEY_SHA256S` and removes `UNPUBLISHED_PROVING_KEY_SHA256S`.
   - Update the TS `sdk-libs/ts/src/interface/shape.ts` and `proving-keys.ts`, and add a CHANGELOG
     entry.
   - Revert the test relaxations in `vk_proving_key_lock.rs` and `circuit.rs`.
   - Until this is done, the prover's RPC preload mode would try to fetch keys that are not
     published (`TestRPCPreloadsOnlyPublishedShapes`).
2. **Heap request in the client.** `ComputeBudgetConfig` has no heap field, and wide transactions
   need 42 to 48 KiB. Add one and set it through `compile_message` (`sdk-libs/client/src/rpc/
   compute_budget.rs`). The prototype calls `v1::TransactionConfig::with_heap_size` directly in
   test support.
3. **Auto-selection policy.** The prototype keeps the wide shapes declared-only
   (`AUTO_SELECT_MAX_OUTPUTS`). This needs a product decision, and `docs/spec.md` should list the
   shape set.
4. **Owner-hash dedupe is O(n^2).** The `OwnerHashCache` linear scan costs about 2.5·n² CU
   [m-fit], 56k at 150 outputs. Use a sorted or hashed lookup, or skip dedupe for inline output
   owners.
5. **A real batch program** (an application program, not the fixture), with:
   - batch lifecycle and authority policy;
   - the init merged into the first write;
   - close or rent handling.
6. **Indexing:**
   - Outputs arrive in a CPI'd `transact` (inner instruction, depth 2, event at depth 3).
   - The prototype did not check `sdk-libs/event` or Photon reconstruction from inner
     instructions. Run the Photon e2e before relying on it.
   - Outputs without ciphertext need off-chain note delivery.
7. `sdk-libs/transaction` `MAX_OUTPUT_SLOTS` (plaintext slot indices) now follows `MAX_OUTPUTS` =
   150. Check the encrypted-output slot semantics for the wider value. The tests pass, but this was
   not reviewed.

## Future SPP buffer-reading variant (~500 outputs) [e]

The next step past 150 is an SPP variant that reads outputs from a buffer account instead of
instruction data. That removes the 10 KiB CPI cap. All numbers in this section are estimated from
the measured fits.

- **CU becomes the binding limit.** A fit to the measured 1x16, 1x128 and 1x150 points gives:
  - owner hashes 980n + 2.49n²;
  - tree append 26.4k + 732n + 1.06n²;
  - public input hash about 15.5k + 1,080n;
  - SPP net about 2.5k + 197n;
  - batch about 2.2k + 97n;
  - fixed (verify, input, signer) about 84k.

  That totals CU(n) ≈ 128k + 3,086n + 3.55n², which predicts 671k at 150 (677,946 measured).
  - As built, 1.4M CU allows about **305 outputs**. CU(500) ≈ 2.56M.
  - With the quadratic terms removed (linear owner dedupe, linear append), the limit is about
    **412 outputs**.
  - 500 outputs fit only at 2,544 CU per output or less. For example, an output queue instead of
    in-instruction tree append (about 732 down to about 100 CU per output) together with a linear
    owner cache gives about 1.36M at 500. Removing on-chain owner identity hashing (about 980 per
    output) would leave more margin, but changes the circuit's public inputs.
- **u8 output count binds at 255.** The `outputs` length prefix (`FixIntLen<u8>`) and
  `CircuitId`'s `n_outputs` are u8. A 500-output variant needs u16 counts, which is a layout
  change.
- **Circuit:**
  - 1x500 compiles to 2,027,410 constraints [m] (1x256: 800,666 [m]).
  - Key about 600 MB, at the measured ~290 to 300 B per constraint.
  - Prove about 3.3 s, scaled from 1x150's 0.68 s.
  - Setup peak RSS about 4.5 GB; prover RSS with the key loaded about 5 GB.
- **Heap:** about 0.27 KiB per output (42 KiB at 128, 48 KiB at 150 [m]), so about 145 KiB at
  500. That is under the 256 KiB maximum.
- **Batch account:** 500 x 64 + 35 = 32,035 bytes. Filling it takes 9 write transactions at 60
  records each, plus init. Rent is about 0.22 SOL while the batch is open.
- **Settle transaction:** unchanged at about 700 bytes and 7 addresses for 1 input, since the
  outputs no longer travel in instruction data.

## Phase 2: final 15-circuit set

Date: 2026-10-09, same worktree and branch. Nothing committed or pushed. No proving keys were
rotated or uploaded; all 15 keys are local single-party setups (`light-prover setup-transfer`)
in the gitignored `prover/server/proving-keys`. [m] = measured, [e] = estimated.

The shape set changed three times during the phase (12 confidential shapes, then 2-input rows,
then the final 4-input rows). Every dropped key and vk file was deleted; the lists below are
the final state. The phase 1 shapes 1x128, 1x150 and 16x142-only-confidential are superseded.

### Decisions

- **Final set, per rail [m: sizes from the serialized CPI data].** Each rail's widest shapes are
  sized to its own instruction data under the 10,240-byte CPI cap:

  | rail | shapes |
  | --- | --- |
  | transfer_confidential | 4x32, 4x64, **4x148**, **16x142**, **58x121** |
  | transfer_ring (eddsa) | 4x32, 4x64, **4x148**, **16x142**, **57x121** |
  | transfer_p256_ring | 4x32, 4x64, **4x146**, **16x140**, **57x120** |

  The 4-input max is 4x148, not 4x149: 4x149 needs 10,264 bytes [m]. The ring rails are sized
  with `ring_data_hash` present (+32 bytes), the larger encoding a ring program that binds its
  own digest produces. P256 adds 97 bytes on top (`RingP256ProofData`: 64-byte BSB22 commitment
  and PoK, plus the fixed 33-byte `default_owner_tag`). That costs 2 outputs at 4 and 16 inputs.
  Without `ring_data_hash`, ring eddsa would reach 57x122 (10,231 bytes [e, formula]).
- **The ring rails stop at 57 inputs, not 58 [m].** The ring path needs one more account than the
  confidential path: the ring config, which is the batch program's `ring_auth` PDA. The settle
  transaction carries 7 fixed addresses (authority/payer, batch account, batch program, SPP,
  ring config, tree, system program) plus one nullifier PDA per input, so 57 inputs use 64/64.
  A ring 58x121 settle fits the CPI cap (10,230 bytes [m]) but needs 65 addresses [m]. A
  58-input ring transact has no other way in: a ring program forwarding the data inline exceeds
  4,096 bytes. So the ring rails get a 57xMAX row in place of 58xMAX.
- **Batch-settlement shapes are never auto-selected.** `AUTO_SELECT_MAX_OUTPUTS` is gone (58x16 has
  16 outputs, so an output bound could not exclude it). It is replaced by an explicit
  `BATCH_SETTLEMENT_SHAPES` list plus `Shape::is_batch_settlement()`, and Go has the same pair
  (`BatchSettlementShapes`, `IsBatchSettlement`). `SPP_SUPPORTED_SHAPES` is the union: 38
  published plus 9 batch shapes, 47 in all. The batch shapes are keyed per rail: the vk table has
  `batch_confidential`, `batch_ring` and `batch_p256` sections, and Go has
  `batchSettlementShapes` per circuit type. On a rail that does not key a shape (for example
  `RingEddsa(58, 121)`), `verifying_key()` returns `None`.
- **1-, 2- and 3-input spends pad to the 4-input shapes with compact padding.** Compact padding
  inputs are not sent and insert no nullifier (see the headroom section).
- **Nullifiers live in the batch account.** Input records (`nullifier_hash [32] | tree_index u8`,
  33 bytes) are stored before the output records. The header is
  `disc | authority | output_count u16 | output_capacity u16 | input_count u8 | input_capacity u8`
  (39 bytes). `write_batch` takes a kind byte (outputs or inputs). Write transactions are packed
  greedily: inputs first, then outputs, with two `write_batch` instructions in one transaction
  when both fit. `settle` takes `prefix | middle | suffix` and splices in both vectors itself, so
  the settle transaction carries about 300 bytes of instruction data regardless of the input
  count.
- **New `settle_ring` (tag 4).** For the ring rails the batch program is the ring program. It CPIs
  `ring_transact` and signs its own `ring_auth` PDA, which SPP takes as the ring config.

### SPP and library changes in phase 2

SPP still has no new instruction, no new event and no buffer variant.

- `program-libs/interface/src/lib.rs`:
  - `MAX_TRANSACT_INPUTS` 49 -> 58.
  - `MAX_OUTPUTS` 150 -> 148, the widest output count in the set.
- `program-libs/hasher/src/zero_suffix_hash_chain.rs`: `PADDED_CHAIN_MAX_WIDTH` 54 -> 58. **This
  is a stack-buffer increase of 128 bytes, not a heap move.**
  - Why: the nullifier chain and the cache's empty-selection chain fold over the input width
    with `create_padded_right_hash_chain_4`. The first 58-input attempt failed with
    `Allowed input length 54 provided 58` [m].
  - Effect: no frame overflow at 58 inputs [m]; existing shapes cost 4 to 124 CU more than the
    phase 1 tree (regression table).
  - Alternative: a heap fold at each input-chain call site (SPP `verify.rs`,
    `state/cache.rs`, client assembly). Rejected as the larger diff. Flagging it because the rule
    was "stack-to-heap moves only".
- `programs/shielded-pool/src/instructions/transact/verify.rs`: the phase 1 heap `padded_chain`
  now rejects more sent values than slots, as the stack version does. It used to truncate
  silently.
- No new stack-to-heap moves were needed for 58 inputs. 58x121 settles as a real v1 transaction
  [m]. `TransactAccounts::nullifier_pdas` (`ArrayVec<_, MAX_INPUTS>`) grows from 49 to 58
  references, 72 more bytes.
- `shape.rs` and the vk table (`verifying_keys/circuit.rs`, `mod.rs`) changed as described under
  Decisions. 15 generated vk files. `UNPUBLISHED_PROVING_KEY_SHA256S` lists all 15.

### Phase 2 table

Settle figures are for the batch program's `settle` / `settle_ring` CPI.

- **Settle CU:** mollusk against the profiling `.so`, at the smallest heap that succeeds.
- **Trace entries, addresses and settle tx bytes:** from the same settle sent as a real v1
  transaction through LiteSVM at that heap. The tx bytes include the heap request.
- **Proof time:** the prover server over HTTP, warm (second proof in the run). Cold first proofs
  are in the notes.
- **Setup:** `/usr/bin/time -l` on `setup-transfer`, one setup at a time. Real time and peak RSS.
- **Inputs and outputs:** confidential rows use dummy inputs and distinct real owners. Ring rows
  use 1 real deposit input plus dummy inputs, dummy outputs, and `ring_data_hash`.

| rail | shape | constraints [m] | setup time [m] | setup peak RSS [m] | key size [m] | proof time [m] | settle CU [m] | heap [m] | addresses [m] | trace entries [m] | settle tx bytes [m] | CPI data bytes [m] | write txs [m] | verdict, binding limit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| confidential | 4x32 | 163,474 | 5.35 s | 421 MB | 51,934,467 B | 0.35 s | 248,959 | 32 KiB | 10 | 7 | 754 | 2,542 | 1 | works; nothing binds |
| confidential | 4x64 | 240,146 | 6.61 s | 497 MB | 71,520,622 B | 0.35 s | 358,692 | 32 KiB | 10 | 7 | 754 | 4,654 | 2 | works; nothing binds |
| confidential | **4x148** | 481,394 | 13.63 s | 906 MB | 137,232,674 B | 0.59 s | 680,152 | 47 KiB | 10 | 7 | 754 | 10,198 | 3 | **4-input max**; CPI data cap (4x149: 10,264 > 10,240) |
| confidential | **16x142** | 748,178 | 25.51 s | 1.83 GB | 223,535,674 B | 1.00 s | 696,913 | 46 KiB | 22 | 19 | 1,150 | 10,198 | 3 | **16-input max**; CPI data cap (16x143: 10,264) |
| confidential | **58x121** | 1,663,022 | 53.22 s | 3.77 GB | 495,911,382 B | 2.08 s | 761,496 | 42 KiB | **64** | 61 | 2,536 | 10,198 | 3 | **58-input max**; CPI data cap (58x122: 10,264) and 64 addresses, both reached |
| ring eddsa | 4x32 | 164,298 | 4.57 s | 418 MB | 52,076,616 B | 0.30 s | 206,090 | 32 KiB | 11 | 7 | 819 | 2,574 | 1 | works |
| ring eddsa | 4x64 | 241,738 | 5.83 s | 524 MB | 71,780,671 B | 0.35 s | 264,071 | 32 KiB | 11 | 7 | 819 | 4,686 | 2 | works |
| ring eddsa | **4x148** | 485,002 | 12.46 s | 1.05 GB | 137,783,925 B | 0.61 s | 411,259 | 47 KiB | 11 | 7 | 819 | 10,230 | 3 | **max**; CPI cap (4x149: 10,296) |
| ring eddsa | **16x142** | 751,798 | 18.59 s | 1.88 GB | 224,087,224 B | 0.98 s | 441,223 | 46 KiB | 23 | 19 | 1,215 | 10,230 | 3 | **max**; CPI cap (16x143: 10,296) |
| ring eddsa | **57x121** | 1,643,581 | 43.95 s | 3.65 GB | 490,513,102 B | 2.31 s | 545,668 | 42 KiB | **64** | 60 | 2,568 | 10,197 | 3 | **max**; 64 addresses (58 inputs need 65) and CPI cap (57x122: 10,263) |
| ring p256 | 4x32 | 309,458 | 12.21 s | 796 MB | 100,687,164 B | 0.55 s | 267,025 | 32 KiB | 11 | 7 | 916 | 2,671 | 1 | works |
| ring p256 | 4x64 | 387,090 | 13.82 s | 972 MB | 121,733,975 B | 0.64 s | 323,568 | 32 KiB | 11 | 7 | 916 | 4,783 | 2 | works |
| ring p256 | **4x146** | 624,782 | 20.13 s | 1.47 GB | 198,173,344 B | 0.98 s | 470,024 | 47 KiB | 11 | 7 | 916 | 10,195 | 3 | **max**; CPI cap (4x147: 10,261) |
| ring p256 | **16x140** | 891,626 | 26.39 s | 1.76 GB | 271,638,584 B | 1.24 s | 500,134 | 46 KiB | 23 | 19 | 1,312 | 10,195 | 3 | **max**; CPI cap (16x141: 10,261) |
| ring p256 | **57x120** | 1,786,928 | 67.11 s | 4.10 GB | 552,069,492 B | 2.28 s | 606,572 | 42 KiB | **64** | 60 | 2,665 | 10,228 | 3 | **max**; 64 addresses and CPI cap (57x121: 10,294) |

**Total key size of the 15 circuits: 3,200,678,916 bytes, 3.20 GB [m].** By rail: confidential
980 MB, ring eddsa 976 MB, P256 1,244 MB.

Notes:

- **LiteSVM settle CU:** the same settle as a v1 transaction in LiteSVM uses 200 to 260 CU less
  than mollusk, because of the profiling syscalls in the profiling `.so` [m]. For example,
  confidential 58x121 is 761,231. All 15 settles succeed.
- **Batch program overhead** (settle minus the direct `transact` of the same data, mollusk):
  about 5.8k to 20k CU, growing with outputs [m]. 4x148: 680,152 against 663,184. 58x121:
  761,496 against 743,175.
- **Ring CU is lower than confidential** at the same shape. Ring outputs without the
  confidential encryption marker publish owner tag 0, so SPP hashes no owner identity per output
  [m]. At 4x148 that is 411k against 680k. P256 adds about 59k to 61k over ring eddsa at the same
  input count.
- **Heap:** the wide shapes need 46 to 47 KiB at about 145 outputs and 42 KiB at 121 outputs.
  The 4x32 and 4x64 shapes fit the 32 KiB default [m]. In LiteSVM the three confidential Max
  shapes fail 1 KiB below their heap and succeed at it [m]
  (`wide_settlements_succeed_as_v1_transactions`).
- **Write transactions:** 60 output records fill a 4,096-byte write transaction. The input
  records share the first write transaction, so every Max shape needs 3 write transactions plus
  the init transaction [m]. For 58x121 that is 58 x 33 + 121 x 64 bytes of records; the batch
  account is 9,697 bytes.
- **Trace entries:** batch program + SPP + one system create per nullifier PDA + the SPP event
  self-CPI = inputs + 3. That gives 61 at 58 inputs and 60 at 57, against a limit of 64 [m].
- **Cold first proofs** (including key load): ring eddsa 0.98 / 1.27 / 2.32 / 3.89 / 7.97 s;
  P256 1.88 / 2.49 / 3.53 / 4.69 / 8.61 s, in table order [m]. The confidential keys were
  already loaded by an earlier run, so their first proofs were warm.
- **Setup conditions:** setups ran one at a time, but some overlapped cargo builds, so treat the
  times as upper bounds. Confidential 16x142 was regenerated in this phase: 25.5 s, against 27.8 s
  in phase 1.

### 58-input maximum [m]

- **Confidential: the largest n that settles is 121.** 58x121 settles with a real proof as a v1
  transaction in LiteSVM:
  - 761,538 CU;
  - 42 KiB heap;
  - 64/64 addresses;
  - 61 of 64 trace entries;
  - 2,536-byte settle transaction;
  - 10,198-byte CPI.
- **First failing n is 122.** 58x122 fails in the batch program's CPI with
  `Invoked an instruction with data that is too large (10264 > 10240)`. It is probed without a
  proof; it fails before SPP runs.
- **Ring eddsa max is 57x121 and P256 is 57x120.** See Decisions for why 58 inputs need 65
  addresses on these rails.

### Extra measurements [m]

| case | settle CU | heap | addresses | trace entries | settle tx bytes | CPI data bytes | write txs | top-level `transact`, no batch account |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| confidential 4x148, 1 input + 40 outputs sent | 276,679 | 32 KiB | 7 | 4 | 655 | 2,971 | 1 | **fits**: 3,259 bytes, 5 addresses; direct CU 270,337 |
| confidential 4x148, 1 input + 148 outputs sent | 671,701 | 47 KiB | 7 | 4 | 655 | 10,099 | 3 | does not fit: 10,387 bytes |
| confidential 4x148, all 4 inputs + 148 outputs | 680,152 | 47 KiB | 10 | 7 | 754 | 10,198 | 3 | does not fit: 10,585 bytes |
| confidential 4x32, 1 input vs 4 inputs sent | 240,507 vs 248,959 | 32 KiB | 7 vs 10 | 4 vs 7 | 655 vs 754 | 2,443 vs 2,542 | 1 | fits: 2,731 / 2,929 bytes |
| ring eddsa 4x32, 1 vs 4 inputs sent | 197,244 vs 206,090 | 32 KiB | 8 vs 11 | 4 vs 7 | 720 vs 819 | 2,475 vs 2,574 | 1 | n/a (ring) |
| ring p256 4x32, 1 vs 4 inputs sent | 258,547 vs 267,025 | 32 KiB | 8 vs 11 | 4 vs 7 | 817 vs 916 | 2,572 vs 2,671 | 1 | n/a (ring) |
| confidential 58x121 as collect: 57 inputs + 2 outputs sent | 343,113 | 32 KiB | 63 | 60 | 2,503 | 2,311 | 1 | does not fit: 4,447 bytes, 61 addresses |
| ring eddsa 57x121 as collect: 57 + 2 | 343,734 | 32 KiB | 64 | 60 | 2,568 | 2,343 | 1 | n/a (ring) |
| ring p256 57x120 as collect: 57 + 2 | 404,989 | 32 KiB | 64 | 60 | 2,665 | 2,440 | 1 | n/a (ring) |

- **Padding cost on 4x32.** Sending 1 input instead of 4 saves 8,452 CU (confidential), 8,846
  (ring eddsa) and 8,478 (P256) [m]. That is about 2.8k to 2.9k per padded slot: the nullifier
  PDA create, the queue insertion and 33 bytes of data. The proof and its verification cost the
  same, so the padding itself costs nothing on chain.
- **Collect on the 58-input shape.** With 57 inputs and 2 outputs it uses 63 of 64 addresses
  (64 on the ring rails) [m]. The top-level form needs 4,447 bytes, so only the batch path can
  send it [m].
- **Padded settlement without the batch account.** 1 input with 40 outputs on 4x148 fits a
  top-level transaction (3,259 bytes [m]). The in-place ceiling for 1 sent input was not
  re-measured for 4x148 [e: about 52, from phase 1's 1-input measurement].

### Dummy-input headroom

What it measures:

- `TreeAccount::dummy_input_headroom()` (`program-libs/tree/src/lib.rs`) is
  `remaining_queue_capacity - utxo_tree.capacity()`, that is
  `2^40 - queue_next_index - 2^32`.
- It is the nullifier slots left above a reserve of one slot for every UTXO the state tree can
  ever hold. Dummy and address inputs consume nullifier slots that no UTXO backs, so they must
  not eat into the reserve that real spends need.

How it is consumed:

- `apply_input_trees` (`programs/shielded-pool/src/instructions/transact/tree.rs`) publishes
  `allow_dummy_inputs = headroom >= sent inputs` for each input tree, as bit 0 of `input_flags`.
- When the flag is false, the circuit requires every input slot to be a real UTXO or compact
  padding (`circuits/spp_transaction/shared/transaction.go`).
- Every queued nullifier, real or dummy, lowers the headroom by one.
- Compact padding is not sent: it inserts nothing and consumes nothing.
- Nothing replenishes it; the queue index only grows.

Can a busy tree run out?

- Only after about 2^40 - 2^32 ≈ 1.095e12 queued nullifiers [e, arithmetic].
- At most 2^32 of those can be real spends, so the state tree fills (2^32 UTXOs) and rolls over
  long before. Exhausting the headroom would take about 1.09e12 dummy nullifiers.
- A 1-input spend on a 4-input shape consumes 1 unit (its own nullifier), not 4. The 3 padded
  slots draw none.
- Even at zero headroom the spend still settles, as long as it is proven for
  `allow_dummy_inputs = false`. Only random (non-compact) dummy padding stops working.

Tested [m]: `compact_padded_settlement_needs_no_dummy_input_headroom` in
`tests/transact/batch_settlement.rs` (ignored, needs the local ring 4x32 key; it passes). It
settles a ring eddsa 4x32 spend with 1 real input and 3 compact slots through the batch
program, and checks:

- On a fresh tree the headroom drops by exactly 1, with 32 outputs appended and 1 nullifier
  queued.
- With the queue cursor moved so the headroom is 0, the spend proven for
  `allow_dummy_inputs = false` settles, and the headroom stays 0.
- The same spend proven for `allow_dummy_inputs = true` is refused at zero headroom.

The existing `transact_past_the_dummy_threshold_accepts_only_compact_padding` (INV-TRANSACT-33)
covers the same rule for a top-level 2-input transact, and it passes.

### Regression [m]

- **`just test-shielded-pool` passes** (exit 0, `ZOLANA_PORT_OFFSET=700`):
  - zolana-interface + zolana-program: 176 passed, 2 skipped;
  - shielded-pool-program: 1 passed;
  - shielded-pool-tests (proofs): 427 passed, 6 skipped (the skipped ones include the 3
    ignored batch tests);
  - user-registry: 1 and 6 passed.
- **`transact_batch_settlement` with `--include-ignored`:** 3 of 3 pass (1x16; 4x148, 16x142 and
  58x121 as v1 transactions; the headroom test).
- **`cargo test -p zolana-interface -p zolana-hasher`** passes. **`cargo fmt --all --check`** is
  clean. **Clippy** on the touched crates (shielded-pool-tests, spp-batch-program,
  zolana-interface, zolana-hasher, zolana-transaction, zolana-client, shielded-pool-program) is
  clean.
- **Go `./prover-test/spp/protocol`** passes.
- **Go `./prover/common` fails the same 2 tests as phase 1, on purpose:**
  - `TestKeyFilesAreTheLockfileKeys`: the key list now has exactly the 15 batch keys beyond the
    lockfile.
  - `TestRPCPreloadsOnlyPublishedShapes`: `transfer_confidential_4_32.key` is unpublished.

  This is the rotation signal and needs publication, which this task did not allow.
- **Existing bench rows** (`bench_cu_output_scaling`, direct `transact`, `process_transact_ix`
  total, mollusk) all succeed:

  | shape | main (`CU_BENCHMARK.md`) | phase 1 | phase 2 | phase 2 vs main |
  | --- | --- | --- | --- | --- |
  | 1x2 | 136,612 | 136,839 | 136,843 | +231 (+0.17%) |
  | 1x8 | 148,429 | 148,706 | 148,724 | +295 (+0.20%) |
  | 1x16 | 163,543 | 163,881 | 163,911 | +368 (+0.23%) |
  | 16x8 | 198,032 | 198,315 | 198,409 | +377 (+0.19%) |
  | 49x2 | 299,382 | 299,652 | 299,776 | +394 (+0.13%) |

  The phase 2 increase over phase 1 is 4 to 124 CU. It comes from the wider padded-chain stack
  buffer and the 58-slot nullifier PDA `ArrayVec`.
- **Not run:** the Go circuit test suite (`go test ./...` under `circuits/`), the TS SDK and
  the localnet/validator suites.

### Phase 2 diff summary

- `program-tests/spp-batch-program/src/lib.rs`: input records, the header with counts and
  capacities, the kind byte in `write_batch`, the three-part `settle`, and `SETTLE_RING`, which
  signs `ring_auth`.
- `program-tests/shielded-pool/src/support/batch.rs`:
  - `SplitTransact` cuts around both vectors.
  - Greedy mixed write packing.
  - `ScalingSpend` gains `sent_inputs` / `sent_outputs` (compact padding on both sides).
  - `send_v1_traced` reports trace entries.
- New `program-tests/shielded-pool/src/support/batch_ring.rs`: `RingScalingSpend` (ring eddsa
  and P256 with real proofs, compact padding, `ring_data_hash`, dummy-input policy) and
  `ring_transact_instruction`.
- `tests/bench/output_scaling.rs`:
  - Rail-prefixed specs (`ring:`, `p256:`) and sent counts (`58x121/57x2`).
  - LiteSVM v1 send for CU and trace entries.
  - Top-level size column.
  - `SPP_BENCH_DIRECT` for direct profiles.
- `tests/transact/batch_settlement.rs`: the wide test now covers 4x148, 16x142 and 58x121; new
  headroom test.
- Rust and Go shape lists, the vk table, the `MAX_*` constants and the hasher constant, as above.
- Test adjustments:
  - `interface/tests/{shape,circuit,tree_slot,vk_proving_key_lock}.rs`.
  - Go `shape_test.go`.
- `program-tests/shielded-pool/CU_BENCHMARK_BATCH_SETTLEMENT.md` holds the last generated
  per-function profile, which is the ring rails' run. The tables above are the source of truth.

To reproduce, set up the bench `.so` files as `just bench-shielded-pool` does (plain copy to
`shielded_pool_program_plain.so`, profiling build in `target/deploy`), then run:

```bash
ZOLANA_PORT_OFFSET=700 ZOLANA_PROVER_URL=http://127.0.0.1:3701 SPP_BENCH_DIRECT=1 \
SPP_BENCH_BATCH_SHAPES=4x32,4x32/1x32,4x64,4x148,4x148/1x40,4x148/1x148,16x142,58x121,58x121/57x2,ring:4x32,ring:4x64,ring:4x148,ring:16x142,ring:57x121,p256:4x32,p256:4x64,p256:4x146,p256:16x140,p256:57x120 \
SPP_BENCH_PROBE_SHAPES=4x149,16x143,58x122,ring:4x149,ring:57x122,ring:58x121,p256:4x147,p256:57x121 \
cargo test -p shielded-pool-tests --features proofs --test bench_cu bench_cu_batch_settlement -- --ignored --nocapture
```
