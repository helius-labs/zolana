# Batch settlement through a batch account: how many outputs one SPP transact can pay

Date: 2026-10-09 (planned on worktree t3code-80fd8010, branch t3code/80fd8010)

## IMPORTANT

- Split the task into todos, one per task below. Work through them one at a time; do not batch.
- Use subagents where it makes sense (opus agents implement, the main session reviews and re-measures).
- If stuck or starting to do random things, use a subagent to research.
- Test early: run each task's test or measurement as soon as its code exists.
- Scratch branch only. Do not commit to main, push, rotate proving keys or upload keys.
  Locally generated insecure test keys for experimental shapes are fine.
- **No new SPP instruction, no SPP buffer variant, no new SPP event (user decision).** SPP is
  reached through its existing `transact`. Allowed on the scratch branch: the shape and constant
  changes a wider existing shape needs (shape tables, vk table entries, `MAX_OUTPUTS`, hash-chain
  table width) and stack-to-heap moves (ArrayVec -> Vec/Box) where a wide shape overflows the
  SBF frame. Every such change is listed in the report.
- Settlement model (user decision): fill the batch account over several write transactions,
  then ONE settlement transaction with ONE proof pays every output.
- Every number in the report is marked **measured** or **estimated**.
- Measure through the SPP bench harness (`program-tests/shielded-pool/tests/bench/cu.rs`,
  `just bench-shielded-pool`: litesvm builds state, mollusk replays against the profiling .so).
- Hard limits (cannot change): 4,096-byte v1 transaction, 64 addresses, 1.4M CU, 10 KiB CPI
  instruction data (`MAX_CPI_INSTRUCTION_DATA_LEN = 10 * 1024`), 64-entry instruction trace,
  256 KiB maximum heap.
- Spec context: kVault intents spec in worktree `t3code-955b6797`
  (`sdk-tests/kamino-vault-intents/spec.md`, open item 1: batched pay and collect).

## Goal

Measure how many outputs one settlement can pay when a batch program reads the outputs from its
batch account and CPIs the existing SPP `transact` with them inline (outputs without ciphertext),
for 1 input and for 16 inputs, and the cost of getting there: CU, write transactions, circuit
size and proving cost. Also 49x2 collect through the same program.

## Starting estimate (to be replaced by measurements)

Instruction data per the wincode layout (plain eddsa, no transfers, data hashes or messages):
293 fixed bytes + 33 per input + 4 per input tree; 66 bytes per output
(`utxo_hash` 32 + `OwnerTag::Inline` 33 + `data: None` 1).
- 1 input: (10,240 - 330) / 66 = **150 outputs** (estimated).
- 16 inputs: (10,240 - 825) / 66 = **142 outputs** (estimated).
- CU at 150 outputs: about 134k + 150 x 2.5k = about 510k (estimated). The 10 KiB CPI data cap
  binds before CU.
- Code caps on this path: `outputs` length prefix is u8 and `CircuitId` stores `n_outputs` as u8
  (255, above the 150 data cap, so no change needed).

## Design

### Batch program (`program-tests/spp-batch-program`, test SBF program)
- `init_batch(batch_id, capacity)`: create the batch PDA `[b"batch", authority, batch_id]`.
- `write_batch(offset, records)`: write records in chunks; authority signs.
- `settle(prefix, suffix)`: read the records, build the SPP `transact` instruction data on the heap
  (caller passes the fixed fields: expiry, viewing key, salt, private tx hash, circuit, proof,
  inputs, tree contexts; the program splices in the outputs from the batch account), CPI SPP
  `transact` with the forwarded accounts.
- `close_batch`: close to a dedicated rent recipient.
- Record layout: `utxo_hash [32] | owner [32]`, 64 bytes per output. Header:
  `discriminator u8 | authority [32] | count u16`.
- The batch account is trusted by nobody: every output hash and owner tag is bound by the proof's
  public input hash, so a tampered batch account fails verification.
- Indexing is unchanged: outputs are in the inner instruction data of the CPI'd `transact`, and
  the existing SPP event and `sdk-libs/event` reconstruction apply. Depth: batch program -> SPP ->
  SPP self-CPI event = 3.

## Tasks

1. **Scratch branch and baseline.** Create `jorrit/spp-output-buffer-scaling` from main. Build
   programs, run `just bench-shielded-pool` for 1x2/1x8/1x16 to reproduce the known numbers.
   Accept: baseline within 1% of CU_BENCHMARK.md.

2. **Circuit sizing (Go).** Add 1x64, 1x128, 1x150, 16x142 and 49x2 (exists) to the Go shape
   list on the scratch branch. Compile each: constraint count. For 1x150 and 16x142: insecure
   local setup, setup time, `.key` size, peak RSS (`/usr/bin/time -l`), one proof time.
   Also compile 1x256 and 1x500 for the record (constraints only), as the reference for a
   future SPP buffer variant.
   Accept: table of constraints, key size, memory, prove time, measured.

3. **Shape and constant changes.** Add 1x128, 1x150 and 16x142 to `program-libs/interface/src/shape.rs`,
   the vk table (`verifying_keys/circuit.rs`, scratch insecure vks), Go `shape.go` and
   `lazy_key_manager.go`; raise `MAX_OUTPUTS` (`program-libs/interface/src/lib.rs:57`) to 150 and
   decouple the cache assert (`state/cache.rs:30`); extend the zero-suffix table past 54
   (`program-libs/hasher/src/zero_suffix_hash_chain.rs`) to 150; check other `MAX_OUTPUTS`-sized
   buffers (`OwnerHashCache`, `TransactProofInputs` in `transact/verify.rs`).
   Accept: `cargo test -p zolana-interface -p zolana-hasher` green; SPP builds for SBF.

4. **Stack and heap fixes in SPP.** Build and run a 1x150 transact; where the SBF frame overflows
   (`resolve_outputs` ArrayVec in `transact/event.rs:23`, owner caches), move to `Vec`/`Box`.
   Accept: existing transact tests green; 1x150 runs without frame errors.

5. **Batch test program.** Implement as above with builders in the test crate.
   Accept: init + chunked writes + settle CPI succeed for 1x16.

6. **Bench sweep.** Real proofs from local insecure keys: 1x128, 1x150, 16x142, 49x2 via the batch
   program. Profile per function (tree append, public input hash, owner hashes, CPI, event).
   Probe the data cap: 1x151 must fail on CPI instruction data length. Count write transactions
   per shape with `zolana_client::transaction_size`.
   Accept: per-shape profile table; maximum outputs for 1 and 16 inputs measured.

7. **Input limits check.** With 16x142 and 49x2: address count (nullifier PDAs + fixed accounts
   + batch program accounts), `MAX_SIGNERS` (16 inputs -> 16 signer slots, under 29), nullifier
   queue insertion per instruction, input root checks, the 58-input address cap.
   Accept: measured address counts and any error hit.

8. **Report.** `plans/spp-output-buffer-scaling-report.md`: table (shape -> CU -> batch bytes and
   write txs -> constraints, prove time, key size -> verdict and binding limit), maximum outputs for
   1 and 16 inputs, comparison with settling in place at about 45 outputs per tx, the prototype
   diff summary, the required changes with file references, and an estimated section for a future
   SPP buffer variant (about 500 outputs, CU-bound) as the next step beyond 150.

## Phase 2: final shape set (user decision, 2026-10-09)

Confidential eddsa rail only, all excluded from automatic shape selection:

| Inputs | 16 | 32 | 64 | 128 | Max |
| --- | --- | --- | --- | --- | --- |
| 1 | | 1x32 | 1x64 | 1x128 | 1x150 |
| 2 | | 2x32 | 2x64 | 2x128 | 2x149 |
| 16 | | | 16x64 | | 16x142 |
| 58 | 58x16 | | | | 58x121 (estimate; measure the true max) |

58x16 replaces 58x2 (collect uses it with compact output padding). No 58x64.

Tasks:
11. **Shape set.** Make the scratch shape lists (Rust `shape.rs`, vk table, Go `shape.go`,
    `lazy_key_manager.go`, `generate_keys_transfer.sh` if used) exactly the set above; drop
    experimental-only shapes no longer in the set. Local insecure keys and vks for each.
12. **Nullifiers in the batch account.** Batch program stores input records
    (`nullifier_hash [32] | tree_index u8`) next to the output records; `settle` splices inputs and
    outputs into the SPP transact data. The settle tx carries only the batch program data and
    the account list. Raise `MAX_TRANSACT_INPUTS` to 58 (`program-libs/interface/src/lib.rs:60`)
    and move to the heap whatever overflows the SBF frame at 58 inputs.
13. **58-input maximum.** Measure the largest n with 58xn settling (first failure and its error),
    the address count (expect 64/64), trace entries, settle tx size, CU, heap request. Also 58x16
    with 2 sent outputs (collect).
14. **Measure every shape.** Constraints, setup time and memory, key size, proof time, settle CU
    (via the batch program), heap request, write tx count. Update the report with a phase 2 table.
15. **Regression.** `just test-shielded-pool` and the existing bench rows; report honestly.

## Phase 2 revision: final 15-circuit set (user decision, 2026-10-09, supersedes the table above)

Rails: transfer_confidential, transfer_ring, transfer_p256_ring (no ring authority).
Shapes per rail: 4x32, 4x64, 4xMAX (about 148), 16x142, 58xMAX (about 121). No 1- or 2-input
wide shapes; smaller spends pad the unused input slots. Ring rails use their own largest fitting
Max shapes.
Extra checks: 4xMAX with 1 input and 40 / MAX outputs sent; 4x32 with 1 vs 4 inputs sent;
58xMAX as collect (57 in, 2 out); dummy-input headroom behaviour for 1-input spends on 4-input
shapes (3 padded slots).

## Acceptance criteria

- Every number in the report is marked measured or estimated.
- Maximum output count for 1 input and for 16 inputs, with the binding limit named.
- No new SPP instruction or event; SPP changes limited to shapes, constants and stack-to-heap moves.
- Scratch branch holds the prototype diff; nothing pushed, no keys uploaded or rotated.
- Existing shielded-pool tests still pass on the scratch branch (`just test-shielded-pool`).
