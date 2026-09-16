# Settlement critical path for arbitrary scattered notes

The measured 144-input PR #320 comparator takes 7,659 ms to recipient wallet decryption: 968 ms of witness preparation, 3,974 ms proving, 2,704 ms submission, and approximately 12 ms after confirmation. It uses five packed v1 transactions, five proofs, normal Squads authorization, four actual prover permits, and GOMAXPROCS=18. It is a warm-key, unprepared-payment single sample.

A 10× target is 766 ms. Removing the entire submission stage still leaves approximately 4,955 ms. Transport improvements alone cannot meet this target on the measured CPU/proving path. Do not describe faster confirmation polling as a new proving architecture or infer production finality latency from a single-validator fixture.

## An avoidable confirmation barrier

`SolanaRpc::process_transaction` delegates to solana-rpc-client 4.2.2's `send_and_confirm_transaction`. Its nonblocking implementation sleeps 500 ms whenever a signature has not reached the configured commitment. Our harness repeats this barrier for every packed transaction. Initially, five observations at approximately 540 ms suggested that almost all submission time might be observation delay. The real fast-poll experiment disproves that stronger inference: submission still takes 1,627 ms with 25 ms polling.

The isolated SDK exposes `wait_for_signature_with_interval` for the existing send-only method. It preserves the client's commitment and reports confirmed execution errors. The production `process_transaction` default is unchanged. An explicit `E2E_BENCH_POLL_MS` enables this path only in the benchmark snapshots. Short HTTP polling is appropriate for this local experiment; websocket signature notifications avoid a proportional increase in production RPC traffic.

The initial paired experiment keeps every existing transaction confirmation barrier. This isolates polling from pipelining. The controlled mock probe is separately labeled: it makes the first status pending and the second finalized, so it measures the SDK's observation delay, not chain execution or finality.

The controlled mock probe passed at 502,571 microseconds for the upstream 500 ms path and 28,621 microseconds for the 25 ms path. Correctness tests verify that lower-commitment success does not prematurely satisfy a finalized-configured client, that confirmed execution errors propagate, and that zero polling intervals fail. Raw output: `notes/confirmation-probe.log`.

Both original recipient-index waits use the existing `test_validator_asserts::wait_for`, which sleeps 500 ms after a miss. Cache polls transactions by recipient tag; the original direct harness polled output Merkle proofs before fetching the transaction by signature. The new cache run's 511 ms tail is consistent with one missed poll; the prior 12 ms tail was an immediate hit. The 500 ms interval remains unchanged. Ratios between individual runs are not robust performance estimates.

The first direct fast-poll run also revealed an instrumentation asymmetry: direct fetched CU metadata after each transaction, inside submission timing, whereas cache collected it after recipient decryption. `fetch_confirmed_transaction` retries every 250 ms. That first direct run is retained in `notes/direct144-fast-poll.log` but is not the final aligned comparator. The corrected direct snapshot moves CU, event, and extra output-Merkle assertions after recipient timing; it uses the same recipient-tag polling helper as cache. Both decrypt through `Wallet::sync` with index zero and `DEFAULT_TAG_WINDOW`. Every correctness assertion is retained.

The completed cache fast-poll sample uses five transactions/five proofs and 1,333,581 CU: witness 944 ms, proving 3,841 ms, submission 1,627 ms, confirmed 6,413 ms including witnesses, recipient decrypted 6,924 ms. Deposit setup was 76,295 ms and excluded key warmup was 4,590 ms. The actual fresh server log confirms four permits and GOMAXPROCS=18. Raw outputs are `notes/cache144-fast-poll.log` and `notes/cache144-fast-poll-server.log`.

The corrected direct run also passed, including full-balance recipient decryption and all deferred CU/event/Merkle assertions. The final comparison is:

| Warm keys, unprepared payment, 144 inputs | Proofs | Transactions | Total CU | Witness | Proving | Submission | Recipient decrypted, including witnesses |
|---|---:|---:|---:|---:|---:|---:|---:|
| PR #320 cache, 25 ms status poll | 5 | 5 | 1,333,581 | 944 ms | 3,841 ms | 1,627 ms | 6,924 ms |
| Direct, aligned endpoint/instrumentation, 25 ms status poll | 9 | 3 | 1,145,347 | 546 ms | 3,313 ms | 973 ms | 5,380 ms |

These individual samples give a 1.287× recipient-latency ratio, not 10× and not a statistically established speedup. Both waited approximately one index-poll interval after confirmation: cache 511 ms, direct 532 ms. The direct run excluded 34,923 ms of deposits/registration and 3,936 ms of key warmup. Its raw `confirmed_ms=4301` and `indexed_ms=4833` start after initial witness generation; `total_ms=5380` is the comparable full recipient endpoint. The cache's `confirmed_ms` already includes its witness phase, so those raw confirmation fields must not be compared directly.

The direct server log confirms four permits; the shared run script explicitly exports GOMAXPROCS=18, but that older binary does not log the runtime value. The corrected artifacts are `notes/direct144-fast-poll-aligned.log` and `notes/direct144-fast-poll-aligned-server.log`. No competing proof or compile job ran during either measured spend window. The direct native build during the cache fixture finished before the first cache proof request. Scoped listener checks after completion found no services on the six owned localnet/prover ports.

## Packet limits

Fresh, independent 256-bit nullifiers require 4,608 bytes for 144 inputs before proofs, signatures, account addresses, and outputs. Even ideal fixed 254-bit field encoding requires 4,572 bytes. Neither fits a 4,096-byte v1 transaction. For 512 inputs, 16,384 raw nullifier bytes require at least four packets with zero overhead, and therefore at least five actual packets. This does not imply one slot or one confirmation round per packet.

The reproducible native experiment is `sdk-libs/client/examples/settlement_wire.rs`. It uses the existing `transaction_size`, compiler, signer, and wire serializer, asserting that both byte counts agree. Outputs use the real confidential encryption helper, with two output commitments/tags/ciphertexts, not empty placeholders. It includes expiry, maximum forester fee, both root indices, private-transaction hash, viewing key, salt, priority fee, a 256 KiB heap request, a signer, one shared input/output tree, and one nullifier filter account. The proposed instruction format is not accepted by the deployed program. Proof point placeholders measure bytes only; they are not valid proofs.

Multiple proof variants additionally carry a 32-byte value commitment per 36-input chunk. These model the public glue needed by a chunk-plus-balance construction; changing the proof encoding does not prove that construction is implemented or sound.

Measured signed sizes for 144 inputs, two encrypted outputs, and five account addresses:

| Tag bits | Proofs and point encoding | Wire bytes | Fits 4,096 B |
|---:|---|---:|---|
| 256 | One 192-byte proof | 5,516 | No |
| 192 | One 192-byte proof | 4,364 | No |
| 184 | One 192-byte proof | 4,220 | No |
| 176 | One 192-byte proof | 4,076 | Yes, 20 B spare |
| 160 | One 192-byte proof | 3,788 | Yes, 308 B spare |
| 128 | One 192-byte proof | 3,212 | Yes, 884 B spare |
| 128 | Five 192-byte proofs, four value commitments | 4,108 | No, 12 B over |
| 128 | Five 128-byte proofs, four value commitments | 3,788 | Yes, 308 B spare |

The one-proof 128-bit version still fits at 3,730 B with a 256-byte memo encrypted in each output. These sizes exclude a Squads wrapper, an additional owner/fee-payer signer, a registry account, a separate output tree, and P256/BSB22 proof commitments. Adding such requirements consumes the stated headroom. The 176-bit maximum is specific to this schema, not a protocol-wide optimum. The complete raw output is `notes/settlement-wire.log`.

## Short deterministic public tags

Publishing a fixed prefix or suffix of each deterministic nullifier can cross the packet boundary without revealing the note's tree position. Repeating the same full nullifier always repeats its tag. An exact tag set therefore prevents double spending, although two different nullifiers with the same tag can cause a false rejection. A new circuit must constrain the published tag to the correct bits of the original nullifier. Every spend path must check and register the same namespace.

For an ideal t-bit tag, generic birthday collisions take about 2^(t/2) work; targeting one particular existing note takes about 2^t work. Targeting any of M spent tags reduces the latter to about 2^t/M. Random collision probability among n tags is approximately n(n-1)/2^(t+1). These are availability and grind-resistance changes, even when repeated-tag rejection retains double-spend safety. A 128-bit tag is not automatically necessary: 160-bit and wider layouts are measured below.

Migration must project every historical spent nullifier and ensure every legacy/new spend updates the tag set before enabling tag-only admission. A partially backfilled filter can admit an old spend again. A Bloom filter may reject conservatively, but its construction and updates must have no false negatives. An exact collision fallback needs authenticated full-nullifier information for the collision bucket; it cannot conjure unpublished original nullifiers after a collision. No migration or fallback has been implemented here.

The new-path lifecycle is equally important: a forester cannot insert the original full nullifier into the legacy indexed tree from its short tag. Clearing a recent-tag guard and later accepting a legacy non-inclusion proof would permit a replay of that new-path spend. A permanent authoritative tag set checked by every route avoids that gap. An alternative must publish authenticated full-nullifier data and prove ingestion before pruning the guard. A Bloom-positive fallback to the old tree is not a drop-in solution when short-only spends never entered that tree.

The minimal packet also assumes one filter account. A flat exact 160-bit set reaches 10 MiB at 524,288 tags before any indexing/metadata. Sharding expands the account-address table when arbitrary inputs touch many shards: 15 additional addresses and instruction references cost approximately 495 B, already larger than the 160-bit format's 308 B headroom. Loaded-account limits also constrain large multi-shard reads. An authoritative short-tag indexed tree plus a sound negative filter can be designed, but all routes and maintenance then need that new state model; the legacy full-nullifier tree cannot supply its missing history. A bounded Bloom filter's saturation and rotation must not erase replay protection.

## One final confirmation without one transaction

Independent certificate/buffer uploads can be broadcast using one fetched blockhash. A finalizer can verify an exact owner-bound manifest of successfully prepared receipts, verify the aggregate balance/intent proof, consume every original nullifier atomically, and append only the final recipient outputs. Confirming successful finalization then suffices to establish its checked prerequisites. Receipt preparation itself must not consume the original notes.

Broadcast order is not an execution-order guarantee. The final transaction can fail if a prerequisite has not landed; an orchestrator needs receipt observation, an ordered bundle with explicit delivery assumptions, or bounded finalizer retries. Failed attempts consume fees but cannot partially consume a correctly atomic spend. Multiple dependent transactions can execute in the same slot, so packet count is not a universal slot-count lower bound.

Separate receipt PDAs remove one write conflict, but a common writable fee payer remains a scheduling conflict. Independent funded fee payers can remove that conflict when owner authorization remains read-only and explicit. The final tree/filter update remains serialized. Moving this authority outside Squads requires preserving the configured authority policy; merely bypassing the wrapper changes the comparator.

## Verification and compression

The current proof wire format keeps G2 uncompressed: 32-byte A, 128-byte B, and 32-byte C. The existing solana-bn254 API supports a 64-byte compressed G2 point. This saves 64 bytes per proof without a circuit or trusted-setup change, but requires instruction decoding/verifier changes and point validation. The local runtime 4.2.1 source charges 13,610 CU for G2 decompression before surrounding program overhead. Five proofs save 320 bytes for 68,050 CU of additional decompression charges.

The program already supports BSB22 commitment verification in `instructions/verifier.rs`, and the interface's `Bsb22Commitment` carries two compressed 32-byte G1 points. A GKR-backed outer proof can reuse that verifier support; it needs a matching circuit selector, key, public-input binding, and wire connection rather than a verifier written from scratch. The existing point payload is 192+64=256 bytes; compressing G2 would reduce it to 192 bytes before selector-specific metadata. Our measured packet table models vanilla proofs and is not a serialization test of the actual GKR payload.

Randomized Groth16 batch verification can combine the fixed-key pairing terms, but it retains one variable (A,B) pairing per proof. A k-proof same-key group can use k+3 pairing pairs instead of 4k, plus scalar multiplications and hashing for sound coefficients. The full transcript must bind all proofs, public inputs, keys, order, and domain. Simply multiplying equations with all coefficients equal to one is unsound because invalid equations can cancel. This is an unimplemented cryptographic optimization, not a measured speedup.

Runtime 4.2.1's pairing charges are 36,364 CU for the first pair and 12,121 per additional pair. Four independent four-pair checks cost 290,908 CU in pairing charges; a seven-pair batch costs 109,090 CU before extra scalar work. This reduces pairing charges by 181,818 CU for that group, not 10× of the complete 1.33M-CU cached spend. Native SBF execution, account creation, nullifier hashing/insertion, events, and tree updates still need measurement.

## Reproduction and isolation

The cache snapshot is `/Users/tsv/Developer/zolana/zolana-10x-settlement` on `experiment/merge/10x-settlement`; the direct snapshot is `/Users/tsv/Developer/zolana/zolana-10x-settlement-direct` on `experiment/merge/10x-settlement-direct`. They copy the prior uncommitted implementations and read their matching deployed binaries and development keys. The measured original worktrees are unchanged. This historical checkpoint is now preserved on the branches above. The final aligned comparison is on `experiment/merge/second-gkr`.

Native checks:

```sh
DEVELOPER_DIR=/Library/Developer/CommandLineTools \
CARGO_TARGET_DIR=/Users/tsv/Developer/zolana/zolana-pr320-bench/target \
cargo run --offline -j2 -p zolana-client --example settlement_wire

DEVELOPER_DIR=/Library/Developer/CommandLineTools \
CARGO_TARGET_DIR=/Users/tsv/Developer/zolana/zolana-pr320-bench/target \
cargo test --offline -j2 -p zolana-client --features solana-rpc --test solana_rpc confirmation_
```

Localnet runs must be serialized: fixture startup stops validator processes globally, even when ports differ. Execute `notes/run-fast-poll.sh cache`, then `notes/run-fast-poll.sh direct`. Both paired runs use `E2E_BENCH_INPUTS=144 E2E_BENCH_WARM_KEYS=1 PROVER_SYNC_CONCURRENCY=4 GOMAXPROCS=18 E2E_BENCH_POLL_MS=25`, fresh prover processes, the same confirmed endpoint, and recipient wallet decryption assertions. Setup deposits and key warmup stay outside spend latency; all usable spend proofs remain inside it. The direct snapshot now contains the corrected, aligned benchmark; its earlier instrumented raw log is retained only to make the correction auditable.
