# Two-phase operator queue

Design for the operator batch rail: enqueue transact entries into a queue
account, verify them in one RLC, then apply them in slices. The packet limit
stops bounding the batch size, which unlocks the fold ratios at N=8 and N=16
(the verify leg alone drops 64% to 69% against solo verifies).

Supersedes the queue sketch in the internal design notes: the RLC verifier
exists (`zolana-groth16-batch` over the agave fold), tags 52 and 53 are taken
by the packet-bound batch instructions, and the eddsa authorization question
is resolved below.

## Status

Implemented and measured (2026-07-29, `just bench-batch-dual`). Both duals
clear the 10% gate, so the path is recommended for operators:

| N | Legacy CU | Two-phase total | Saved | Hot path (execute plus applies) | Hot saved |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 8 | 1233588 | 892955 | 27.6% | 750369 | 39.2% |
| 16 | 2468036 | 1720717 | 30.3% | 1436520 | 41.8% |

The total includes create, N enqueues, and close. The hot path is the CU on
the contended tree accounts. Execute at N=8 and above needs a 256 KB heap
frame (`ComputeBudgetInstruction::request_heap_frame`), the fold exceeds the
default 32 KB program heap.

## The instruction set (tags 54 to 58)

One state struct, four instructions, all additive. A queue binds one operator
and one circuit shape and moves through three stages: filling, verified,
applied.

**`BatchQueue` account** (`state/batch_queue.rs`). Operator-owned, created
with the program as owner in the same transaction, capped at 16 entries
(about 27 KB): discriminator, stage, count, apply cursor, the allow-dummy
flag captured at verify, circuit, operator address, and fixed entry slots.
Each slot stores the exact `TransactIxData` bytes, the decompressed
fold-ready proof (256 bytes, `a` un-negated), and the input owner hashes the
enqueue signer checks produced. The per-proof decompression cost lands in the
CU-idle enqueue transaction.

**`CreateBatchQueue` (54).** Accounts: payer (signer), operator (signer),
queue (writable). Data: the circuit as variant, inputs, outputs, and public
slots. Standard Groth16 shapes only.

**`EnqueueTransact` (55).** Accounts: operator (signer), queue (writable),
then extra entry signers. Data: one transact payload, the same bytes
`Transact` takes. Entry signer index 0 is the operator and indexes 2 and up
map past the queue account, which matches the solo layout where index 0 is
the payer. The processor checks the operator, the shape, the Inline owner
tags, and expiry, runs the input-signer checks, decompresses the proof, and
appends the entry. It rejects a full queue and a queue past the filling
stage. Measured cost: about 18k CU per entry.

**`ExecuteBatchVerify` (56).** Accounts: operator (signer), queue (writable),
input tree, output tree. Derives every entry's `public_input_hash` exactly as
`BatchTransact` does, with the payer bound to the operator and the input
owner hashes read from the queue, folds all proofs in one RLC, captures the
allow-dummy flag, and sets the stage to verified. Nothing mutates the trees.

**`ApplyBatch` (57).** Accounts: operator (signer, writable), queue
(writable), trees, the system program, and the shielded pool program for the
event self-CPI. Requires the verified stage and the unchanged allow-dummy
flag, so the batch fails closed when the tree crossed the dummy threshold
between verify and apply. Applies up to four entries per call through the
same tree and event code path `BatchTransact` uses. Events are byte-identical
to `Transact` events, so photon needs only the source-tag allowlist entry.

**`CloseBatchQueue` (58).** Operator signer plus a dedicated rent recipient.
Allowed at the applied stage or on an empty queue.

## Authorization at enqueue

The eddsa rail authorizes a spend by the input owner signing the transaction.
At execute time the user is absent, so the signature check cannot move there.
The P256 rail carries ownership inside the circuit but uses BSB22, which the
batch fold rejects.

Resolution: the users co-sign the enqueue transaction. `EnqueueTransact` runs
the same input-signer checks `Transact` runs, against the enqueue accounts.
The queue then holds the payload immutably, so the recorded authorization
covers exactly the bytes that verify and apply later. The operator cannot
alter an entry after enqueue without failing the fold.

## Restrictions

- Pure shielded entries only. No settlement legs, so the apply account list
  stays fixed.
- Owner tags must be `Inline`. An `Account` tag indexes a transaction account
  list that no longer exists at apply time.
- One circuit shape per queue, standard Groth16 only. BSB22 stays on solo
  verify.
- Every entry proof binds the operator as the payer. The operator pays the
  forester fees at apply. Delegated-proving clients already know who relays
  for them.

## Staleness window

Entries pin tree roots by root-history index at enqueue. Execute re-derives
the public inputs against the live root history, so an entry stays valid while
its pinned roots remain within the 120-slot history. An operator that fills
and executes within that window never hits the edge. A stale entry fails the
fold and the queue closes without applying.

## What it buys

Measured in the status table above. Bytes do not improve: payloads land on
chain either way, plus rent per queue slot, reclaimable on close.

## Test coverage

`program-tests/shielded-pool/tests/batch_dual_cu.rs`: the lifecycle test
covers the stage gates, the missing-signer rejection, apply parity with the
solo state transitions, and close with rent return. The ignored dual measures
N=8 and N=16. Photon parser tests cover the apply-batch source tag.
