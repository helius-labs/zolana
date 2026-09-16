# Next options for arbitrary existing 512-note balances

General 10× is not demonstrated. Resolve the transport measurement first, then choose a larger architectural change against the remaining bottleneck.

## Provisional limits

The earlier matched sample was **6.586 s admitted versus 17.033 s optimized PR #320**, or 2.59×. That comparator implies a 1.703 s target. The general 512-input backend alone measured **2.916 s median** across three verified proofs: unchanged, it caps improvement at 5.84× even with free remaining work. The **1.024 s H10 DAG** result only supports roots populated within their first 1,024 positions. These are implementation measurements, not impossibility bounds. [Backend scope](../prover/server/benchmarks/admitted-payment.md)

A later smoke reported 3.485 s upload, including 0.923 s allocation, and 1.146 s witness preparation. Upload and proving overlap; do not sum their durations blindly. Surfpool's default profiling repeats instruction prefixes, and its transaction loop is serial. Both harnesses now support `--disable-instruction-profiling`. Use the latest corrected pair before retaining the old comparator or target. [Diagnostic evidence](simulator-profiling.md)

## Three distinct options

**1. Reusable empty buffers: the next concrete experiment.** Allocate owner scratch space independently of any selected notes or recipient. Give PR #320 equivalent reusable empty infrastructure and report allocation-included and amortized results separately. Keep witness generation, nullifier derivation, payment-specific writes and merge proving inside the timer; end at the same recipient-observed state.

Reuse needs a session generation checked by every mutation and bound into the payment intent. Delayed signed chunks must not populate another session. Prepared-certificate IDs currently depend only on the buffer address, so they also need generation binding; payment-only reuse is the smaller first change. Closing and recreating the same PDA must not reset the counter. A complete-write bitmap permits resetting metadata without clearing all payload bytes. [Current buffer](../programs/shielded-pool/src/instructions/direct_spend/buffer.rs)

**2. Authenticated owner balance or spend epoch: simpler future payments, paid legacy import.** The registry contains keys and identity, with no balance, note-set or spend-epoch commitment. An account aggregate can replace hundreds of future inputs after authenticating their import. Revoking an entire owner-key epoch can replace per-note markers only if previous spends, omitted notes, other assets and incoming payments are handled. Every legacy route must enforce it. Publishing receipt indices adds linkage beyond the already-public owner signer. This is migration or a warm-payment design; PR #320 can also premerge before a warm timer. [Registry](../program-libs/user-registry-interface/src/state.rs)

**3. Shared authenticated lookup: the deeper generic-proof experiment.** Preprocess a cumulative snapshot of existing note commitments for a hiding lookup argument. This work is public and shared, unlike preparing one wallet's payment. It could remove private Merkle paths at arbitrary positions. A sound composition must bind lookup values to amounts, ownership and nullifiers. Our [current DAG circuit](../prover/server/circuits/direct_spend/dag_payment.go) does not implement this general protocol. Historical filter migration is also still missing.

A 32-byte nullifier-list commitment cannot replace current freshness checks. A succinct current-root spent-set transition could compress settlement, but introduces root contention, all-route migration and data-availability requirements for future witnesses. Thus linear on-chain bytes are not fundamental; deleting them safely is a different protocol. First test whether corrected transport makes the existing bytes inexpensive, while retaining the unchanged 1.4M CU limit.
