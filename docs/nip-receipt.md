# Nullifier receipts (experiment)

Branch `experiment/merge/nip-receipt`, forked from PR #320 (`1e395f7`).

## Idea

Today a merge proof does two things per input: it proves membership of the
UTXO in the state tree (private) and it proves non-inclusion of the nullifier
in the nullifier tree (public data, but proven inside the private circuit). The
non-inclusion part is 55% of the 36-input merge circuit.

A receipt moves the non-inclusion part out of the merge:

1. The nullifiers of the UTXOs to merge are published into a receipt account.
2. One proof shows that every nullifier in the receipt is absent from the
   nullifier tree at root `R`. The program verifies it once and stores `R`.
3. Merges reference a slice of the receipt. The merge circuit proves
   membership, ownership and the output; it does not touch the nullifier tree.
   The program requires the merge's nullifier root to be `R` and the merge's
   nullifier list to be exactly the receipt slice.

Nothing else changes: pending table, nullifier queue, root history, cache and
the cached transfer are untouched. A receipt reserves nothing and can be built
by anyone holding the nullifier list.

## Protocol changes

Accounts:

- `Receipt` PDA `[b"receipt", sponsor, nonce_le]`, discriminator 8, owned by
  the pool program. Header 120 bytes (`ReceiptHeader`): `capacity`, `count`,
  `filled`, `verified`, `tree`, `nullifier_root`, `rent_sponsor`, `nonce`.
  Body: `capacity` slots of 32 bytes.
- Supported capacities: `RECEIPT_CAPACITIES` (8 now; 512 once its key is
  generated). A receipt with `count < capacity` is zero-padded.

Instructions (event tags 24–27):

- `create_receipt(nonce, capacity)` — sponsor pays rent, binds the tree.
  Idempotent for the same config.
- `upload_receipt(offset, nullifiers)` — sponsor appends a contiguous slice
  (`offset == filled`). Zero is not a nullifier. Rejected once verified.
- `verify_receipt(root_index, count, proof, commitment, pok)` — permissionless.
  Requires `count == filled`, zero padding, verifies the receipt proof against
  the tree's nullifier root at `root_index`, stores the root, sets `verified`.
- `close_receipt` — sponsor reclaims rent at any time.

Merge:

- `MergeTransactIxData.receipt_offset: Option<u16>` appended (wire length
  `272 + 32n`); `MergeTransact.receipt: Option<Pubkey>` appended read-only
  after `cache`.
- With a receipt the program checks, in this order: eddsa owner only
  (`ReceiptUnsupportedOwner`), receipt verified, same tree, slice
  `[offset, offset + n)` within `count`, slice equals `ix.nullifiers`
  (`ReceiptSliceMismatch`), and after the root-history lookup
  `receipt.nullifier_root == merge nullifier root` (`ReceiptRootMismatch`).
  Then the existing pending / queue / cache path runs unchanged.
- The proof is verified with the `merge_receipt_<n>_1` key instead of
  `merge_<n>_1`. Same public input hash.
- Ring merges reject `receipt_offset`.

Errors 7081–7093, see `ShieldedPoolError`.

## Circuits

`nullifier_receipt` (`prover/server/circuits/nullifier_receipt`), shapes 8 and
512:

- Public input: `HashChain4(domain, tree_id, root, count, HashChain4(slots))`
  with `domain = 0x4e525031`. The program recomputes it from the account.
- Per slot `i < count`: `low < nullifier < next`, `IndexedLeafHash(low, next)`
  is at `index` under `root`. Slots `>= count` are gated off; a non-zero slot
  after the first zero slot is rejected (prefix rule).
- Poseidon runs through the GKR compressor (`gadget/poseidon_gkr.go`), so the
  proof carries a BSB22 commitment; on chain it is verified with
  `verify_groth16(commitment: Some(..))`.

`merge-receipt` (`spp_merge` with `SkipNonInclusion`): the default merge
circuit with the non-inclusion block replaced by `low = next = index = 0`.
Same public input, own verifying key `merge_receipt_<n>_1`.

Constraints (gnark, BN254):

| circuit | constraints |
|---|---|
| merge 8 (today) | 177,739 |
| merge-receipt 8 | 81,683 |
| merge 36 (today) | 780,681 |
| merge-receipt 36 | 348,429 |
| nullifier-receipt 8 | 752,648 |
| nullifier-receipt 512 | 2,579,487 |

The receipt has a fixed cost of about 720k (GKR transcript) and about 3.6k per
slot. A 512 receipt covers 14 merges of 36: per merge that is 348k private
plus 184k public work (2,579k / 14) instead of 781k private. The public part
can be proven by any party and in parallel with the merges.

## Soundness

The freshness rule is the same as today. A default merge proves "nullifier not
in tree at root `R`" inside the proof, and the program then requires `R` to be
in root history and inserts the nullifier into the pending table and queue. A
receipt-backed merge proves the same statement in a different proof against
the same `R`, and the program requires:

- the receipt's stored root equals the merge's root (both are the public
  `nullifier_root` of the merge's tree slot, checked against history);
- the receipt's slice equals the merge's nullifier list, which is bound by the
  merge proof's public input hash;
- the receipt is verified (stored root came from a valid proof) and belongs to
  the same tree.

So at the moment of the merge the program knows the same fact it knows today:
each nullifier was absent at `R`, and `R` is acceptable. The gap between `R`
and now is covered by the pending table, as for every merge. A receipt cannot
be edited after verification, cannot be used with another root, and a slice is
consumed by the pending table once spent, so replaying a merge fails exactly
where a replayed default merge fails.

What a receipt does not protect: nothing new. It does not hide nullifiers
(they were public in the merge instruction already), and it does not need a
TTL: it lapses when `R` leaves root history.

## Client

- `ProverClient::prove_receipt(&ReceiptInputs)` — `ReceiptProver` builds the
  witness from non-inclusion proofs (`NonInclusionProof`) and computes the
  public input hash. `ReceiptInputs::verify_data(root_index, proof)` produces
  `VerifyReceiptData`.
- `MergeProver.receipt: Option<MergeReceiptTarget { address, offset }>` sets
  `receipt_offset`; `ProverClient::prove_merge_receipt` proves with blanked
  nullifier paths.
- Tests: `program-tests/shielded-pool/src/support/receipt.rs` builds and
  publishes receipts; `RealMergeProof::build_receipt_backed` builds the pair.

## Reproduce

Keys (Mac, ~16 GB for the 512 receipt):

```
prover/server/scripts/generate_keys_receipt.sh prover/server/proving-keys
```

This writes `merge_receipt_{8,36}_1.key`, `nullifier_receipt_{8,512}_0.key`
and their `.rs` verifying-key modules. After that: add `nullifier_receipt_512_0`
to `verifying_keys/mod.rs`, set `RECEIPT_CAPACITIES = [8, 512]`, add the arm in
`instructions/receipt/verify.rs`, re-pin `tests/vk_fingerprint.rs`.

Tests:

```
cargo test -p shielded-pool-tests --test receipt                       # contract, no proofs
cargo test -p shielded-pool-tests --features proofs --test receipt_functional -- --nocapture
```

The functional test prints `verify_receipt` and receipt-backed
`merge_transact` compute units.

Prover only:

```
cd prover/server && go test ./circuits/nullifier_receipt ./circuits/spp_merge/...
RECEIPT_COUNTS=1 go test ./circuits/nullifier_receipt -run TestReceiptConstraints -v
MERGE_COUNTS=1 go test ./circuits/spp_merge -run TestReceiptMergeConstraints -v
```

## Open items

- Generate `nullifier_receipt_512_0` and enable capacity 512; add the
  36-input receipt-backed merge test (needs capacity ≥ 36).
- Measure CU on the Mac: `verify_receipt` at 8 and 512 slots (the 512 slot
  hash chain is 511 Poseidon hashes), receipt-backed merge at 8 and 36.
- Wallet integration: who builds and pays for receipts (the wallet before a
  batch of merges, or a relayer), and receipt reuse across merges of one user.
- Ring merges could take a receipt the same way; not done here.
