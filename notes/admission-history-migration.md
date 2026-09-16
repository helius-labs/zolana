# Authenticated migration of historical nullifiers

This is a protocol design, not implemented functionality. Existing spent trees can be migrated without a new circuit or a privileged assertion that an uploaded history is complete. The simplest version freezes the tree, authenticates every physical indexed leaf and every queued value, then activates the filter atomically. It is linear in lifetime history and can impose hours of downtime with a serial uploader. An online variant is a separate follow-up.

## What the existing state authenticates

At a frozen checkpoint define `R = latest nullifier root`, `N = next_index`, and `Q = queue_next_index`. Real indexed nullifiers occupy exactly `[1,N)` and queued, unapplied nullifiers occupy `[N,Q)`. Leaf zero is the initial sentinel; it is not a spent nullifier. The queue assigns the eventual physical leaf index at insertion.

An indexed leaf hashes **`Poseidon(value, next_value)`**. `value` is the complete canonical 32-byte nullifier, not a truncated tag or an additional digest. Its position is insertion order and remains fixed; subsequent insertions may change `next_value`. `next_index` is off-chain ordering metadata and is not hashed, so traversing claimed successor pointers cannot prove complete coverage. Enumerate physical indices instead. Use the snapshot root's current tuple at each index, not the tuple originally inserted.

Evidence: `program-libs/indexed-array/src/array.rs::IndexedElement::hash`; `prover/server/circuits/nullifier_tree.go::Define`; `services/photon/src/ingester/persist/indexed_merkle_tree/helpers.rs`; `program-libs/tree/src/nullifier_tree/{layout,queue_insert}.rs`.

Production uses height 40 and the full BN254 `p-1` upper sentinel. Some old Go/reference constructors still default to a 248-bit sentinel; do not reuse that initialization for migration. The authenticated live root, production Photon helper and explicitly configured Rust reference tree are the relevant sources.

## Frozen migration

1. Allocate the filter and any needed compact pending table before pausing, through new staging instructions reusing the existing allocator. The existing enable instructions must not be used to bypass their genesis/drained-queue checks. Beginning migration atomically pauses the tree and records its full pubkey, tree id, current mode, `R`, root-history slot and sequence, `N`, `Q`, and a migration id. Store a strict import cursor initially one. No negative admission is allowed during migration. Block unpause while migration is active; snapshot equality at finalization is additional protection, not a substitute for this guard.
2. Import contiguous indexed leaves against `R`. A page carries `(value,next_value)` tuples for `[cursor,cursor+k)` plus an authenticated path. Restrict `k` to an aligned power of two, at most 256, so verification is a simple subtree reduction and upper path. Derive orientation from the cursor; reject gaps, overlaps, out-of-range positions, wrong path length and trailing payload bytes. Verify the complete page before changing bits or advancing the cursor. Starting at index one needs a few initial small pages before alignment permits full-size pages.
3. At cursor `N`, import the remaining queue in exact sequence order, using the frozen queue commitments described below. Every successful page advances coverage. For a legacy individual-PDA tree, also insert authenticated queued values into its new pending table with their original queue sequence. That table remains inactive until cutover.
4. Finalize only when coverage reaches exactly `Q`, the tree remains frozen at the same checkpoint, the filter/account configuration is unchanged, and any legacy pending import is complete. Atomically set filter coverage to `Q` and mode Active. Already-compact trees can preserve their existing pending table and accepted root history. For legacy-to-compact conversion, preserve only the frozen latest NF root, set `close_before_index=N`, and activate the new pending table holding `[N,Q)`. Every accepted exact-NIP root then contains all indexed history, while the table covers everything not indexed. Old pending proofs may need a fresh NF witness after this root-history reset. The UTXO tree is unchanged.

The current compact-enable method intentionally requires `N==Q`, because it installs an empty pending table. Do not weaken that check globally. Migration needs a distinct finalized transition whose authenticated queued import justifies enabling a nonempty table. The current `Off -> Active` genesis-only filter transition also remains unchanged outside this new path.

A dedicated verified-history import receipt should authorize bitmap insertion during migration. Do not relabel historical membership as `exact_verified=true` in the ordinary spend API, whose contract requires non-inclusion and current pending admission. All migration bits, cursors and account mode changes must roll back together on error. An aborted inactive migration may discard its staged filter; it must preserve the original guards and must never reset an Active/Retired filter.

Current pause also blocks the forester through `TreeAccount::from_account_view_mut` in `batch_update_nullifier_tree.rs`. That is compatible with the frozen protocol: no queue draining is required. Admin fee changes do not change the committed spent set. No route may unpause or mutate that set during the import.

## Authenticating complete and partial queued batches

The two queue batches each retain one `HashChain4` commitment per ZKP batch. Applied slots are cleared, but their values are already covered by `[1,N)`. Map every unapplied sequence to the correct physical batch and ZKP slot using stored `start_index`, full/inserted counts and configured batch size. Snapshot and validate that these ranges cover `[N,Q)` without gaps or overlap.

For a complete ZKP batch, require exactly the configured 10 or 250 values and recompute its stored chain. The supported lengths are `1 mod 3`, so there is no padded terminal group. A full 250-value page contains 8,000 bytes of nullifiers and uses 83 four-input Poseidon calls for its commitment check.

For the open partial batch let `m` be its actual number of values and, when `m>0`, let `p=(m-1) mod 3`. The stored chain covers the first `m-p` values; the last `p` values are stored separately in `pending_values`. Recompute the absorbed prefix and compare every live tail value. Bind `m` from account metadata, never caller metadata. When `m=0`, ignore unused/stale tail slots. Hashing the entire partial list with zero padding and comparing only the chain is not equivalent to the stored representation. New read-only production accessors for this commitment/tail tuple are needed; the present `pending_values()` accessor is test-only.

Evidence: `program-libs/tree/src/nullifier_tree/batch.rs::{add_to_hash_chain,num_pending,get_num_inserted_elements}` and `merkle_tree_update.rs::{verify_proof_cache_update,clear_cached_tree_update}`.

## Reuse the existing upload buffer

The direct-spend buffer already stores opaque, owner-bound bytes with sequential append offsets, a 24,000-byte limit, a consumed status, and owner rent refund. Its write instruction does not deserialize a financial payload. Reuse this mechanism and PDA allocation rather than introducing a second uploader.

Expose the existing byte upload/chunk helper behind the typed `upload_spend` builder and share raw owned-buffer validation. A migration consumer decodes a distinct versioned page containing the migration PDA/id, snapshot binding, start index and proof data; it requires a complete unconsumed buffer and marks it consumed atomically with the import. It must not interpret a payment/certificate payload as a history page. The existing `SpendUpload` proof-prefix/suffix split adds no benefit because a migration page is known in full before upload. A separate buffer per page can reuse the same implementation; close it after consumption.

With the existing 800-byte write chunks, a 256-leaf page needs about 22 write instructions. The account allocator's current growth path handles its roughly 17.5KB payload. A 512-leaf tuple page does not fit the 24KB buffer. These are raw-size estimates; packet packing needs exact signed serialization before choosing transaction counts.

## Cost and operational limits

For an aligned `k`-leaf page, raw tuple/path bytes are `64k + 32(40-log2(k))`, before page metadata. Verification uses `k` leaf hashes, `k-1` subtree hashes and `40-log2(k)` path hashes. The inspected Agave schedule charges `61*n²+542` CU for an `n`-input Poseidon call, hence 786 CU for two inputs. Keccak probes add the previously derived 128-CU syscall subtotal per nullifier.

| Leaves/page | Raw tuple + path bytes | Poseidon calls | Hash-syscall CU subtotal |
|---:|---:|---:|---:|
| 32 | 3,168 | 98 | 81,124 |
| 256 | 17,408 | 543 | 459,566 |
| 512 | 33,760 | 1,054 | 893,980 |

These are source-derived lower subtotals, not measured import CU. They exclude bitmap probes, canonical checks, decoding, state writes, allocation and upload transactions. A 256-leaf page has substantial space below 1.4M for those costs, but requires an SBF test. A 32-leaf inline page might fit a 4KB transaction with suitable metadata; that needs a wire test.

One million historical values need roughly 3,907 pages at 256 leaves plus boundary pages, about 68MB of tuple/path payload, and roughly 1.80 billion hash-syscall CU. With 800-byte writes this is approximately 86,000 write instructions plus page creation/consumption/closing. Packing four writes per v1 transaction suggests roughly six upload transactions plus a consumption transaction per page; at an illustrative 0.4 seconds per serial confirmation, that alone is about three hours. This is an operational model, not a localnet measurement. Parallel buffer upload and pipelined imports help, but all imports and live spends share writable tree/filter locks. A freeze must not be advertised as a quick 10× migration.

Filter allocation remains 410 growth calls and about 29.19 SOL of rent-exempt capital for 4MiB. A new default pending table is about 5MiB when converting the 25,000-element legacy queue. Existing compact trees already paid that cost. At one million spent nullifiers the 12-probe filter's modeled 512-input fallback rate is 0.02794%; at two million it is 14.96%; at four million it is essentially certain. Migrating a saturated tree does not deliver the fast path. Storage sizing, exact fallback and irreversible retirement remain necessary.

## Online follow-up

For an already-compact tree, begin atomically with a stored immutable snapshot `(R,N,Q)` and copies of all relevant queue commitments, counters and live partial tails. Root-history indices and mutable queue slots are insufficient: roots expire and forester updates clear/reuse slots. Preserve an indexer snapshot/export capable of producing proofs against `R`; current Photon helpers generally read current nodes, so historical availability must be implemented explicitly.

Use a distinct Migrating state with two cursors: historical import coverage starting at one, and live exact-spend coverage starting at `Q`. Every accepted live spend remains on the ordinary NIP-plus-pending path and atomically ORs its full nullifiers into the filter, advancing only the live cursor. Authenticated imports OR older values into the same bitmap and advance only the historical cursor. No negative spend is allowed yet. This requires migration-specific coverage handling; the current one-cursor filter header cannot silently claim the missing prefix is covered.

Activation checks historical coverage equals the snapshot `Q` and live coverage equals the tree's current `queue_next_index`, then atomically changes to Active. The union covers every spent value, even if the snapshot root has expired from ordinary proof history. Current pending and exact-NIP safeguards remain unchanged. Importers and spenders contend on the same filter account, so online migration exchanges downtime for sustained write load.

Online legacy-PDA conversion requires an additional pending-table transition, not just the two Bloom cursors. One possible extension mirrors every live spend into a shadow pending table while legacy PDAs remain authoritative, imports snapshot queued values still at/above the live `next_index`, and reclaims shadow entries below that live indexed boundary. At finalization, require complete snapshot import and uninterrupted live mirroring, retain only the latest NF root, and switch to the shadow table atomically. Every then-unprocessed value must be present. This needs dedicated coverage invariants and tests; it is not part of the minimal frozen protocol.

Before shipping either form: test altered tuple/sibling/root, skipped/overlapping page, reordered/omitted queue value, all partial-tail lengths, both queue batches, cached-but-unapplied updates, aborted migrations, unauthorized unpause, exact root-history reset behavior, and replay after real forester pruning. The migration must complete on a populated legacy tree and preserve old note commitments. No measured current payment result includes this work.
