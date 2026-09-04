<!-- cargo-rdme start -->

# zolana-tree

The shielded pool's tree account. A single Solana account holds both trees
the pool maintains, cast in place as one `TreeAccountLayout`: an
append-only UTXO state tree of height 32, and a batched indexed nullifier
tree of height 40 with its input queue.

| Module | Description |
|--------|-------------|
| `smt` | `UtxoTreeLayout`, the append-only state tree |
| `nullifier_tree` | The batched indexed nullifier tree and its input queue |
| `error` | `TreeError`, the account-level error type |

## Loading

`TreeAccount` is the loader for both subtrees. It checks program
ownership, the discriminator, and the pause flag, then returns `&mut`
access to `TreeAccount::utxo_tree` or `TreeAccount::nullifier_tree`.
Under the `account-view` feature it also loads straight from a pinocchio
`AccountView`: `from_account_view_mut` rejects a paused tree, which freezes
the write paths, and `pause_tree` loads through
`from_account_view_mut_allow_paused` so it can unpause.

## State tree

`smt::UtxoTreeLayout` appends output commitments one leaf at a time and
keeps a cyclic root history of `smt::ROOT_HISTORY_CAPACITY` roots for
validity proofs. Its height is pinned to `UTXO_TREE_HEIGHT`, and
`TreeAccount::init` rejects any other value.

## Nullifier tree

`nullifier_tree` is an indexed Merkle tree with an integrated input
queue. Spent-note nullifiers are queued instead of being applied a leaf at
a time, and a queued batch is applied to the tree with a Groth16 proof that
the values append correctly. A per-nullifier PDA
(`zolana_interface::state::NullifierPda`) records the queue index a value
reserved, and rejects a second insertion of the same nullifier while it is
pending. `nullifier_tree_spec.md` is the normative description of queue
insertion, batch append, and PDA cleanup.

Both trees are sized by const generics, so the account is one zero-copy
cast and `TreeAccount::account_size` is the length the allocator must
use.

## Features

Nothing is on by default: deserializing a tree account out of bytes needs
neither a Solana runtime nor a proof verifier, and a client that only reads
the account should not link one.

| Feature | Adds | Pulls in |
|---------|------|----------|
| `account-view` | `TreeAccount::from_account_view_mut` and its allow-paused twin | `pinocchio` |
| `verify` | `nullifier_tree::verify` and `NullifierTreeLayout::update_tree_from_address_queue` | `groth16-solana` |

`TreeAccount::from_bytes`, `TreeAccount::init`, both subtree layouts
and `nullifier_tree::proof::CompressedProof` are always available, so
indexers and foresters build a batch update without a verifier.

## Testing

`just test-tree` runs every test that needs no prover.

The nullifier-tree suite drives the layout through byte slices, so all of
it except `tests/nullifier_tree/init_roots.rs` is gated on the `test-only`
feature. That feature also relaxes the height-40 check in
`nullifier_tree::init`, letting tests build small trees;
`TreeAccount::init` still rejects any height but 40, and the
shielded-pool build leaves `test-only` off. The `prover_e2e` module
additionally needs a prover at `ZOLANA_PROVER_URL`.

<!-- cargo-rdme end -->
