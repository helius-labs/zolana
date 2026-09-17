# Poseidon2 nullifier tree hash

Branch `experiment/tree/poseidon2`, forked from `main`.

## Result

The nullifier tree (40 levels, indexed) hashes its nodes and its leaves
`H(value, next_value)` with Poseidon2. The state tree stays on Poseidon.
Everything else (note hashes, nullifier derivation, hash chains, the
public-input hash) is unchanged.

| circuit | Poseidon | Poseidon2 nullifier tree | change |
|---|---|---|---|
| transfer confidential 2×3 | 54,912 | 50,484 | −8% |
| transfer ring 2×3 | 55,017 | 50,589 | −8% |
| transfer ring authority 2×2 | 52,036 | 47,608 | −9% |
| transfer p256 ring 2×3 | 199,973 | 195,545 | −2% |
| custom ring policy | 483,954 | 461,814 | −5% |
| custom ring base | 213,042 | 213,042 | 0 |
| merge 8×1 | 177,739 | 160,027 | −10% |
| batch address append 40×10 | 421,991 | 333,971 | −21% |
| batch address append 40×250 | ≈10,546,000 | ≈8,346,000 | −21% |

The batch append circuit is linear in the batch size, 33,382 constraints
per element with Poseidon2 (measured at 10 and 50) against 42,184 with
Poseidon; the 40×250 row is that model, the key itself is 2.69 GB.

One 2-to-1 hash is 186 R1CS constraints instead of 241. In R1CS the cost is
the number of S-boxes (62 against 81); the linear layer is free for both
hashes. A larger saving needs a different proof system, not a different
hash.

## Why the state tree stays on Poseidon

The program appends to the state tree on chain, 32 hashes per leaf, through
the `sol_poseidon` syscall: 27,900 CU per append (`bench/tree/CU_BENCHMARK.md`).
There is no Poseidon2 syscall. With the state tree on Poseidon2 (commit
`3202916`), `just bench-tree` fails the first append with
`exceeded CUs meter` at the 1,400,000 CU transaction limit, so one plain-Rust
Poseidon2 append costs more than 50 Poseidon appends. Moving the state tree
would need the appends to leave the program (forester-proven batches, as the
nullifier tree already does); that is a different change.

With both trees on Poseidon2 the circuits were 47,028 / 146,203 / 333,971
constraints for transfer 2×3 / merge 8×1 / batch append; the state tree
accounts for the difference to the table above.

## What was done

Hash parameters: Poseidon2 over BN254, width 2, 6 full and 50 partial
rounds, the gnark-crypto defaults; round keys derived from the parameter
string `Poseidon2-BN254[t=2,rF=6,rP=50,d=5]`; compression
`perm(left, right)[1] + right`.

One definition per language:

- Circuits: `gadget.NullifierTreeHash`
  (`prover/server/circuits/gadget/tree_hash.go`). `ProveParentHash` and
  `MerkleRootGadget` take `NullifierTree: true` to select it; the state tree
  paths keep `PoseidonHash`. `IndexedLeafHash` and the batch-append circuit
  use it for the leaves.
- Go host: `merkletree.TreeHash` (`prover/server/merkle-tree/tree_hash.go`).
  The `merkle-tree` package only builds nullifier trees. The SPP test
  protocol has `stateNodeHash` (Poseidon) and `nullifierNodeHash`
  (Poseidon2) with `StateMerkleRoot` / `NullifierMerkleRoot`.
- Rust: `zolana_hasher::Poseidon2`, a `Hasher` for exactly two canonical
  32-byte inputs, plain Rust on every target. Used by every reference
  `IndexedMerkleTree` of the nullifier tree (forester, program tests, SDK
  indexers, benches) and by photon, where `RingsTreeKind::parent_hash` /
  `zero_hash` pick the hash per tree and `MerkleProofWithContext` carries
  the tree kind.

`light-prover tree-hash-constants` regenerates from the Go definition: the
Rust round keys (`ark_ff::MontFp!` constants, no conversion at run time),
the Rust and Go Poseidon2 zero tables (41 levels), and
`test-vectors/tree_hash.json` with compress vectors, zero nodes and the
nullifier tree init root. `NULLIFIER_TREE_INIT_ROOT_40` is checked against
the Rust reference tree and against that vector; photon's empty-tree proof
test checks the same constant.

Also on this branch: the deposit path used `Poseidon::zero_bytes()[1]` as
`Poseidon(0, 0)` and now uses `SOL_ASSET_FIELD`, so the zero tables are only
tree constants; the Go `IndexedMerkleTree.Verify` folded proofs in the wrong
direction for indices other than zero.

## Tests

```
cd prover/server && go test ./circuits/... ./prover/... ./prover-test/...
cargo test -p zolana-hasher -p zolana-tree -p zolana-merkle-tree -p photon-indexer --lib
```

Cross-implementation checks: `program-libs/hasher/tests/poseidon2.rs`
(Rust against the Go vectors), `program-libs/tree/tests/nullifier_tree/init_roots.rs`
(constant against Rust reference and Go vector), photon
`empty_rings_nullifier_proof_matches_init_root`, and after key rotation
`program-libs/tree/tests/nullifier_tree/prover_e2e.rs` (Rust reference tree
against the Go batch-append prover).

## Not done here

- Proving keys and verifying keys: every circuit with a nullifier path
  moved, so every key except `custom_ring_base` must be rotated
  (`prover/server/scripts/rotate_local_no_upload.sh`) before the proof tests
  run.
- Formal verification: `Poseidon.lean` proves the Poseidon round gadgets and
  `Circuit.lean` is extracted from the circuits; both need the Poseidon2
  gadget added.
- The Go `IndexedMerkleTree.Init` sentinel is `2^248 - 1` while the protocol
  nullifier tree uses `p - 1`; pre-existing, unchanged.
