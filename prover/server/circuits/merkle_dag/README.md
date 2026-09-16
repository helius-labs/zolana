# Private Merkle DAG experiment

This experiment proves membership of a hidden, salted vector of leaves in the existing depth-32 Poseidon tree. Each level contains private pairs of children. The hash of every pair must occur among the authenticated children at the level above it. Gnark's committed lookup argument keeps the routing private. The final pair hashes to the public root.

It does not require complete owned subtrees. The fixture selects distinct random positions across a `2^20` prefix, supplies pseudorandom off-path sibling commitments inside that prefix, and uses empty subtrees above it. These are synthetic membership witnesses, not a million-deposit ledger fixture. The fixed circuit hashes the same number of nodes regardless of how many incidental ancestors the selected positions share.

Measurements on the local Apple M5 Pro use native BN254 Groth16, `GOMAXPROCS=4`, resident keys, three proofs per case, and verification of every proof. Witness construction, compilation, and local experimental key setup are excluded. There is no previously prepared input proof.

| 144 private leaves, same root and vector commitment | Constraints | Median proof time |
| --- | ---: | ---: |
| Independent depth-32 paths | 1,134,289 | 4,937.931 ms |
| Depth-20 paths plus one shared upper path | 717,302 | 3,053.517 ms |
| Private DAG with lookup routing | 518,076 | 2,069.675 ms |

The DAG is 2.386x faster than independent paths and 1.475x faster than the simpler shared-prefix circuit. These are membership-only timings. They do not include ownership, amounts, nullifier derivation, spentness, outputs, transaction submission, or recipient indexing.

The level capacity is `min(input_count, 2^(prefix_height - level - 1))`, with a minimum of one. For a tree whose occupied range fits in `2^20`, this covers arbitrary scattered selections without narrowing the existing anonymity set. For a larger tree, that circuit requires the selected inputs to fit in one aligned `2^20` subtree, although its position remains private. Use height 32 to cover arbitrary positions throughout the entire tree; the sharing benefit then decreases. At 512 inputs the respective fixed budgets are 6,155 and 12,287 parent hashes, versus 16,384 independent hashes.

The 512-input compile-only results include private routing and the salted vector commitment:

| Occupied-prefix height | Independent paths | Shared prefix | Private DAG |
| --- | ---: | ---: | ---: |
| 20 | 4,033,121 | 2,543,046 | 1,583,263 |
| 32 | 4,033,121 | 4,033,121 | 3,097,903 |

At full height the constraint reduction is only 1.30x. No 512-input DAG proof time was measured. Valid and negative witness tests pass at both heights 12 and 32.

The tests reject a changed root, changed vector commitment, an invented leaf with a recomputed vector commitment, altered siblings, incorrect in-range routing, and out-of-range references. Repeated leaves deliberately pass membership: an integrated payment must reject duplicate nullifiers before consuming value.

The fixed salt is a test fixture. Production needs private random blinding and binding to the exact note/value statement. The DAG uses gnark's BSB22 commitment support. SPP already has a commitment-aware verifier for P256 circuits; integration should reuse it with a new selector, proof payload, verifying key, and the normal single-public-hash wrapper. This historical branch does not integrate the DAG proof into direct spend; the later GKR branch carries a commitment-aware payload for its own circuits. No program, production key, or deployment is modified.

Run from `prover/server`:

```sh
GOMAXPROCS=4 go test ./circuits/merkle_dag -run '^TestPrivateDAG$' -count=1 -v
GOMAXPROCS=4 GOMEMLIMIT=12GiB DAG_INPUTS=144 DAG_HEIGHT=20 go test ./circuits/merkle_dag -run '^TestProving$' -count=1 -v
```

Set `DAG_COMPILE_ONLY=1` for constraint counts without key setup or proving. Raw measurements are in [second-dag-144.log](benchmarks/second-dag-144.log).
