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

- Circuits: `gadget.NullifierTreeHash` calls the `Poseidon2Compress` gadget
  (`prover/server/circuits/gadget/poseidon2.go`: permutation, external and
  internal round as abstractor gadgets, two-operand ops, round keys as
  arguments), used by `NullifierParentHash` / `NullifierMerkleRootGadget`
  and by `IndexedLeafHash`; the state tree keeps `ProveParentHash` /
  `MerkleRootGadget` on `PoseidonHash`. The two trees are separate gadget
  types on purpose: the Lean extractor identifies a gadget by type name and
  array lengths, so a field selecting the hash extracted one body for both
  trees. The gadget compiles to the same R1CS as gnark's std Poseidon2
  gadget (byte-identical constraint system on batch append 40×10), so the
  keys rotated on the std gadget stay valid; `TestPoseidon2CompressMatchesNative`
  checks it against gnark-crypto and pins 3 constraints per S-box.
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
- Lean (`prover/server/formal-verification`): `Circuit.lean` is the current
  extraction (CI diffs it against the circuits). `Poseidon2.lean` proves the
  extracted round gadgets, the permutation and the compression each have a
  unique assignment and defines `nullifierHash` as that value. `Merkle.lean`
  and `RangeTree.lean` state the nullifier tree lemmas over `nullifierHash`
  (`hashLevel` takes the hash as a parameter; the state tree and the hash
  chains stay over `poseidon₂`). `Main.lean` pins the `(1, 2)` vector from
  `test-vectors/tree_hash.json` with `native_decide` and axiomatizes
  collision resistance and no zero preimage for `nullifierHash`, so
  `NonInclusionCircuit.sound_and_complete` depends on exactly those two
  axioms about the hash.

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
`empty_rings_nullifier_proof_matches_init_root`.

On the rotated keys, both prover-backed suites pass: `transact_functional`
(21 tests, wallet-side reference trees -> Go prover -> on-chain Groth16) and
`prover_e2e` (8 tests, `--features test-only,verify`: 300 nullifiers in 5
batches through the forester's reference `IndexedMerkleTree<Poseidon2>` ->
Go batch-append prover -> on-chain verification, in random submission
orders).

### Formal verification

`cd prover/server/formal-verification && lake exe cache get && lake build`
passes (also the `formal-verification` workflow). Two build notes:

- The compression's unique assignment is `opaque`. The kernel ignores
  reducibility attributes, and a definitional check on `nullifierHash` that
  did not close on its arguments made it evaluate the 56-round composition
  symbolically; `Merkle.lean` ran out of memory at 40 GB. Proofs only use
  the `equiv` field and `native_decide` compiles the value, so the kernel
  never needs the body. With `opaque`, the library builds in about a minute.
- On macOS 26, dyld refuses the binaries the toolchain's bundled linker
  produces (`__DATA_CONST` without `SG_READ_ONLY`), so build in a Linux
  container, with `git` installed or lake re-clones the packages:

  ```
  docker run --rm -it -v "$PWD/prover/server/formal-verification:/fv" \
    -v zolana-elan:/root/.elan -w /fv ubuntu:24.04 bash -c '
    apt-get update -qq && apt-get install -y -qq git curl >/dev/null
    export PATH=/root/.elan/bin:$PATH
    command -v lake >/dev/null || curl -sSf https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh | sh -s -- -y --default-toolchain none
    lake exe cache get && lake build'
  ```

## Not done here

- Keys are on the Mac that rotated them and in the lockfile, not in S3.
- The Go `IndexedMerkleTree.Init` sentinel is `2^248 - 1` while the protocol
  nullifier tree uses `p - 1`; pre-existing, unchanged.
