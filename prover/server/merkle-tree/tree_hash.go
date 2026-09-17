package merkle_tree

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// Poseidon2 over BN254, width 2, 6 full and 50 partial rounds; the same
// parameters as `gadget.NullifierTreeHash` in the circuits.
const (
	TreeHashWidth         = 2
	TreeHashFullRounds    = 6
	TreeHashPartialRounds = 50
)

var treeHashPermutation = poseidon2.NewPermutation(TreeHashWidth, TreeHashFullRounds, TreeHashPartialRounds)

// TreeHash is the 2-to-1 hash of the nullifier tree, its nodes and its
// indexed leaves: `perm(left, right)[1] + right`. Inputs must be canonical
// field elements. The trees in this package are nullifier trees; the state
// tree stays Poseidon.
func TreeHash(left, right *big.Int) *big.Int {
	var x [2]fr.Element
	x[0].SetBigInt(left)
	x[1].SetBigInt(right)
	if x[0].BigInt(new(big.Int)).Cmp(left) != 0 || x[1].BigInt(new(big.Int)).Cmp(right) != 0 {
		panic("tree hash input is not a canonical field element")
	}
	res := x[1]
	if err := treeHashPermutation.Permutation(x[:]); err != nil {
		panic(err)
	}
	res.Add(&res, &x[1])
	return res.BigInt(new(big.Int))
}

// TreeHashBytes is TreeHash over 32-byte big-endian encodings.
func TreeHashBytes(left, right [32]byte) [32]byte {
	out := TreeHash(new(big.Int).SetBytes(left[:]), new(big.Int).SetBytes(right[:]))
	var b [32]byte
	out.FillBytes(b[:])
	return b
}

// ZeroNodes returns the empty subtree hashes for levels 0..height:
// level 0 is the zero leaf, level i is TreeHash(z[i-1], z[i-1]).
func ZeroNodes(height int) [][32]byte {
	nodes := make([][32]byte, height+1)
	for i := 1; i <= height; i++ {
		nodes[i] = TreeHashBytes(nodes[i-1], nodes[i-1])
	}
	return nodes
}
