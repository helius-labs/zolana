package gadget

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

const sha256MerkleTestHeight = 3

type sha256MerkleCircuit struct {
	Leaf      frontend.Variable
	PathIndex frontend.Variable
	Path      [sha256MerkleTestHeight]frontend.Variable
	Root      frontend.Variable `gnark:",public"`
}

func (c *sha256MerkleCircuit) Define(api frontend.API) error {
	index := api.ToBinary(c.PathIndex, sha256MerkleTestHeight)
	root := Sha256MerkleRoot(api, c.Leaf, index, c.Path[:])
	api.AssertIsEqual(root, c.Root)
	return nil
}

func referenceSha256Node(left, right *big.Int) *big.Int {
	var message [64]byte
	left.FillBytes(message[:32])
	right.FillBytes(message[32:])
	digest := sha256.Sum256(message[:])
	digest[0] = 0
	return new(big.Int).SetBytes(digest[:])
}

func TestSha256MerkleRootMatchesReference(t *testing.T) {
	modulus := ecc.BN254.ScalarField()
	leaf := new(big.Int).Sub(modulus, big.NewInt(1))
	path := []*big.Int{
		new(big.Int).Sub(modulus, big.NewInt(7)),
		big.NewInt(0),
		new(big.Int).Lsh(big.NewInt(1), 247),
	}
	pathIndex := uint64(0b101)

	root := new(big.Int).Set(leaf)
	for level, sibling := range path {
		if (pathIndex>>uint(level))&1 == 0 {
			root = referenceSha256Node(root, sibling)
		} else {
			root = referenceSha256Node(sibling, root)
		}
	}

	assignment := &sha256MerkleCircuit{Leaf: leaf, PathIndex: pathIndex, Root: root}
	for i := range path {
		assignment.Path[i] = path[i]
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(
		&sha256MerkleCircuit{},
		test.WithValidAssignment(assignment),
		test.WithInvalidAssignment(&sha256MerkleCircuit{
			Leaf:      leaf,
			PathIndex: pathIndex,
			Path:      assignment.Path,
			Root:      new(big.Int).Add(root, big.NewInt(1)),
		}),
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16),
		test.NoFuzzing(),
		test.NoSerializationChecks(),
	)
}
