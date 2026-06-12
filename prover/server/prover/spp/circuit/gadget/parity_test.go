package gadget

import (
	"math/big"
	"math/rand"
	"testing"

	"light/light-prover/prover/spp/internal/spptest"
	"light/light-prover/prover/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type parityCircuit struct {
	Leaf         frontend.Variable
	PathElements []frontend.Variable
	PathIndex    frontend.Variable

	HashChainInputs []frontend.Variable

	IndexedValue     frontend.Variable
	IndexedNextValue frontend.Variable

	ExpectedMerkleRoot frontend.Variable `gnark:",public"`
	ExpectedHashChain  frontend.Variable `gnark:",public"`
	ExpectedIndexed    frontend.Variable `gnark:",public"`
}

func (c *parityCircuit) Define(api frontend.API) error {
	pathIndexBits := api.ToBinary(c.PathIndex, len(c.PathElements))
	api.AssertIsEqual(c.ExpectedMerkleRoot, MerkleRoot(api, c.Leaf, c.PathElements, pathIndexBits))
	api.AssertIsEqual(c.ExpectedHashChain, HashChain(api, c.HashChainInputs))
	api.AssertIsEqual(c.ExpectedIndexed, IndexedLeafHash(api, c.IndexedValue, c.IndexedNextValue))
	return nil
}

func TestGadgetsMatchNativeProtocol(t *testing.T) {
	assert := test.NewAssert(t)
	rng := rand.New(rand.NewSource(1))

	for i := 0; i < 8; i++ {
		leaf := spptest.RandomField(rng)
		pathElements := spptest.RandomFields(rng, 5)
		pathIndex := uint64(rng.Intn(1 << uint(len(pathElements))))
		hashChainInputs := spptest.RandomFields(rng, 4)
		indexedValue := spptest.RandomField(rng)
		indexedNextValue := spptest.RandomField(rng)

		merkleRoot, err := protocol.MerkleRoot(leaf, pathElements, pathIndex)
		if err != nil {
			t.Fatalf("native Merkle root: %v", err)
		}
		hashChain, err := protocol.HashChain(hashChainInputs)
		if err != nil {
			t.Fatalf("native hash chain: %v", err)
		}
		indexed := spptest.MustPoseidon(t, 3, []*big.Int{indexedValue, indexedNextValue})

		circuit := &parityCircuit{
			PathElements:    make([]frontend.Variable, len(pathElements)),
			HashChainInputs: make([]frontend.Variable, len(hashChainInputs)),
		}
		assignment := &parityCircuit{
			Leaf:               leaf,
			PathElements:       spptest.ToVariables(pathElements),
			PathIndex:          new(big.Int).SetUint64(pathIndex),
			HashChainInputs:    spptest.ToVariables(hashChainInputs),
			IndexedValue:       indexedValue,
			IndexedNextValue:   indexedNextValue,
			ExpectedMerkleRoot: merkleRoot,
			ExpectedHashChain:  hashChain,
			ExpectedIndexed:    indexed,
		}

		assert.SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
	}
}
