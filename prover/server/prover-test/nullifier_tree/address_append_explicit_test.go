package nullifiertreetest

import (
	"math/big"
	"testing"
	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover/nullifier_tree"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"
)

// The Light AddressV2 tree is height 40, batch size 10, and this circuit
// range-checks inserted values to 248 bits. Replay an explicit batch of
// 248-bit values through the witness builder and assert the circuit is
// satisfied — this is the Go-side gate that the witness matches the circuit
// before we prove it with the committed key and submit it on-chain.
func TestBuildAddressAppendParamsFromExplicitValues(t *testing.T) {
	const height, batch = 40, 10
	values := make([]*big.Int, batch)
	for i := range values {
		// Distinct, increasing, comfortably inside (0, 2^248-1).
		values[i] = new(big.Int).Lsh(big.NewInt(int64(i)+1), 200)
	}

	params, err := BuildAddressAppendParamsFromValues(height, values, 1)
	if err != nil {
		t.Fatalf("build params: %v", err)
	}
	if params.BatchSize != batch || params.TreeHeight != height {
		t.Fatalf("shape: got %d/%d", params.BatchSize, params.TreeHeight)
	}
	if params.NewRoot.Cmp(params.OldRoot) == 0 {
		t.Fatal("new root must differ from old root")
	}

	witness, err := params.CreateWitness()
	if err != nil {
		t.Fatalf("create witness: %v", err)
	}
	circuit := nullifiertree.InitBatchAddressTreeAppendCircuit(height, batch)
	if err := test.IsSolved(&circuit, witness, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("circuit not satisfied by explicit-value witness: %v", err)
	}
}

func TestBuildNullifierAppendParamsFromFullFieldSentinel(t *testing.T) {
	const height, batch = 40, 10
	tree, err := protocol.NewNullifierTree()
	if err != nil {
		t.Fatalf("new nullifier tree: %v", err)
	}

	params := &nullifiertree.BatchAddressAppendParameters{
		StartIndex:           tree.NextIndex(),
		TreeHeight:           height,
		BatchSize:            batch,
		OldRoot:              tree.Root(),
		LowElementValues:     make([]big.Int, batch),
		LowElementIndices:    make([]big.Int, batch),
		LowElementNextValues: make([]big.Int, batch),
		NewElementValues:     make([]big.Int, batch),
		LowElementProofs:     make([][]big.Int, batch),
		NewElementProofs:     make([][]big.Int, batch),
	}

	for i := uint32(0); i < batch; i++ {
		value := big.NewInt(int64(1000 + i))
		witness, err := tree.InsertWithWitness(value, height)
		if err != nil {
			t.Fatalf("insert witness %d: %v", i, err)
		}
		params.LowElementValues[i].Set(witness.LowValue)
		params.LowElementIndices[i].SetUint64(witness.LowIndex)
		params.LowElementNextValues[i].Set(witness.NextValue)
		params.NewElementValues[i].Set(value)
		params.LowElementProofs[i] = copyBigInts(witness.LowElementProof)
		params.NewElementProofs[i] = copyBigInts(witness.NewElementProof)
	}

	params.NewRoot = tree.Root()
	params.HashchainHash = computeNewElementsHashChain(params.NewElementValues)
	params.PublicInputHash = computePublicInputHash(
		params.OldRoot,
		params.NewRoot,
		params.HashchainHash,
		params.StartIndex,
	)

	assignment, err := params.CreateWitness()
	if err != nil {
		t.Fatalf("create witness: %v", err)
	}
	circuit := nullifiertree.InitBatchAddressTreeAppendCircuit(height, batch)
	if err := test.IsSolved(&circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("circuit not satisfied by nullifier-tree witness: %v", err)
	}
}

func copyBigInts(values []*big.Int) []big.Int {
	out := make([]big.Int, len(values))
	for i, value := range values {
		out[i].Set(value)
	}
	return out
}
