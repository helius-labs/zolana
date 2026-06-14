package nullifiertreetest

import (
	"light/light-prover/prover/nullifier_tree"
	"math/big"
	"testing"

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
