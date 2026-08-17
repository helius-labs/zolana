package gadget

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	iden3 "github.com/iden3/go-iden3-crypto/poseidon"
)

type fieldHasherCircuit struct {
	In  []frontend.Variable
	Out frontend.Variable
}

func (c *fieldHasherCircuit) Define(api frontend.API) error {
	hasher := NewPoseidonFieldHasher(api)
	for _, in := range c.In {
		hasher.Write(in)
	}
	api.AssertIsEqual(hasher.Sum(), c.Out)
	return nil
}

// The five writes eddsa performs must hash exactly like the host Poseidon over
// the same five values, otherwise no host-produced signature can verify.
func TestPoseidonFieldHasherMatchesHostPoseidon(t *testing.T) {
	values := []*big.Int{big.NewInt(11), big.NewInt(22), big.NewInt(33), big.NewInt(44), big.NewInt(55)}
	expected, err := iden3.Hash(values)
	if err != nil {
		t.Fatalf("host poseidon: %v", err)
	}

	assignment := &fieldHasherCircuit{In: make([]frontend.Variable, len(values)), Out: expected}
	for i, value := range values {
		assignment.In[i] = value
	}
	circuit := &fieldHasherCircuit{In: make([]frontend.Variable, len(values))}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("hasher does not match host poseidon: %v", err)
	}
}

type fieldHasherResetCircuit struct {
	Discarded []frontend.Variable
	Kept      []frontend.Variable
	Out       frontend.Variable
}

func (c *fieldHasherResetCircuit) Define(api frontend.API) error {
	hasher := NewPoseidonFieldHasher(api)
	hasher.Write(c.Discarded...)
	hasher.Reset()
	hasher.Write(c.Kept...)
	api.AssertIsEqual(hasher.Sum(), c.Out)
	return nil
}

// Reset must drop everything written before it. A hasher reused across input
// slots without a working Reset would silently hash a growing prefix.
func TestPoseidonFieldHasherReset(t *testing.T) {
	kept := []*big.Int{big.NewInt(7), big.NewInt(8)}
	expected, err := iden3.Hash(kept)
	if err != nil {
		t.Fatalf("host poseidon: %v", err)
	}

	assignment := &fieldHasherResetCircuit{
		Discarded: []frontend.Variable{big.NewInt(1), big.NewInt(2), big.NewInt(3)},
		Kept:      []frontend.Variable{kept[0], kept[1]},
		Out:       expected,
	}
	circuit := &fieldHasherResetCircuit{
		Discarded: make([]frontend.Variable, 3),
		Kept:      make([]frontend.Variable, 2),
	}
	if err := test.IsSolved(circuit, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("reset did not clear the buffer: %v", err)
	}
}
