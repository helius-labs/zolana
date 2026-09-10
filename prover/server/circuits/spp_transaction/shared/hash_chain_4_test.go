package shared_test

import (
	"fmt"
	"math/big"
	"testing"

	"zolana/prover/circuits/gadget"
	"zolana/prover/prover-test/spp/protocol"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type hashChain4Circuit struct {
	Inputs []frontend.Variable
	Hash   frontend.Variable `gnark:",public"`
}

func (c *hashChain4Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Hash, gadget.HashChain4(api, c.Inputs))
	return nil
}

func TestHashChain4GadgetMatchesHost(t *testing.T) {
	for _, length := range []int{1, 2, 3, 4, 5, 7, 8, 16, 36} {
		t.Run(fmt.Sprintf("len_%d", length), func(t *testing.T) {
			inputs := make([]*big.Int, length)
			for i := range inputs {
				inputs[i] = big.NewInt(int64(i + 1))
			}
			want, err := protocol.HashChain4(inputs)
			if err != nil {
				t.Fatal(err)
			}
			circuit := &hashChain4Circuit{Inputs: make([]frontend.Variable, length)}
			assignment := &hashChain4Circuit{Inputs: make([]frontend.Variable, length), Hash: want}
			for i, input := range inputs {
				assignment.Inputs[i] = input
			}
			assert := test.NewAssert(t)
			assert.CheckCircuit(circuit,
				test.WithValidAssignment(assignment),
				test.WithCurves(ecc.BN254),
				test.NoFuzzing(),
				test.NoSerializationChecks(),
			)
		})
	}
}

func TestHashChain4GadgetRejectsBinaryChain(t *testing.T) {
	inputs := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	binary, err := protocol.HashChain(inputs)
	if err != nil {
		t.Fatal(err)
	}
	circuit := &hashChain4Circuit{Inputs: make([]frontend.Variable, len(inputs))}
	assignment := &hashChain4Circuit{Inputs: make([]frontend.Variable, len(inputs)), Hash: binary}
	for i, input := range inputs {
		assignment.Inputs[i] = input
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(circuit,
		test.WithInvalidAssignment(assignment),
		test.WithCurves(ecc.BN254),
		test.NoFuzzing(),
		test.NoSerializationChecks(),
	)
}
