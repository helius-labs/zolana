package gadget

import (
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type IsLessCircuit struct {
	A frontend.Variable `gnark:"public"`
	B frontend.Variable `gnark:"private"`
}

func (circuit *IsLessCircuit) Define(api frontend.API) error {
	isLess := AssertIsLess{
		A: circuit.A,
		B: circuit.B,
		N: 248,
	}
	abstractor.CallVoid(api, isLess)
	return nil
}

func TestAssertIsLess(t *testing.T) {
	limit := new(big.Int).Lsh(big.NewInt(1), 248)
	max := new(big.Int).Sub(limit, big.NewInt(1))
	maxMinusOne := new(big.Int).Sub(max, big.NewInt(1))
	value := new(big.Int)
	value.SetString("69785880290080757662711965351793407854352282886293293941974851767353317742", 10)

	testCases := []struct {
		a        *big.Int
		b        *big.Int
		expected bool
	}{
		{big.NewInt(2), big.NewInt(5), true},      // 2 < 5
		{big.NewInt(5), big.NewInt(2), false},     // 5 >= 2
		{big.NewInt(3), big.NewInt(3), false},     // 3 == 3
		{big.NewInt(0), big.NewInt(0), false},     // 0 == 0
		{big.NewInt(1), big.NewInt(1), false},     // 1 == 1
		{big.NewInt(0), big.NewInt(1), true},      // 0 < 1
		{big.NewInt(100), big.NewInt(1000), true}, // 100 < 1000
		{maxMinusOne, max, true},                  // 2^248 - 2 < 2^248 - 1
		{max, maxMinusOne, false},                 // 2^248 - 1 >= 2^248 - 2
		{max, max, false},                         // upper-bound equality
		{big.NewInt(0), max, true},                // full valid-domain span
		{value, max, true},                        // interior value < maximum
	}

	for _, tc := range testCases {
		var circuit IsLessCircuit
		if tc.expected {
			assert := test.NewAssert(t)
			assert.ProverSucceeded(&circuit, &IsLessCircuit{
				A: tc.a,
				B: tc.b,
			}, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.NoSerializationChecks())
		} else {
			assert := test.NewAssert(t)
			assert.ProverFailed(&circuit, &IsLessCircuit{
				A: tc.a,
				B: tc.b,
			}, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254), test.NoSerializationChecks())
		}
	}
}
