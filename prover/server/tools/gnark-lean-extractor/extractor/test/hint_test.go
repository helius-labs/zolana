package extractor_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

func splitHint(_ *big.Int, inputs, outputs []*big.Int) error {
	for i, out := range outputs {
		out.SetUint64(uint64(inputs[0].Bit(i)))
	}
	return nil
}

func init() {
	solver.RegisterHint(splitHint)
}

type HintGadget struct {
	In frontend.Variable
}

func (g HintGadget) DefineGadget(api frontend.API) interface{} {
	bits, err := api.Compiler().NewHint(splitHint, 2, g.In)
	if err != nil {
		panic(err)
	}
	api.AssertIsEqual(api.Add(bits[0], api.Mul(bits[1], 2)), g.In)
	return bits
}

type HintCircuit struct {
	In  frontend.Variable
	Out frontend.Variable `gnark:",public"`
}

func (c *HintCircuit) Define(api frontend.API) error {
	bits, err := api.Compiler().NewHint(splitHint, 3, c.In, 7)
	if err != nil {
		return err
	}
	api.AssertIsBoolean(bits[2])
	unused, err := api.NewHint(splitHint, 1, c.Out)
	if err != nil {
		return err
	}
	_ = unused
	pair := abstractor.Call1(api, HintGadget{c.Out})
	api.AssertIsEqual(pair[1], bits[0])
	return nil
}

func TestHintCircuit(t *testing.T) {
	out, err := extractor.CircuitToLean(&HintCircuit{}, ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	checkOutput(t, out)
}
