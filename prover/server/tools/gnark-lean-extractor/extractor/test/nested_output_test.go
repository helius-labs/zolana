package extractor_test

import (
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

type PairGadget struct {
	A, B frontend.Variable
}

func (g PairGadget) DefineGadget(api frontend.API) interface{} {
	sum := api.Add(g.A, g.B)
	product := api.Mul(g.A, g.B)
	return [][]frontend.Variable{{sum, product}, {product, sum}}
}

type SingletonGadget struct {
	A frontend.Variable
}

func (g SingletonGadget) DefineGadget(api frontend.API) interface{} {
	return []frontend.Variable{api.Mul(g.A, g.A)}
}

type NestedOutputCircuit struct {
	A, B frontend.Variable
}

func (c *NestedOutputCircuit) Define(api frontend.API) error {
	single := abstractor.Call1(api, SingletonGadget{A: c.A})
	api.AssertIsEqual(single[0], c.B)
	out := abstractor.Call2(api, PairGadget{A: c.A, B: c.B})
	api.AssertIsEqual(out[0][1], out[1][0])
	api.AssertIsEqual(api.Add(out[0][0], out[1][1], out[0][1]), 0)
	return nil
}

func TestNestedOutputCircuit(t *testing.T) {
	out, err := extractor.CircuitToLean(&NestedOutputCircuit{}, ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Gates.eq gate_2[0][1] gate_2[1][0]") {
		t.Error("nested gadget outputs lost their inner index")
	}
	checkOutput(t, out)
}
