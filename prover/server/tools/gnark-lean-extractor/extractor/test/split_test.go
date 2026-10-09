package extractor_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

type SplitGadget struct {
	In [3]frontend.Variable
}

func (g SplitGadget) DefineGadget(api frontend.API) interface{} {
	bits, err := api.Compiler().NewHint(splitHint, 2, g.In[0])
	if err != nil {
		panic(err)
	}
	a := api.Mul(g.In[0], g.In[1])
	b := api.Add(a, g.In[2])
	c := api.Mul(b, bits[1])
	api.AssertIsBoolean(bits[0])
	d := api.Add(a, c, bits[0])
	return []frontend.Variable{d, a}
}

type SplitCircuit struct {
	In  [3]frontend.Variable
	Out frontend.Variable `gnark:",public"`
}

func (c *SplitCircuit) Define(api frontend.API) error {
	pair := abstractor.Call1(api, SplitGadget{In: c.In})
	x := api.Mul(pair[0], c.In[2])
	api.AssertIsEqual(x, c.Out)
	api.AssertIsEqual(pair[1], c.In[0])
	return nil
}

func TestSplitCircuit(t *testing.T) {
	out, err := extractor.ExtractCircuitsWith(extractor.ExportOptions{VectorGet: true, MaxBodyApps: 2}, "SplitCircuit", ecc.BN254, &SplitCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	checkOutput(t, out)
}
