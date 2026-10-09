package extractor_test

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

type KeyedGadget struct {
	In  frontend.Variable
	Key *big.Int
}

func (g KeyedGadget) GadgetHash() string { return "0000beef" }

func (g KeyedGadget) DefineGadget(api frontend.API) interface{} {
	return []frontend.Variable{api.Add(g.In, g.Key), 0}
}

type KeyedCircuit struct {
	In frontend.Variable
}

func (c *KeyedCircuit) Define(api frontend.API) error {
	out := abstractor.Call1(api, KeyedGadget{In: c.In, Key: big.NewInt(7)})
	api.AssertIsEqual(out[0], out[1])
	return nil
}

func TestKeyedCircuit(t *testing.T) {
	out, err := extractor.CircuitToLean(&KeyedCircuit{}, ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "def KeyedGadget_h0000beef ") {
		t.Error("GadgetHash does not name the definition")
	}
	checkOutput(t, out)
}
