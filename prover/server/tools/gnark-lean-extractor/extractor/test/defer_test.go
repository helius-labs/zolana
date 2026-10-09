package extractor_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

type DeferCircuit struct {
	In  frontend.Variable
	ran *bool
}

func (c *DeferCircuit) Define(api frontend.API) error {
	api.Compiler().Defer(func(api frontend.API) error {
		*c.ran = true
		api.AssertIsEqual(c.In, 2)
		return nil
	})
	api.AssertIsEqual(c.In, 1)
	return nil
}

func TestDeferCircuit(t *testing.T) {
	ran := false
	out, err := extractor.CircuitToLean(&DeferCircuit{ran: &ran}, ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	if ran {
		t.Fatal("deferred callback ran during extraction")
	}
	checkOutput(t, out)
}
