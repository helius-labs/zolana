package extractor_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

type OpaqueRange struct {
	V    frontend.Variable
	Bits int
}

func (OpaqueRange) DefineGadget(frontend.API) interface{} { panic("extraction-only") }
func (OpaqueRange) OpaqueOutputs() int                    { return 0 }

type OpaqueRow struct {
	Rows  [][]frontend.Variable
	Index frontend.Variable
}

func (OpaqueRow) DefineGadget(frontend.API) interface{} { panic("extraction-only") }
func (OpaqueRow) OpaqueOutputs() int                    { return 3 }

type OpaqueEntry struct {
	Index frontend.Variable
}

func (OpaqueEntry) DefineGadget(frontend.API) interface{} { panic("extraction-only") }
func (OpaqueEntry) OpaqueOutputs() int                    { return 1 }

type OpaqueCircuit struct {
	Rows  [2][3]frontend.Variable
	Index frontend.Variable
}

func (c *OpaqueCircuit) Define(api frontend.API) error {
	if !abstractor.Extracting(api) {
		panic("expected the extractor")
	}
	abstractor.CallVoid(api, OpaqueRange{V: c.Index, Bits: 1})
	abstractor.CallVoid(api, OpaqueRange{V: c.Rows[0][1], Bits: 11})
	rows := [][]frontend.Variable{c.Rows[0][:], c.Rows[1][:]}
	row := abstractor.Call1(api, OpaqueRow{Rows: rows, Index: c.Index})
	entry := abstractor.Call(api, OpaqueEntry{Index: row[2]})
	again := abstractor.Call(api, OpaqueEntry{Index: entry})
	api.AssertIsEqual(again, row[0])
	return nil
}

func TestOpaqueCircuit(t *testing.T) {
	out, err := extractor.CircuitToLean(&OpaqueCircuit{}, ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	checkOutput(t, out)
}
