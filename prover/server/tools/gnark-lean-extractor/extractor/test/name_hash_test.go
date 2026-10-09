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

type ScaleGadget struct {
	In     frontend.Variable
	Factor *big.Int
	Limits []*big.Int
	Square bool
	Width  int
	cache  *big.Int
}

func (g ScaleGadget) DefineGadget(api frontend.API) interface{} {
	out := api.Mul(g.In, g.Factor)
	if g.Square {
		out = api.Mul(out, out)
	}
	return out
}

type ScaleCircuit struct {
	In frontend.Variable
}

func (c *ScaleCircuit) Define(api frontend.API) error {
	limits := []*big.Int{big.NewInt(1), big.NewInt(2)}
	a := abstractor.Call(api, ScaleGadget{In: c.In, Factor: big.NewInt(3), Limits: limits, Width: 4})
	b := abstractor.Call(api, ScaleGadget{In: a, Factor: big.NewInt(5), Limits: limits, Width: 4, cache: big.NewInt(9)})
	d := abstractor.Call(api, ScaleGadget{In: b, Factor: big.NewInt(5), Limits: limits, Width: 4})
	e := abstractor.Call(api, ScaleGadget{In: d, Factor: big.NewInt(5), Limits: limits, Square: true, Width: 4})
	api.AssertIsEqual(e, 0)
	return nil
}

func TestScaleCircuit(t *testing.T) {
	out, err := extractor.CircuitToLean(&ScaleCircuit{}, ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	limits := []*big.Int{big.NewInt(1), big.NewInt(2)}
	for _, g := range []ScaleGadget{
		{Factor: big.NewInt(3), Limits: limits},
		{Factor: big.NewInt(5), Limits: limits},
		{Factor: big.NewInt(5), Limits: limits, Square: true},
	} {
		name := "def ScaleGadget_4_h" + abstractor.ParamHash(g) + " "
		if strings.Count(out, name) != 1 {
			t.Errorf("want one definition %q", name)
		}
	}
	if n := strings.Count(out, "def ScaleGadget_"); n != 3 {
		t.Errorf("got %d ScaleGadget definitions, want 3", n)
	}
	checkOutput(t, out)
}

type LabelGadget struct {
	In    frontend.Variable
	Label string
}

func (g LabelGadget) DefineGadget(api frontend.API) interface{} {
	return api.Add(g.In, len(g.Label))
}

type LabelCircuit struct {
	In frontend.Variable
}

func (c *LabelCircuit) Define(api frontend.API) error {
	abstractor.Call(api, LabelGadget{In: c.In, Label: "a"})
	return nil
}

func TestStringFieldPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("a string gadget field must not be extracted")
		}
	}()
	_, _ = extractor.CircuitToLean(&LabelCircuit{}, ecc.BN254)
}

func TestParamHashEncoding(t *testing.T) {
	type params struct {
		V      frontend.Variable
		Bound  *big.Int
		Rows   [][]int
		Unused *big.Int
		hidden string
	}
	got := abstractor.ParamHash(params{Bound: big.NewInt(-7), Rows: [][]int{{1, 2}, {3}}})
	if len(got) != 8 {
		t.Fatalf("hash %q is not 8 hex digits", got)
	}
	if got != abstractor.ParamHash(&params{Bound: big.NewInt(-7), Rows: [][]int{{1, 2}, {3}}, hidden: "x"}) {
		t.Error("hash depends on unexported fields or pointer indirection")
	}
	if got == abstractor.ParamHash(params{Bound: big.NewInt(7), Rows: [][]int{{1, 2}, {3}}}) {
		t.Error("hash ignores the sign of a big integer")
	}
	if abstractor.ParamHash(struct{ V frontend.Variable }{}) != "" {
		t.Error("a gadget without parameters must not be hashed")
	}
}
