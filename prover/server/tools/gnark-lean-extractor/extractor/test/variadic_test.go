package extractor_test

import (
	"regexp"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/extractor"
)

type VariadicCircuit struct {
	A, B, C, D frontend.Variable
}

func (c *VariadicCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Add(c.A, c.B, c.C), api.Add(c.A, c.B, c.C, c.D))
	api.AssertIsEqual(api.Sub(c.A, c.B, c.C), api.Sub(c.A, c.B, c.C, c.D))
	api.AssertIsEqual(api.Mul(c.A, c.B, c.C), api.Mul(c.A, c.B, c.C, c.D))
	return nil
}

var selfBinding = regexp.MustCompile(`(?m)∃(gate_\d+|_ignored_), (\S+) = Gates\.\w+ .*`)

func TestVariadicCircuit(t *testing.T) {
	out, err := extractor.CircuitToLean(&VariadicCircuit{}, ecc.BN254)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range selfBinding.FindAllStringSubmatch(out, -1) {
		rhs := m[0][len("∃"+m[1]+", "+m[2]+" = "):]
		if regexp.MustCompile(`(^|[^\w])` + regexp.QuoteMeta(m[1]) + `([^\w]|$)`).MatchString(rhs) {
			t.Errorf("binder refers to itself: %s", m[0])
		}
	}
	checkOutput(t, out)
}
