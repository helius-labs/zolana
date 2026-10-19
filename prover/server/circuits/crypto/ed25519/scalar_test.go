package ed25519

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/circuits/crypto/nonnative"
)

type fixedBaseCircuit struct {
	Scalar, Result [32]frontend.Variable
}

func (v *fixedBaseCircuit) Define(api frontend.API) error {
	c := newCurve(api)

	var bits []frontend.Variable
	for _, b := range v.Scalar {
		bits = append(bits, api.ToBinary(b, 8)...)
	}
	for _, b := range bits[253:] {
		api.AssertIsEqual(b, 0)
	}
	s := c.fromBits(c.fr, bits[:253])
	c.fr.AssertCanonical(s)
	r := c.montBase(bits[:253])
	var outBits []frontend.Variable
	for _, b := range v.Result {
		outBits = append(outBits, api.ToBinary(b, 8)...)
	}
	y := c.fromBits(c.fp, outBits[:255])
	c.fp.AssertCanonical(y)
	c.fp.AssertZero(nonnative.T(1, r.y), nonnative.T(-1, y))
	x := c.fp.Eval(nonnative.T(1, r.x))
	c.fp.AssertCanonical(x)
	c.fp.RangeChecker().Check(api.Mul(api.Sub(x.Limbs()[0], outBits[255]), new(big.Int).ModInverse(big.NewInt(2), api.Compiler().Field())), layout.LimbBits-1)
	return nil
}
func TestFixedBaseScalarEdges(t *testing.T) {
	data, err := os.ReadFile("testdata/scalars-dalek-4.1.3.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Torsion             int `json:"torsion"`
		Key, Scalar, Result string
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &fixedBaseCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fixed-base constraints %d", cs.GetNbConstraints())
	for i, v := range vectors {
		if v.Torsion != 0 {
			continue
		}
		w := &fixedBaseCircuit{}
		for _, part := range []struct {
			dst *[32]frontend.Variable
			src string
		}{{&w.Scalar, v.Scalar}, {&w.Result, v.Result}} {
			raw, err := hex.DecodeString(part.src)
			if err != nil {
				t.Fatal(err)
			}
			for i, b := range raw {
				part.dst[i] = b
			}
		}
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); err != nil {
			t.Fatalf("vector %d torsion%d scalar%s: %v", i, v.Torsion, v.Scalar, err)
		}
	}
}
