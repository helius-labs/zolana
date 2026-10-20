package nonnative

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

// Limbwise canonical checks enforce the strict modulus bound.
func TestAssertCanonicalComparesLimbwise(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &plainCanonicalCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("canonical check over range-checked limbs: %d constraints", cs.GetNbConstraints())
	p := edProjectionPrime
	values := []*big.Int{
		big.NewInt(0),
		new(big.Int).Sub(p, big.NewInt(1)),
		p,
		new(big.Int).Add(p, big.NewInt(1)),
		new(big.Int).Sub(pow2(255), big.NewInt(1)),
		new(big.Int).Sub(new(big.Int).Sub(pow2(255), big.NewInt(1)), pow2(43)),
		new(big.Int).Sub(p, pow2(43)),
		new(big.Int).Sub(pow2(255), pow2(254)),
	}
	for i := 0; i < 32; i++ {
		v, _ := rand.Int(rand.Reader, pow2(255))
		values = append(values, v)
	}
	for _, v := range values {
		w := &plainCanonicalCircuit{Limbs: edLimbs(v)}
		witness, _ := frontend.NewWitness(w, ecc.BN254.ScalarField())
		accept := v.Cmp(p) < 0
		if err := cs.IsSolved(witness); (err == nil) != accept {
			t.Fatalf("value %x: accept=%v err=%v", v, accept, err)
		}
		if err := test.IsSolved(&plainCanonicalCircuit{}, w, ecc.BN254.ScalarField()); (err == nil) != accept {
			t.Fatalf("test engine value %x: accept=%v err=%v", v, accept, err)
		}
	}
}

// The fallback modulus-gap check rejects a forged gap.
func TestCanonicalModulusGapRejectsForgery(t *testing.T) {
	q := ecc.BN254.ScalarField()
	cs, err := frontend.Compile(q, r1cs.NewBuilder, &nativeGapCircuit{Modulus: q})
	if err != nil {
		t.Fatal(err)
	}
	forged := solver.OverrideHint(solver.GetHintID(modulusGapHint), func(_ *big.Int, inputs, outputs []*big.Int) error {
		widths := edProjectionLayout.reducedWidths(q.BitLen())
		rest := edProjectionLayout.writePieces(outputs, new(big.Int).Sub(pow2(q.BitLen()), big.NewInt(1)), widths)
		rest[0].SetUint64(1)
		return nil
	})
	expectRejected(t, cs, &nativeGapCircuit{Modulus: q, Value: edLimbs(q)}, forged)
}

type plainCanonicalCircuit struct {
	Limbs [6]frontend.Variable
}

func (c *plainCanonicalCircuit) Define(api frontend.API) error {
	f := NewFor(api, edProjectionPrime, edProjectionLayout)
	f.AssertCanonical(fromLimbs(f, c.Limbs[:]))
	return nil
}
