package ed25519

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/circuits/crypto/nonnative"
)

// With D=T only the final curve check binds the chord slope.
type coincidentWrongOutputCircuit struct{}

func (*coincidentWrongOutputCircuit) Define(api frontend.API) error {
	c := newCurve(api)
	p := hostMont(hostMul(generator(), big.NewInt(4)))
	t := hostMont(hostMul(generator(), big.NewInt(8)))
	r := c.quadrupleAddChecked(&montPoint{c.fp.Const(p.x), c.fp.Const(p.y)}, &montPoint{c.fp.Const(t.x), c.fp.Const(t.y)})
	c.assertMontOnCurve(c.montReduce(r))
	mod := fieldPrime()
	den := new(big.Int).Mul(big.NewInt(-3), t.x)
	den.ModInverse(den, mod)
	mu := new(big.Int).Mul(big.NewInt(2), t.y)
	mu.Mul(mu, den).Mod(mu, mod)
	wrongX := new(big.Int).Mul(mu, mu)
	wrongX.Add(wrongX, t.x).Mod(wrongX, mod)
	if wrongX.Cmp(hostMont(hostMul(generator(), big.NewInt(24))).x) == 0 {
		panic("test slope did not change output")
	}
	c.fp.AssertZeroProjected(nonnative.T(1, r.x), nonnative.T(-1, c.fp.Const(wrongX)))
	return nil
}

type coincidentSpecialCircuit struct {
	Multiple int `gnark:"-"`
}

func (v *coincidentSpecialCircuit) Define(api frontend.API) error {
	c := newCurve(api)
	p := hostMont(hostMul(generator(), big.NewInt(int64(v.Multiple))))
	t := hostMont(hostMul(generator(), big.NewInt(int64(2*v.Multiple))))
	c.quadrupleAddChecked(&montPoint{c.fp.Const(p.x), c.fp.Const(p.y)}, &montPoint{c.fp.Const(t.x), c.fp.Const(t.y)})
	return nil
}

func TestCoincidentSpecialOnCurveCandidateRejected(t *testing.T) {
	var multiple int
	var slope *big.Int
	for i := 1; i < 64; i++ {
		point := hostMont(hostMul(generator(), big.NewInt(int64(2*i))))
		x3 := new(big.Int).Mul(big.NewInt(3), point.x)
		if candidate := new(big.Int).ModSqrt(x3.Mod(x3, fieldPrime()), fieldPrime()); candidate != nil {
			tangent := ratio(fieldPrime(), montNumerator(point.x), new(big.Int).Lsh(point.y, 1))
			if candidate.Cmp(tangent) == 0 {
				candidate.Sub(fieldPrime(), candidate)
			}
			multiple, slope = i, candidate
			break
		}
	}
	if slope == nil {
		t.Fatal("no special point found")
	}
	template := &coincidentSpecialCircuit{Multiple: multiple}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, template)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(template, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.IsSolved(w); err != nil {
		t.Fatal(err)
	}
	forge := func(q *big.Int, in, out []*big.Int) error {
		return nonnative.Unwrap(q, in, out, func(_ *big.Int, _, _, values []*big.Int) error {
			values[0].Set(slope)
			return nil
		})
	}
	if err := cs.IsSolved(w, solver.OverrideHint(solver.GetHintID(montSlopeHint), forge)); err == nil {
		t.Fatal("special x2=xD branch accepted a non-tangent slope")
	}
}

func TestCoincidentWrongOutputRejected(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &coincidentWrongOutputCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(&coincidentWrongOutputCircuit{}, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	zeroSlope := func(_ *big.Int, _ []*big.Int, out []*big.Int) error {
		for _, v := range out {
			v.SetInt64(0)
		}
		return nil
	}
	if err := cs.IsSolved(w, solver.OverrideHint(solver.GetHintID(montSlopeHint), zeroSlope)); err == nil {
		t.Fatal("coincident chord accepted an off-curve wrong result")
	}
}
