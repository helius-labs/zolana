package shortchecker

import (
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/circuits/verifiable-encryption/internal/emfield"
)

type finalBindingCircuit struct {
	AX, AY, TX, TY, EX, EY [6]frontend.Variable
	RemoveBinding          bool `gnark:"-"`
}

func (w *finalBindingCircuit) Define(api frontend.API) error {
	lay := emfield.Layout{NbLimbs: 6, LimbBits: 43, PieceBits: 11, Lookups: true}
	fp := emfield.NewFor(api, prime(), lay)
	a, b := coefficients(false)
	c := &curve{api: api, lay: lay, fp: fp, a: fp.Const(a), b: fp.Const(b)}
	input := &point{X: fp.FromLimbs(w.AX[:]), Y: fp.FromLimbs(w.AY[:])}
	table := &point{X: fp.FromLimbs(w.TX[:]), Y: fp.FromLimbs(w.TY[:])}
	target := &point{X: fp.FromLimbs(w.EX[:]), Y: fp.FromLimbs(w.EY[:])}
	c.assertOnCurve(input)
	c.assertOnCurve(table)
	c.assertOnCurve(target)
	output := c.quadrupleAndAddLazy(input, table)
	if !w.RemoveBinding {
		c.assertEqual(output, target)
	}
	return nil
}

// This is the equal-point off-curve branch from the ladder soundness argument.
// D=2A obeys y(D)=45*x(D)-15^3. Its forged tangent 16 leaves a nonzero curve
// residual while satisfying the step equations and the slope output guard.
// Equality to the known on-curve target must therefore close that freedom.
func TestFinalTargetEqualityRejectsOffCurveStep(t *testing.T) {
	values := []string{
		"56315937167270029707832967348571669996984168277109667346950791516854389607151",
		"44965204925558946467922949168077637337796043602109427338794541856924666118410",
		"33073570943515243142567967266963430655881332430205618055834885040878574226923",
		"40909576991733498620921214404755531348785151038745762019350026740621719709435",
		"25741911739859815003866790852896779092105958140630038510274301489400605943773",
		"25318922052309677266111348699093233291494646183488282541774807600681206261874",
	}
	nums := make([]*big.Int, len(values))
	var w finalBindingCircuit
	dest := []*[6]frontend.Variable{&w.AX, &w.AY, &w.TX, &w.TY, &w.EX, &w.EY}
	for i, v := range values {
		n, _ := new(big.Int).SetString(v, 10)
		nums[i] = new(big.Int).Set(n)
		for j := range dest[i] {
			dest[i][j] = new(big.Int).And(n, new(big.Int).Sub(pow2(43), big.NewInt(1)))
			n.Rsh(n, 43)
		}
	}
	a, b := coefficients(false)
	doubled := hostAdd(hostPoint{nums[0], nums[1]}, hostPoint{nums[0], nums[1]}, a)
	if doubled.x.Cmp(nums[2]) != 0 || doubled.y.Cmp(nums[3]) != 0 {
		t.Fatal("test does not reach equal-point chord")
	}
	z := new(big.Int).Sub(big.NewInt(256), new(big.Int).Lsh(nums[2], 1))
	mu := modRatio(prime(), new(big.Int).Lsh(nums[3], 1), new(big.Int).Sub(z, nums[2]))
	fakeX := new(big.Int).Add(nums[2], new(big.Int).Mul(mu, new(big.Int).Add(mu, big.NewInt(32))))
	fakeY := new(big.Int).Sub(new(big.Int).Mul(new(big.Int).Add(mu, big.NewInt(16)), new(big.Int).Sub(fakeX, nums[2])), nums[3])
	residual := new(big.Int).Mul(fakeY, fakeY)
	residual.Sub(residual, new(big.Int).Exp(fakeX, big.NewInt(3), prime())).Sub(residual, new(big.Int).Mul(a, fakeX)).Sub(residual, b).Mod(residual, prime())
	if residual.Sign() == 0 {
		t.Fatal("forged output is not off curve")
	}
	witness, e := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if e != nil {
		t.Fatal(e)
	}
	forge := func(q *big.Int, in, out []*big.Int) error {
		return emfield.Unwrap(q, in, out, func(_ *big.Int, _, _, o []*big.Int) error { o[0].SetInt64(16); return nil })
	}
	for _, remove := range []bool{false, true} {
		cs, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &finalBindingCircuit{RemoveBinding: remove})
		if e != nil {
			t.Fatal(e)
		}
		if e := cs.IsSolved(witness); e != nil {
			t.Fatalf("honest step: %v", e)
		}
		e = cs.IsSolved(witness, solver.OverrideHint(solver.GetHintID(shortImplicitChordHint), forge))
		if remove {
			if e != nil {
				t.Fatalf("mutation did not expose forged residual: %v", e)
			}
		} else {
			if e == nil {
				t.Fatal("accepted off-curve step")
			}
			if !strings.Contains(e.Error(), "is not satisfied") {
				t.Fatal(e)
			}
		}
	}
}
