// Tested invariants:
//
//  1. A final curve check alone admits an on-curve forgery of a ladder step;
//     the step's output guard rejects it.
//  2. The output guard alone admits an off-curve forgery of a ladder step; the
//     final curve check rejects it.
//  3. A ladder step whose table point equals the doubled accumulator takes the
//     tangent and returns the host product.
package emcurve

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

// Invariant 1: A final curve check alone admits an on-curve forgery; the output guard rejects it.
func TestFinalCurveCheckNeedsLadderOutputGuard(t *testing.T) {
	ax, ay, dx, dy := equalPointStep(t)
	p := elliptic.P256().Params().P
	w := ladderStepWitness(ax, ay, dx, dy, dx, new(big.Int).Sub(p, dy))
	forgery := solver.OverrideHint(solver.GetHintID(p256ImplicitChordHint), fixedLadderChord(2))
	// lambda=2 and mu=-4 satisfy both slope equations, while the result
	// is -D instead of 3D.
	if err := solveLadderStep(t, &ladderStepCircuit{OmitGuard: true}, w, forgery); err != nil {
		t.Fatalf("mutation did not expose the on-curve forgery: %v", err)
	}
	if err := solveLadderStep(t, &ladderStepCircuit{}, w, forgery); err == nil {
		t.Fatal("wrong on-curve result accepted with the output guard")
	}
}

// Invariant 2: The output guard alone admits an off-curve forgery; the final curve check rejects it.
func TestLadderOutputGuardNeedsFinalCurveCheck(t *testing.T) {
	ax, ay, dx, dy := equalPointStep(t)
	p := elliptic.P256().Params().P
	chordSlope := big.NewInt(3)
	intermediateX := new(big.Int).Sub(big.NewInt(9), new(big.Int).Lsh(dx, 1))
	secondSlope := modRatio(p, new(big.Int).Lsh(dy, 1), new(big.Int).Sub(intermediateX, dx))
	slopeSum := new(big.Int).Add(secondSlope, new(big.Int).Lsh(chordSlope, 1))
	rx := new(big.Int).Add(dx, new(big.Int).Mul(secondSlope, slopeSum))
	rx.Mod(rx, p)
	ry := new(big.Int).Mul(new(big.Int).Add(chordSlope, secondSlope), new(big.Int).Sub(rx, dx))
	ry.Sub(ry, dy).Mod(ry, p)
	if elliptic.P256().IsOnCurve(rx, ry) {
		t.Fatal("test forgery unexpectedly lies on P-256")
	}
	w := ladderStepWitness(ax, ay, dx, dy, rx, ry)
	forgery := solver.OverrideHint(solver.GetHintID(p256ImplicitChordHint), fixedLadderChord(3))
	if err := solveLadderStep(t, &ladderStepCircuit{OmitCurve: true}, w, forgery); err != nil {
		t.Fatalf("mutation did not expose the off-curve forgery: %v", err)
	}
	if err := solveLadderStep(t, &ladderStepCircuit{}, w, forgery); err == nil {
		t.Fatal("wrong off-curve result accepted with the final curve check")
	}
}

// Invariant 3: An equal-point ladder step takes the tangent.
func TestLadderStepHandlesEqualPointWithTangent(t *testing.T) {
	ax, ay, dx, dy := equalPointStep(t)
	rx, ry := elliptic.P256().ScalarMult(dx, dy, []byte{3})
	w := ladderStepWitness(ax, ay, dx, dy, rx, ry)
	if err := solveLadderStep(t, &ladderStepCircuit{}, w); err != nil {
		t.Fatalf("equal-point tangent rejected: %v", err)
	}
}

// Test circuits and shared helpers.

// omitLadderOutputGuardAPI drops the step's single native output guard.
type omitLadderOutputGuardAPI struct{ frontend.API }

func (omitLadderOutputGuardAPI) AssertIsDifferent(frontend.Variable, frontend.Variable) {}

type ladderStepCircuit struct {
	OmitGuard, OmitCurve bool `gnark:"-"`
	A, Table, Expected   [2][8]frontend.Variable
}

func (c *ladderStepCircuit) Define(api frontend.API) error {
	if c.OmitGuard {
		api = omitLadderOutputGuardAPI{api}
	}
	cv := newCurve(api)
	pointFrom := func(v [2][8]frontend.Variable) *point {
		return &point{X: cv.fp.FromLimbs(v[0][:]), Y: cv.fp.FromLimbs(v[1][:])}
	}
	accumulator, tablePoint := pointFrom(c.A), pointFrom(c.Table)
	cv.assertOnCurve(accumulator)
	cv.assertOnCurve(tablePoint)
	got := cv.quadrupleAndAddLazy(accumulator, tablePoint)
	if !c.OmitCurve {
		cv.assertOnCurve(got)
	}
	cv.assertEqual(got, pointFrom(c.Expected))
	return nil
}

func fixedLadderChord(value int64) solver.Hint {
	return func(q *big.Int, inputs, outputs []*big.Int) error {
		return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, _, out []*big.Int) error {
			out[0].Mod(big.NewInt(value), p)
			return nil
		})
	}
}

func ladderStepWitness(ax, ay, tx, ty, rx, ry *big.Int) *ladderStepCircuit {
	return &ladderStepCircuit{
		A:        [2][8]frontend.Variable{plainLimbValues(ax), plainLimbValues(ay)},
		Table:    [2][8]frontend.Variable{plainLimbValues(tx), plainLimbValues(ty)},
		Expected: [2][8]frontend.Variable{plainLimbValues(rx), plainLimbValues(ry)},
	}
}

func solveLadderStep(t *testing.T, circuit, assignment *ladderStepCircuit, opts ...solver.Option) error {
	t.Helper()
	cs := compile(t, circuit)
	w, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	return cs.IsSolved(w, opts...)
}

// equalPointStep returns A and D = 2A, where D satisfies y = 6x - 8, so a
// forged chord slope of 2 admits the second slope -4 at the table point D.
func equalPointStep(t *testing.T) (ax, ay, dx, dy *big.Int) {
	t.Helper()
	hex := func(value string) *big.Int {
		v, ok := new(big.Int).SetString(value, 16)
		if !ok {
			t.Fatal("invalid equal-point test constant")
		}
		return v
	}
	ax = hex("34566de13c261a68b139c9adce7ae70ac0ed78c5e9ef984b9d26cdfc69668df6")
	ay = hex("fbae09c7d42c740e57c128d6d3c20434d934f7ac5723b2a9529b262c7b9f5758")
	dx = hex("e390994bbc3ef0c9b811aa056a405580e59f7bb307e38e62e4cbb8631880ffd4")
	dy = hex("556397cb6979a4b55069fc207d82010561bce62d2f5556515cc652529305fef5")
	curve := elliptic.P256()
	x, y := curve.Double(ax, ay)
	if !curve.IsOnCurve(ax, ay) || x.Cmp(dx) != 0 || y.Cmp(dy) != 0 {
		t.Fatal("the equal-point test needs D = 2A on P-256")
	}
	return ax, ay, dx, dy
}
