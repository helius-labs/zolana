// Tested invariants and diagnostics:
//
//  1. The distinct-x guard rejects coordinates equal modulo the curve prime.
//  2. The ladder output guard rejects a zero second slope and every integer
//     representative of a zero slope sum, and accepts equal nonzero slopes.
//  3. Forged rational decompositions and multiplication results from the regression
//     report are rejected.
//  4. Valid point addition accepts x-coordinates differing by the BN254 modulus.
package emcurve

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"strings"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

// Invariant 1: The distinct-x guard rejects coordinates equal modulo the curve prime.
func TestDistinctXGuard(t *testing.T) {
	n := emfield.LookupLayout.NbLimbs
	cs := compile(t, &distinctXCircuit{P: make([]frontend.Variable, n), Q: make([]frontend.Variable, n)})
	p := emulated.P256Fp{}.Modulus()
	x := big.NewInt(0x1234_5678)
	for _, row := range []struct {
		name   string
		p, q   *big.Int
		accept bool
	}{
		{"distinct", x, big.NewInt(0x1234_5679), true},
		{"equal", x, x, false},
		{"equal modulo p", x, new(big.Int).Add(x, p), false},
		{"equal modulo p swapped", new(big.Int).Add(x, p), x, false},
	} {
		witness, err := frontend.NewWitness(&distinctXCircuit{P: fieldLimbValues(row.p), Q: fieldLimbValues(row.q)}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); (err == nil) != row.accept {
			t.Fatalf("%s: accept=%v err=%v", row.name, row.accept, err)
		}
	}
}

// Invariant 2: The ladder output guard rejects every zero of mu*(mu+2*lambda) modulo p.
func TestLadderOutputGuard(t *testing.T) {
	solver.RegisterHint(identityHint)
	cs := compile(t, &ladderOutputGuardCircuit{})
	p := elliptic.P256().Params().P
	x := new(big.Int).Sub(p, big.NewInt(0x1234_5678))
	third := new(big.Int).Div(p, big.NewInt(3))
	thirdRemainder := new(big.Int).Sub(p, new(big.Int).Lsh(third, 1))
	for _, row := range []struct {
		name          string
		chord, second *big.Int
		accept        bool
	}{
		{"distinct", x, big.NewInt(0x1234_5679), true},
		{"equal nonzero", big.NewInt(7), big.NewInt(7), true},
		{"zero second slope", big.NewInt(7), big.NewInt(0), false},
		{"zero sum", big.NewInt(7), new(big.Int).Sub(p, big.NewInt(14)), false},
		{"zero sum modulo p", new(big.Int).Sub(p, big.NewInt(7)), big.NewInt(14), false},
		{"sum integer p", third, thirdRemainder, false},
		{"sum integer minus p", new(big.Int).Sub(p, third), new(big.Int).Sub(p, thirdRemainder), false},
		{"zero both", big.NewInt(0), big.NewInt(0), false},
	} {
		w := &ladderOutputGuardCircuit{ChordSlope: plainLimbValues(row.chord), SecondSlope: plainLimbValues(row.second)}
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); (err == nil) != row.accept {
			t.Fatalf("%s: accept=%v err=%v", row.name, row.accept, err)
		}
		if err := test.IsSolved(&ladderOutputGuardCircuit{}, w, ecc.BN254.ScalarField()); (err == nil) != row.accept {
			t.Fatalf("test engine %s: accept=%v err=%v", row.name, row.accept, err)
		}
	}
}

// Invariant 3: Forged rational decompositions and multiplication results from the regression report are rejected.
func TestUnconstrainedHintInScalarMulFakeGLVReportIsRejected(t *testing.T) {
	offCurveX := new(big.Int).SetBytes([]byte("an x nobody can recompute later!"))
	onCurvePeer, onCurveX := sameYCurvePoint(t)
	honestPeer := peerKey(t).PublicKey()
	honestX := new(big.Int).SetBytes(honestPeer.Bytes()[1:33])
	ecdhCS := compile(t, &ecdhCircuit{})
	agreeCS := compile(t, &agreeKeyCircuit{})
	for _, row := range []struct {
		name string
		peer *ecdh.PublicKey
		x    *big.Int
	}{
		{"off-curve result", peerKey(t).PublicKey(), offCurveX},
		{"on-curve result sharing the mirrored y", onCurvePeer, onCurveX},
		{"honest result with the forged decomposition", honestPeer, honestX},
	} {
		t.Run("ECDH "+row.name, func(t *testing.T) {
			if solveUnderAttack(t, ecdhCS, ecdhAttackWitness(row.peer, row.x), row.x) == nil {
				t.Fatal("forged shared secret accepted")
			}
		})
		t.Run("AgreeKey "+row.name, func(t *testing.T) {
			if solveUnderAttack(t, agreeCS, agreeKeyAttackWitness(t, row.peer, row.x), row.x) == nil {
				t.Fatal("forged shared secret accepted")
			}
		})
	}
}

// Invariant 4: Valid point addition accepts x-coordinates differing by the BN254 modulus.
func TestPointAdditionAcceptsNativeModulusXDifference(t *testing.T) {
	params := elliptic.P256().Params()
	sqrt := func(x *big.Int) *big.Int {
		r := new(big.Int).Exp(x, big.NewInt(3), params.P)
		r.Sub(r, new(big.Int).Mul(big.NewInt(3), x)).Add(r, params.B).Mod(r, params.P)
		return new(big.Int).ModSqrt(r, params.P)
	}
	var px, py, qx, qy *big.Int
	for i := int64(0); i < 1000; i++ {
		px = big.NewInt(i)
		qx = new(big.Int).Add(px, ecc.BN254.ScalarField())
		py, qy = sqrt(px), sqrt(qx)
		if py != nil && qy != nil {
			break
		}
	}
	if py == nil || qy == nil {
		t.Fatal("no collision points found")
	}
	x, y := elliptic.P256().Add(px, py, qx, qy)
	t.Logf("valid unequal x coordinates: %s and %s", px, qx)
	cs := compile(t, &pointAdditionCircuit{})
	w := &pointAdditionCircuit{PX: plainLimbValues(px), PY: plainLimbValues(py), QX: plainLimbValues(qx), QY: plainLimbValues(qy), X: plainLimbValues(x), Y: plainLimbValues(y)}
	assertCircuitResult(t, cs, w, true)
	// Control: doubling the same valid point succeeds.
	x, y = elliptic.P256().Double(px, py)
	w.QX, w.QY, w.X, w.Y = w.PX, w.PY, plainLimbValues(x), plainLimbValues(y)
	assertCircuitResult(t, cs, w, true)
	x, y = elliptic.P256().Add(px, py, qx, qy)
}

// Test circuits and shared helpers.

var alternatingHalfScalar, _ = new(big.Int).SetString(strings.Repeat("55", 16), 16)

func equalHalvesDecompositionHint(_ *big.Int, _, outputs []*big.Int) error {
	outputs[0].SetUint64(0)
	for i := 0; i < halfScalarBits; i++ {
		bit := uint64(alternatingHalfScalar.Bit(i))
		outputs[1+i].SetUint64(bit)
		outputs[1+halfScalarBits+i].SetUint64(bit)
	}
	return nil
}

func mirroredResultHint(x *big.Int) solver.Hint {
	return func(q *big.Int, inputs, outputs []*big.Int) error {
		return emfield.Unwrap(q, inputs, outputs, func(p *big.Int, _, in, out []*big.Int) error {
			out[0].Set(x)
			out[1].Sub(p, in[1])
			return nil
		})
	}
}

func mirroredResultAttack(x *big.Int) []solver.Option {
	return []solver.Option{
		solver.OverrideHint(solver.GetHintID(p256DecomposeScalarHint), equalHalvesDecompositionHint),
		solver.OverrideHint(solver.GetHintID(p256ScalarMulHint), mirroredResultHint(x)),
	}
}

func sameYCurvePoint(t *testing.T) (*ecdh.PublicKey, *big.Int) {
	t.Helper()
	p := elliptic.P256().Params().P
	for i := byte(1); i < 255; i++ {
		seed := make([]byte, 32)
		seed[31] = i
		key, err := ecdh.P256().NewPrivateKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		x := new(big.Int).SetBytes(key.PublicKey().Bytes()[1:33])
		disc := new(big.Int).Mul(x, x)
		disc.Mul(disc, big.NewInt(-3)).Add(disc, big.NewInt(12)).Mod(disc, p)
		root := new(big.Int).ModSqrt(disc, p)
		if root == nil {
			continue
		}
		other := new(big.Int).Sub(root, x)
		other.Mul(other, new(big.Int).ModInverse(big.NewInt(2), p)).Mod(other, p)
		return key.PublicKey(), other
	}
	t.Fatal("no key whose y is shared by another curve point")
	return nil, nil
}

func ecdhAttackWitness(peer *ecdh.PublicKey, x *big.Int) *ecdhCircuit {
	var w ecdhCircuit
	setBytes(w.Scalar[:], new(big.Int).Sub(GroupOrder(), big.NewInt(1)).FillBytes(make([]byte, 32)))
	setBytes(w.PublicKey[:], peer.Bytes())
	setBytes(w.Shared[:], x.FillBytes(make([]byte, 32)))
	return &w
}

func agreeKeyAttackWitness(t *testing.T, peer *ecdh.PublicKey, x *big.Int) *agreeKeyCircuit {
	t.Helper()
	w := agreeKeyWitness(t, new(big.Int).Sub(GroupOrder(), big.NewInt(1)), peer)
	lo, hi := packBytes(x.FillBytes(make([]byte, 32)))
	w.Expected[4], w.Expected[5] = lo, hi
	return w
}

func solveUnderAttack(t *testing.T, cs constraint.ConstraintSystem, assignment frontend.Circuit, x *big.Int) error {
	t.Helper()
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	err = cs.IsSolved(witness, mirroredResultAttack(x)...)
	if err != nil && !strings.Contains(err.Error(), "is not satisfied") {
		t.Fatalf("expected a constraint failure, got: %v", err)
	}
	return err
}

type distinctXCircuit struct {
	P, Q []frontend.Variable
}

func (c *distinctXCircuit) Define(api frontend.API) error {
	cv := newCurve(api)
	cv.assertDistinctX(cv.fp.FromLimbs(c.P), cv.fp.FromLimbs(c.Q))
	return nil
}

type ladderOutputGuardCircuit struct {
	ChordSlope, SecondSlope [8]frontend.Variable
}

func (c *ladderOutputGuardCircuit) Define(api frontend.API) error {
	cv := newCurve(api)
	chordSlope := cv.fp.HintBalanced(identityHint, 1, nil, cv.fp.FromLimbs(c.ChordSlope[:]))[0]
	secondSlope := cv.fp.HintBalanced(identityHint, 1, nil, cv.fp.FromLimbs(c.SecondSlope[:]))[0]
	cv.assertLadderOutputDistinct(chordSlope, secondSlope)
	return nil
}

func identityHint(q *big.Int, inputs, outputs []*big.Int) error {
	return emfield.Unwrap(q, inputs, outputs, func(_ *big.Int, _, in, out []*big.Int) error {
		out[0].Set(in[0])
		return nil
	})
}

func plainLimbValues(v *big.Int) (out [8]frontend.Variable) {
	for i := range out {
		out[i] = new(big.Int).And(new(big.Int).Rsh(v, uint(32*i)), big.NewInt(0xffffffff))
	}
	return out
}

type pointAdditionCircuit struct {
	PX, PY, QX, QY, X, Y [8]frontend.Variable
}

func (c *pointAdditionCircuit) Define(api frontend.API) error {
	cv := newCurve(api)
	p := &point{cv.fp.FromLimbs(c.PX[:]), cv.fp.FromLimbs(c.PY[:])}
	q := &point{cv.fp.FromLimbs(c.QX[:]), cv.fp.FromLimbs(c.QY[:])}
	cv.assertOnCurve(p)
	cv.assertOnCurve(q)
	r := cv.completeAdd(p, q)
	cv.assertEqual(r, &point{cv.fp.FromLimbs(c.X[:]), cv.fp.FromLimbs(c.Y[:])})
	return nil
}
