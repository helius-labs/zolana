// Tested invariants and diagnostics:
//
//  1. The distinct-x guard rejects coordinates equal modulo the curve prime.
//  2. The distinct-slope guard rejects equal or negated slopes.
//  3. Forged rational decompositions and multiplication results from the regression
//     report are rejected.
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

// Invariant 2: The distinct-slope guard rejects equal or negated slopes.
func TestDistinctSlopeGuard(t *testing.T) {
	solver.RegisterHint(identityHint)
	cs := compile(t, &distinctSlopeCircuit{})
	p := elliptic.P256().Params().P
	x := new(big.Int).Sub(p, big.NewInt(0x1234_5678))
	for _, row := range []struct {
		name   string
		a, b   *big.Int
		accept bool
	}{
		{"distinct", x, big.NewInt(0x1234_5679), true},
		{"equal", x, x, false},
		{"negated", x, new(big.Int).Sub(p, x), false},
		{"small equal", big.NewInt(7), big.NewInt(7), false},
		{"small negated", big.NewInt(7), new(big.Int).Sub(p, big.NewInt(7)), false},
		{"zero", big.NewInt(0), big.NewInt(0), false},
	} {
		w := &distinctSlopeCircuit{A: plainLimbValues(row.a), B: plainLimbValues(row.b)}
		witness, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := cs.IsSolved(witness); (err == nil) != row.accept {
			t.Fatalf("%s: accept=%v err=%v", row.name, row.accept, err)
		}
		if err := test.IsSolved(&distinctSlopeCircuit{}, w, ecc.BN254.ScalarField()); (err == nil) != row.accept {
			t.Fatalf("test engine %s: accept=%v err=%v", row.name, row.accept, err)
		}
	}
}

// Invariant 3: Forged rational decompositions and multiplication results from the regression report are rejected.
func TestUnconstrainedHintInScalarMulFakeGLVReportIsRejected(t *testing.T) {
	forEachMode(t, func(t *testing.T, noLookups bool) {
		offCurveX := new(big.Int).SetBytes([]byte("an x nobody can recompute later!"))
		onCurvePeer, onCurveX := sameYCurvePoint(t)
		honestPeer := peerKey(t).PublicKey()
		honestX := new(big.Int).SetBytes(honestPeer.Bytes()[1:33])
		ecdhCS := compile(t, &ecdhCircuit{NoLookups: noLookups})
		agreeCS := compile(t, &agreeKeyCircuit{NoLookups: noLookups})
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
	})
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

type distinctSlopeCircuit struct {
	A, B [8]frontend.Variable
}

func (c *distinctSlopeCircuit) Define(api frontend.API) error {
	cv := newCurveFor(api, false)
	a := cv.fp.HintBalanced(identityHint, 1, nil, cv.fp.FromLimbs(c.A[:]))[0]
	b := cv.fp.HintBalanced(identityHint, 1, nil, cv.fp.FromLimbs(c.B[:]))[0]
	cv.assertDistinctSlope(a, cv.nativeValue(b))
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
