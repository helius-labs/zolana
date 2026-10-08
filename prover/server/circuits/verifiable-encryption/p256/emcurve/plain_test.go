package emcurve

import (
	"crypto/elliptic"
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"zolana/prover/circuits/verifiable-encryption/p256/emcurve/emfield"
)

func forEachMode(t *testing.T, run func(t *testing.T, noLookups bool)) {
	for _, noLookups := range []bool{false, true} {
		name := "lookups"
		if noLookups {
			name = "no_lookups"
		}
		t.Run(name, func(t *testing.T) { run(t, noLookups) })
	}
}

func isTableHint(h solver.Hint) bool {
	id := solver.GetHintID(h)
	return id == solver.GetHintID(p256RowLookupHint) || id == solver.GetHintID(p256RowCountHint)
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

func TestNoLookupConstraintCounts(t *testing.T) {
	for _, row := range []struct {
		name    string
		circuit frontend.Circuit
	}{
		{"ecdh", &ecdhCircuit{NoLookups: true}},
		{"generator", &generatorCircuit{NoLookups: true}},
		{"ecdh and generator", &keyAgreementCircuit{NoLookups: true}},
		{"AgreeKey", &agreeKeyCircuit{NoLookups: true}},
	} {
		cs := compile(t, row.circuit)
		t.Logf("no lookups %-20s constraints %7d internal variables %7d", row.name, cs.GetNbConstraints(), cs.GetNbInternalVariables())
		if got := len(cs.GetCommitments().CommitmentIndexes()); got != 0 {
			t.Fatalf("%s without lookups has %d commitments", row.name, got)
		}
	}
	if got := len(compile(t, &agreeKeyCircuit{}).GetCommitments().CommitmentIndexes()); got != 1 {
		t.Fatalf("AgreeKey with lookups has %d commitments, want 1", got)
	}
}

func TestNoLookupAgreeKeyMatchesHostECDH(t *testing.T) {
	peer := peerKey(t).PublicKey()
	n := GroupOrder()
	cs := compile(t, &agreeKeyCircuit{NoLookups: true})
	for _, s := range []*big.Int{
		mergeScalar,
		big.NewInt(2),
		new(big.Int).Sub(n, big.NewInt(2)),
		new(big.Int).Add(big.NewInt(0x1234_5678), n),
	} {
		w := agreeKeyWitness(t, s, peer)
		if err := test.IsSolved(&agreeKeyCircuit{NoLookups: true}, w, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("test engine: %v", err)
		}
		if err := solveAgreeKey(t, cs, w); err != nil {
			t.Fatalf("compiled: %v", err)
		}
	}
}

func TestNoLookupCircuitsHaveNoTableHints(t *testing.T) {
	c := &agreeKeyCircuit{NoLookups: true}
	if reflect.TypeOf(c).Elem().Field(0).Tag.Get("gnark") != "-" {
		t.Fatal("the mode flag must stay out of the witness")
	}
	cs := compile(t, c)
	w := agreeKeyWitness(t, mergeScalar, peerKey(t).PublicKey())
	poisoned := func(_ *big.Int, _, _ []*big.Int) error {
		t.Fatal("a lookup-table hint ran in the no-lookup circuit")
		return nil
	}
	if err := solveAgreeKey(t, cs, w,
		solver.OverrideHint(solver.GetHintID(p256RowLookupHint), poisoned),
		solver.OverrideHint(solver.GetHintID(p256RowCountHint), poisoned),
	); err != nil {
		t.Fatal(err)
	}
}
