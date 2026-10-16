package ed25519

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/helius-labs/zolana/prover/server/prover-test/hintattack"
)

type canonicalPointCircuit struct{ Encoding [32]frontend.Variable }

func (v *canonicalPointCircuit) Define(api frontend.API) error {
	c := newCurve(api)
	p := c.decodeEncoding(v.Encoding)
	_, torsion := c.splitTorsion(p)
	c.assertCanonicalPrime(p, torsion)
	return nil
}

func encodeTestPoint(p hostPoint) (out [32]frontend.Variable) {
	for i := range out {
		out[i] = byte(new(big.Int).Rsh(p.y, uint(8*i)).Uint64())
	}
	out[31] = out[31].(byte) | byte(p.x.Bit(0))<<7
	return out
}

func TestCanonicalPointPolicyRejectsTorsionAndAliases(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &canonicalPointCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	check := func(p [32]frontend.Variable, want bool, opts ...solver.Option) {
		t.Helper()
		w, err := frontend.NewWitness(&canonicalPointCircuit{Encoding: p}, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		err = cs.IsSolved(w, opts...)
		if !want {
			hintattack.RequireConstraintRejection(t, err)
		} else if err != nil {
			t.Fatal(err)
		}
	}
	check(encodeTestPoint(generator()), true)
	for i, torsion := range torsionTable() {
		t.Run("small-order/"+big.NewInt(int64(i)).String(), func(t *testing.T) { check(encodeTestPoint(torsion), false) })
		if i != 0 {
			t.Run("mixed-torsion/"+big.NewInt(int64(i)).String(), func(t *testing.T) {
				encoded := encodeTestPoint(hostAdd(generator(), torsion))
				check(encoded, false)
				called := false
				forge := func(_ *big.Int, _, out []*big.Int) error { called = true; out[0].SetInt64(0); return nil }
				check(encoded, false, solver.OverrideHint(solver.GetHintID(torsionIndexHint), forge))
				if !called {
					t.Fatal("torsion hint was not exercised")
				}
			})
		}
	}
	for i := int64(0); i < 19; i++ {
		called := false
		zeroSplit := func(_ *big.Int, _, out []*big.Int) error { called = true; out[0].SetInt64(0); return nil }
		check(encodeTestPoint(hostPoint{new(big.Int), new(big.Int).Add(fieldPrime(), big.NewInt(i))}), false, solver.OverrideHint(solver.GetHintID(torsionIndexHint), zeroSplit))
		if !called {
			t.Fatal("malformed-point hint override was not exercised")
		}
	}
	negativeZero := encodeTestPoint(hostPoint{new(big.Int), big.NewInt(1)})
	negativeZero[31] = byte(128)
	check(negativeZero, false)
}

type canonicalCoreCircuit coreCircuit

func (v *canonicalCoreCircuit) Define(api frontend.API) error {
	verifyDigest(api, v.PublicKey, v.Signature, v.Digest)
	return nil
}

// These witnesses satisfy the group equation with deliberately cancelling
// torsion. Rejecting them proves the policy is stronger than the equation.
func TestCanonicalSignatureRejectsCancellingTorsion(t *testing.T) {
	strict, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &canonicalCoreCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	reference, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &coreCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for i, torsion := range torsionTable() {
		w := &canonicalCoreCircuit{}
		for j := range w.Signature {
			w.Signature[j] = 0
		}
		for j := range w.Digest {
			w.Digest[j] = 0
		}
		w.PublicKey = encodeTestPoint(hostAdd(hostMul(generator(), big.NewInt(5)), torsion))
		r := hostAdd(hostMul(generator(), big.NewInt(7)), hostNeg(hostMul(torsion, big.NewInt(3))))
		encodedR := encodeTestPoint(r)
		copy(w.Signature[:32], encodedR[:])
		w.Signature[32], w.Digest[0] = 22, 3
		wit, err := frontend.NewWitness(w, ecc.BN254.ScalarField())
		if err != nil {
			t.Fatal(err)
		}
		if err := reference.IsSolved(wit); err != nil {
			t.Fatalf("valid reference equation %d: %v", i, err)
		}
		if accepted := strict.IsSolved(wit) == nil; accepted != (i == 0) {
			t.Fatalf("torsion %d accepted=%v", i, accepted)
		}
	}
}
