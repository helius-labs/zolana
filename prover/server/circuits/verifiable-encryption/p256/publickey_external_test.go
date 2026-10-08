// Tested invariants (shared with publickey_test.go):
//
//  1. Public-key derivation reduces scalars modulo the group order and rejects zero
//     residues.
//  2. Self-agreement matches host ECDH, including edge scalars, and rejects an altered
//     shared x-coordinate.
//  3. Self-agreement reduces scalars modulo the group order and rejects zero residues at
//     the order boundaries.
//  4. Self-agreement scalar inputs are constrained to bytes, including under forged
//     range-check hints.
//  5. Self-agreement rejects forged scalar-multiplication reports and mutated hints.
package p256_test

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/verifiable-encryption/p256"
	"zolana/prover/prover-test/hintattack"
	"zolana/prover/prover-test/hosttest"
)

// Invariant 2: Self-agreement matches host ECDH, including edge scalars, and rejects an altered shared x-coordinate.
func TestSelfAgreeKeyMatchesHostAtEdgeCases(t *testing.T) {
	start := time.Now()
	cs := p256.Compile(t, &p256.SelfAgreementCircuit{})
	scalars := hosttest.EdgeCaseScalars()
	for _, s := range scalars {
		t.Run(s.Name, func(t *testing.T) {
			p256.CheckSelfAgreement(t, cs, s.Name, s.Scalar)
		})
	}
	t.Logf("%d edge scalars in %v", len(scalars), time.Since(start))
}

// Invariant 3: Self-agreement reduces scalars modulo the group order and rejects zero residues at the order boundaries.
func TestSelfAgreeKeyBoundaryScalarAtGroupOrder(t *testing.T) {
	cs := p256.Compile(t, &p256.SelfAgreementCircuit{})
	t.Run("group order", func(t *testing.T) {
		w := selfAgreementWitness(t, scalarBytes(elliptic.P256().Params().N), nil)
		hintattack.RequireConstraintRejection(t, p256.SolveAgreement(t, cs, w))
	})
	for _, row := range orderBoundaryScalars() {
		t.Run(row.name, func(t *testing.T) {
			if err := p256.SolveAgreement(t, cs, selfAgreementWitness(t, scalarBytes(row.raw), row.reduced)); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

// Invariant 4: Self-agreement scalar inputs are constrained to bytes, including under forged range-check hints.
func TestSelfAgreeKeyBoundaryScalarByteRangeCheck(t *testing.T) {
	requireRangeChecks(t, p256.Compile(t, &p256.SelfAgreementCircuit{}),
		func() frontend.Circuit { return selfAgreementWitness(t, scalarBytes(boundaryScalar), boundaryScalar) },
		func(w frontend.Circuit) []frontend.Variable { return w.(*p256.SelfAgreementCircuit).Scalar[:] },
		[]carriedByte{{"scalar byte 5", 5}, {"scalar byte 29", 29}},
	)
}

// Test circuits and shared helpers.

func selfAgreementWitness(t *testing.T, scalar []byte, reduced *big.Int) *p256.SelfAgreementCircuit {
	t.Helper()
	var w p256.SelfAgreementCircuit
	assignBytes(w.Scalar[:], scalar)
	shared := make([]byte, 32)
	public := [33]byte{0x02}
	if reduced != nil {
		key, err := ecdh.P256().NewPrivateKey(scalarBytes(reduced))
		if err != nil {
			t.Fatalf("private key: %v", err)
		}
		if shared, err = key.ECDH(key.PublicKey()); err != nil {
			t.Fatalf("ecdh: %v", err)
		}
		public = hosttest.CompressP256(key.PublicKey().Bytes())
	}
	assignBytes(w.SharedX[:], shared)
	assignBytes(w.PublicKey[:], public[:])
	return &w
}
