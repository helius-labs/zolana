// Tested invariants (shared with keyagreement_test.go):
//
//  1. Honest key agreement matches host ECDH, including edge cases and valid zero-x
//     recipients.
//  2. Recipient encodings must have the correct prefix, canonical coordinates, and a
//     finite on-curve point.
//  3. Recipient and ephemeral-scalar inputs are constrained to bytes, including under
//     forged range-check hints.
//  4. Scalars reduce modulo the group order; zero residues are rejected, including at
//     order boundaries.
//  5. Field-coordinate bytes are canonical (emcurve TestLimbsBelowModulus).
//  6. Forged scalar-multiplication reports (emcurve soundness tests) and mutated hints are rejected.
//  7. Key agreement uses one Groth16 commitment with no public variables committed.
//  8. The variable-base ladder refuses the ephemeral scalars +-1, +-3 and +-1/3.
package p256_test

import (
	"crypto/ecdh"
	"crypto/elliptic"
	"math/big"
	"testing"
	"time"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/verifiable-encryption/p256"
	"zolana/prover/prover-test/hintattack"
	"zolana/prover/prover-test/hosttest"
)

// Invariant 1: Honest key agreement matches host ECDH, including edge cases and valid zero-x recipients.
func TestComputeKeyAgreementMatchesHostAtEdgeCases(t *testing.T) {
	start := time.Now()
	cs := p256.Compile(t, &p256.KeyAgreementCircuit{})
	cases := hosttest.EdgeCaseKeys()
	for _, edge := range cases {
		t.Run(edge.Name, func(t *testing.T) {
			scalar := new(big.Int).SetBytes(edge.Keys.EphemeralSecret.Bytes())
			w := p256.KeyAgreementWitness(t, scalar, edge.Keys.RecipientSecret.PublicKey())
			if hosttest.IsLadderExceptional(scalar) {
				hintattack.RequireConstraintRejection(t, p256.SolveAgreement(t, cs, w))
				return
			}
			if err := p256.SolveAgreement(t, cs, w); err != nil {
				t.Fatalf("honest witness rejected: %v", err)
			}
		})
	}
	t.Logf("%d edge cases in %v", len(cases), time.Since(start))
}

// Invariant 2: Recipient encodings must have the correct prefix, canonical coordinates, and a finite on-curve point.
func TestComputeKeyAgreementBoundaryNonCanonicalRecipient(t *testing.T) {
	cs := p256.Compile(t, &p256.KeyAgreementCircuit{})
	ephemeral := hosttest.DefaultKeys().EphemeralSecret
	for _, row := range hosttest.NonCanonicalRecipients(t) {
		t.Run(row.Name, func(t *testing.T) {
			shared := hosttest.SharedX(t, ephemeral, row.Canonical)
			if err := p256.SolveAgreement(t, cs, presentedAgreement(ephemeral, row.Canonical, shared)); err != nil {
				t.Fatalf("canonical recipient rejected: %v", err)
			}
			hintattack.RequireConstraintRejection(t, p256.SolveAgreement(t, cs, presentedAgreement(ephemeral, row.Presented, shared)))
		})
	}
}

// Invariant 2: Recipient encodings must have the correct prefix, canonical coordinates, and a finite on-curve point.
func TestComputeKeyAgreementRejectsInfinityRecipient(t *testing.T) {
	cs := p256.Compile(t, &p256.KeyAgreementCircuit{})
	n := elliptic.P256().Params().N
	recipientLo, recipientHi := hosttest.PackCompressed([33]byte{0x02})
	sharedLo, sharedHi := hosttest.PackShared([32]byte{})
	for _, row := range []struct {
		name   string
		scalar *big.Int
	}{
		{"default ephemeral", new(big.Int).SetBytes(hosttest.DefaultKeys().EphemeralSecret.Bytes())},
		{"one", big.NewInt(1)},
		{"order minus one", new(big.Int).Sub(n, big.NewInt(1))},
	} {
		t.Run(row.name, func(t *testing.T) {
			keys := hosttest.NewKeys(big.NewInt(1), row.scalar)
			ephemeralLo, ephemeralHi := keys.EphemeralPacked()
			var w p256.KeyAgreementCircuit
			for i, b := range keys.EphemeralScalar() {
				w.Scalar[i] = b
			}
			for i, b := range [65]byte{0x04} {
				w.PublicKey[i] = b
			}
			for i, v := range []*big.Int{recipientLo, recipientHi, ephemeralLo, ephemeralHi, sharedLo, sharedHi} {
				w.Expected[i] = v
			}
			hintattack.RequireConstraintRejection(t, p256.SolveAgreement(t, cs, &w))
		})
	}
}

// Invariant 3: Recipient and ephemeral-scalar inputs are constrained to bytes, including under forged range-check hints.
func TestComputeKeyAgreementBoundaryRecipientByteRangeCheck(t *testing.T) {
	requireRangeChecks(t, p256.Compile(t, &p256.KeyAgreementCircuit{}),
		func() frontend.Circuit { return p256.KeyAgreementWitness(t, boundaryScalar, boundaryPeer()) },
		func(w frontend.Circuit) []frontend.Variable { return w.(*p256.KeyAgreementCircuit).PublicKey[:] },
		[]carriedByte{{"x byte 5", 5}, {"y byte 40", 40}},
	)
}

// Invariant 3: Recipient and ephemeral-scalar inputs are constrained to bytes, including under forged range-check hints.
func TestComputeKeyAgreementBoundaryEphemeralByteRangeCheck(t *testing.T) {
	requireRangeChecks(t, p256.Compile(t, &p256.KeyAgreementCircuit{}),
		func() frontend.Circuit { return p256.KeyAgreementWitness(t, boundaryScalar, boundaryPeer()) },
		func(w frontend.Circuit) []frontend.Variable { return w.(*p256.KeyAgreementCircuit).Scalar[:] },
		[]carriedByte{{"scalar byte 5", 5}, {"scalar byte 29", 29}},
	)
}

// Invariant 4: Scalars reduce modulo the group order; zero residues are rejected, including at order boundaries.
func TestComputeKeyAgreementBoundaryScalarAtGroupOrder(t *testing.T) {
	cs := p256.Compile(t, &p256.KeyAgreementCircuit{})
	peer := boundaryPeer()
	t.Run("group order", func(t *testing.T) {
		w := p256.KeyAgreementWitness(t, big.NewInt(1), peer)
		assignBytes(w.Scalar[:], scalarBytes(elliptic.P256().Params().N))
		infinityLo, infinityHi := hosttest.PackCompressed([33]byte{0x02})
		sharedLo, sharedHi := hosttest.PackShared([32]byte{})
		w.Expected[2], w.Expected[3], w.Expected[4], w.Expected[5] = infinityLo, infinityHi, sharedLo, sharedHi
		hintattack.RequireConstraintRejection(t, p256.SolveAgreement(t, cs, w))
	})
	for _, row := range orderBoundaryScalars() {
		t.Run(row.name, func(t *testing.T) {
			w := p256.KeyAgreementWitness(t, row.reduced, peer)
			assignBytes(w.Scalar[:], scalarBytes(row.raw))
			if hosttest.IsLadderExceptional(row.reduced) {
				hintattack.RequireConstraintRejection(t, p256.SolveAgreement(t, cs, w))
				return
			}
			if err := p256.SolveAgreement(t, cs, w); err != nil {
				t.Fatalf("rejected: %v", err)
			}
		})
	}
}

// Test circuits and shared helpers.

var boundaryScalar = new(big.Int).SetBytes([]byte("ephemeral scalar for the merge!!"))

func boundaryPeer() *ecdh.PublicKey {
	return hosttest.DefaultKeys().RecipientSecret.PublicKey()
}

func scalarBytes(scalar *big.Int) []byte {
	return scalar.FillBytes(make([]byte, 32))
}

func assignBytes(dst []frontend.Variable, src []byte) {
	for i, b := range src {
		dst[i] = int(b)
	}
}

func presentedAgreement(ephemeral *ecdh.PrivateKey, presented [65]byte, sharedX []byte) *p256.KeyAgreementCircuit {
	var w p256.KeyAgreementCircuit
	assignBytes(w.Scalar[:], ephemeral.Bytes())
	assignBytes(w.PublicKey[:], presented[:])
	recipientLo, recipientHi := hosttest.PackCompressed(hosttest.CompressP256(presented[:]))
	ephemeralLo, ephemeralHi := hosttest.PackCompressed(hosttest.CompressP256(ephemeral.PublicKey().Bytes()))
	sharedLo, sharedHi := hosttest.PackShared([32]byte(sharedX))
	for i, v := range []*big.Int{recipientLo, recipientHi, ephemeralLo, ephemeralHi, sharedLo, sharedHi} {
		w.Expected[i] = v
	}
	return &w
}

type carriedByte struct {
	name string
	k    int
}

func requireRangeChecks(t *testing.T, cs constraint.ConstraintSystem, honest func() frontend.Circuit, bytes func(frontend.Circuit) []frontend.Variable, carries []carriedByte) {
	t.Helper()
	for _, prover := range hosttest.RangeCheckProvers(t) {
		t.Run(prover.Name, func(t *testing.T) {
			if err := p256.SolveAgreement(t, cs, honest(), prover.Options...); err != nil {
				t.Fatalf("honest witness rejected: %v", err)
			}
			for _, carry := range carries {
				t.Run(carry.name, func(t *testing.T) {
					w := honest()
					hosttest.CarryIntoByte(t, bytes(w), carry.k)
					hintattack.RequireConstraintRejection(t, p256.SolveAgreement(t, cs, w, prover.Options...))
				})
			}
		})
	}
}

type orderBoundaryScalar struct {
	name    string
	raw     *big.Int
	reduced *big.Int
}

func orderBoundaryScalars() []orderBoundaryScalar {
	n := elliptic.P256().Params().N
	allOnes := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
	return []orderBoundaryScalar{
		{"group order plus one as scalar one", new(big.Int).Add(n, big.NewInt(1)), big.NewInt(1)},
		{"2^256 minus one as its residue", allOnes, new(big.Int).Mod(allOnes, n)},
	}
}
