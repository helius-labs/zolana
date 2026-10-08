package p256_test

import (
	"crypto/elliptic"
	"math/big"
	"testing"
	"time"

	"zolana/prover/circuits/verifiable-encryption/p256"
	"zolana/prover/prover-test/hintattack"
	"zolana/prover/prover-test/hosttest"
)

func TestComputeKeyAgreementMatchesHostAtEdgeCases(t *testing.T) {
	start := time.Now()
	cs := p256.Compile(t, &p256.KeyAgreementCircuit{})
	cases := hosttest.EdgeCaseKeys()
	for _, edge := range cases {
		t.Run(edge.Name, func(t *testing.T) {
			scalar := new(big.Int).SetBytes(edge.Keys.EphemeralSecret.Bytes())
			w := p256.KeyAgreementWitness(t, scalar, edge.Keys.RecipientSecret.PublicKey())
			if err := p256.SolveAgreement(t, cs, w); err != nil {
				t.Fatalf("honest witness rejected: %v", err)
			}
		})
	}
	t.Logf("%d edge cases in %v", len(cases), time.Since(start))
}

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
