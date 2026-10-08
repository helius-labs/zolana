package p256

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark/constraint/solver"

	"zolana/prover/prover-test/hintattack"
)

type attackScalar struct {
	name   string
	scalar *big.Int
}

func attackScalars() []attackScalar {
	return []attackScalar{
		{"scalar c0ffee", big.NewInt(0xC0FFEE)},
		{"scalar one", big.NewInt(1)},
		{"scalar minus one", new(big.Int).Sub(elliptic.P256().Params().N, big.NewInt(1))},
	}
}

func TestComputeKeyAgreementRejectsHintAttacks(t *testing.T) {
	cs := compile(t, &keyAgreementCircuit{})
	peer := agreementPeer(t)
	for _, row := range attackScalars() {
		w := keyAgreementWitness(t, row.scalar, peer)
		t.Run(row.name, func(t *testing.T) {
			hintattack.RunHintAttacks(t, cs, func(opts ...solver.Option) error {
				return solveAgreement(t, cs, w, opts...)
			})
		})
	}
}

func TestSelfAgreeKeyRejectsHintAttacks(t *testing.T) {
	cs := compile(t, &selfAgreementCircuit{})
	for _, row := range attackScalars() {
		w := scalarRow{name: row.name, scalar: row.scalar, reduced: row.scalar}.selfAgreementWitness(t)
		t.Run(row.name, func(t *testing.T) {
			hintattack.RunHintAttacks(t, cs, func(opts ...solver.Option) error {
				return solveAgreement(t, cs, w, opts...)
			})
		})
	}
}
