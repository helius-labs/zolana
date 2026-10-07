package verifiableencryption_test

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/consensys/gnark/constraint/solver"

	"zolana/prover/prover-test/hintattack"
	"zolana/prover/prover-test/hosttest"
)

func TestEnvelopeRejectsHintAttacks(t *testing.T) {
	cs := compileEnvelope(t, eciesPlaintextBytes)
	defaults := hosttest.DefaultKeys()
	recipient := new(big.Int).SetBytes(defaults.RecipientSecret.Bytes())
	minusOne := new(big.Int).Sub(elliptic.P256().Params().N, big.NewInt(1))
	for _, row := range []struct {
		name string
		keys hosttest.Keys
	}{
		{"default keys", defaults},
		{"ephemeral scalar minus one", hosttest.NewKeys(recipient, minusOne)},
	} {
		assignment := envelopeAssignmentFor(row.keys, eciesPlaintextBytes)
		t.Run(row.name, func(t *testing.T) {
			hintattack.RunHintAttacks(t, func(opts ...solver.Option) error {
				return solveCompiled(t, cs, assignment, opts...)
			})
		})
	}
}
