package verifiableencryption_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/prover-test/hintattack"
)

func TestEnvelopePlaintextLengths(t *testing.T) {
	for _, n := range []int{0, 1, 15, 17, 31, 32, 33} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			if err := solveCompiled(t, compileEnvelope(t, n), envelopeAssignment(n)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestEnvelopeBindsEachPointField(t *testing.T) {
	cs := compileEnvelope(t, 16)
	if err := solveCompiled(t, cs, envelopeAssignment(16)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"recipient lo", "recipient hi", "ephemeral lo", "ephemeral hi"} {
		t.Run(name, func(t *testing.T) {
			w := envelopeAssignment(16)
			fields := map[string]*frontend.Variable{
				"recipient lo": &w.RecipientLo, "recipient hi": &w.RecipientHi,
				"ephemeral lo": &w.EphemeralLo, "ephemeral hi": &w.EphemeralHi,
			}
			field := fields[name]
			*field = new(big.Int).Add((*field).(*big.Int), big.NewInt(1))
			hintattack.RequireConstraintRejection(t, solveCompiled(t, cs, w))
		})
	}
}
