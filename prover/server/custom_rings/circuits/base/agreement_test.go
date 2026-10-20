package base_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

type agreementCircuit struct {
	Secret, Recipient [32]frontend.Variable
}

func (c *agreementCircuit) Define(api frontend.API) error {
	base.AgreeAuditKey(api, c.Secret, c.Recipient)
	return nil
}

// RFC aliases preserve DH, but custom-ring keys must have exactly one encoding.
func TestAuditAgreementRejectsAliasesAndZeroDH(t *testing.T) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &agreementCircuit{})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"basepoint", "high bit", "p plus nine", "zero DH", "out of range byte"} {
		t.Run(name, func(t *testing.T) {
			var w agreementCircuit
			for i := range w.Secret {
				w.Secret[i], w.Recipient[i] = 0, 0
			}
			w.Recipient[0] = 9
			switch name {
			case "high bit":
				w.Recipient[31] = 128
			case "p plus nine":
				for i := range w.Recipient {
					w.Recipient[i] = 255
				}
				w.Recipient[0], w.Recipient[31] = 246, 127
			case "zero DH":
				w.Recipient[0] = 0
			case "out of range byte":
				w.Recipient[0] = 265
			}
			witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			err = cs.IsSolved(witness)
			if name == "basepoint" && err != nil {
				t.Fatal(err)
			}
			if name != "basepoint" && err == nil {
				t.Fatal("invalid recipient accepted")
			}
		})
	}
}
