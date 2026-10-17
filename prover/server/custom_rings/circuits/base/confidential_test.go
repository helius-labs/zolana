package base_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
	"github.com/helius-labs/zolana/prover/server/prover-test/ringaudit"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

func TestConfidentialAuditBindsDisclosureAndMode(t *testing.T) {
	keys := ringaudit.DefaultKeys(t)
	statement := keys.Statement(big.NewInt(123))
	statement.Count = 2
	statement.Outputs[0].Domain, statement.Outputs[0].Amount = 3, 100
	full := keys.Circuit(t, statement)
	valid := base.CustomRingConfidentialCircuit{
		PublicInputHash: full.PublicInputHash, PrivateTxHash: full.PrivateTxHash,
		TxViewingSk: full.TxViewingSk, EphSk: full.EphSk, AuditorPk: full.AuditorPk,
		Salt: full.Salt, NOut: full.NOut, Outputs: full.Outputs,
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &base.CustomRingConfidentialCircuit{}, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*base.CustomRingConfidentialCircuit)
	}{
		{"valid", nil},
		{"false amount", func(c *base.CustomRingConfidentialCircuit) { c.Outputs[0].Amount = 10 }},
		{"false second amount", func(c *base.CustomRingConfidentialCircuit) { c.Outputs[1].Amount = 10 }},
		{"wrong owner", func(c *base.CustomRingConfidentialCircuit) { c.Outputs[0].OwnerHash = 1 }},
		{"wrong asset", func(c *base.CustomRingConfidentialCircuit) { c.Outputs[0].Asset = 1 }},
		{"wrong blinding", func(c *base.CustomRingConfidentialCircuit) { c.Outputs[0].Blinding = 1 }},
		{"wrong tree", func(c *base.CustomRingConfidentialCircuit) { c.Outputs[0].TreeID = 1 }},
		{"wrong data hash", func(c *base.CustomRingConfidentialCircuit) { c.Outputs[0].DataHash = 1 }},
		{"wrong ring data hash", func(c *base.CustomRingConfidentialCircuit) { c.Outputs[0].RingDataHash = 1 }},
		{"wrong ring", func(c *base.CustomRingConfidentialCircuit) { c.Outputs[0].RingProgramID = 1 }},
		{"missing output", func(c *base.CustomRingConfidentialCircuit) { c.NOut = 1 }},
		{"zero outputs", func(c *base.CustomRingConfidentialCircuit) { c.NOut = 0 }},
		{"too many outputs", func(c *base.CustomRingConfidentialCircuit) { c.NOut = 5 }},
		{"wrong transaction", func(c *base.CustomRingConfidentialCircuit) { c.PrivateTxHash = 124 }},
		{"wrong salt", func(c *base.CustomRingConfidentialCircuit) { c.Salt[0] = 1 }},
		{"wrong viewing secret", func(c *base.CustomRingConfidentialCircuit) { c.TxViewingSk[1] = 9 }},
		{"wrong ephemeral secret", func(c *base.CustomRingConfidentialCircuit) { c.EphSk[1] = 9 }},
		{"wrong auditor", func(c *base.CustomRingConfidentialCircuit) { c.AuditorPk[0] = 0 }},
		{"anonymous mode", func(c *base.CustomRingConfidentialCircuit) {
			elements := keys.ChainElementsFor(t, statement)
			elements[len(elements)-1] = big.NewInt(1)
			c.PublicInputHash = spptest.MustHashChain(t, elements)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := valid
			if tc.mutate != nil {
				tc.mutate(&w)
			}
			witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			err = cs.IsSolved(witness)
			if (err == nil) != (tc.mutate == nil) {
				t.Fatalf("unexpected solve result: %v", err)
			}
		})
	}
}
