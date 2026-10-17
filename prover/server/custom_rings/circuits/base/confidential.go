package base

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"
	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// CustomRingConfidentialCircuit proves the ordinary audit statement. Its mode
// is a circuit constant, not a prover-controlled flag. The settlement program
// must select this verifying key only for a nonanonymous ring.
type CustomRingConfidentialCircuit struct {
	PublicInputHash               frontend.Variable `gnark:",public"`
	PrivateTxHash                 frontend.Variable
	TxViewingSk, EphSk, AuditorPk [32]frontend.Variable
	Salt                          [16]frontend.Variable
	NOut                          frontend.Variable
	Outputs                       [AuditOutputSlots]AuditOutputWires
}

func (c *CustomRingConfidentialCircuit) Define(api frontend.API) error {
	audit := Audit{PrivateTxHash: c.PrivateTxHash, Anonymous: 0, TxViewingSk: c.TxViewingSk, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Salt: c.Salt}
	tx := AuditTx{Outputs: c.Outputs, NOut: SelectCount(api, c.NOut, 1, AuditOutputSlots)}
	for i, output := range c.Outputs {
		tx.Hashes[i] = output.Hash(api)
	}
	elements := audit.Define(api, rangecheck.New(api), tx)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, elements[:]))
	return nil
}
