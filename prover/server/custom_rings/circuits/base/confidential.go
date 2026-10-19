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
	return c.define(api, false)
}

// CustomRingCompactConfidentialCircuit is the two-output audit proof for the
// 24x2 settlement capacity. The proof relation is unchanged except that it
// hashes and publishes only the 18 live disclosure fields.
type CustomRingCompactConfidentialCircuit CustomRingConfidentialCircuit

func (c *CustomRingCompactConfidentialCircuit) Define(api frontend.API) error {
	return (*CustomRingConfidentialCircuit)(c).define(api, true)
}

func (c *CustomRingConfidentialCircuit) define(api frontend.API, short bool) error {
	// The settlement count selects this key. Pin it in the circuit as well.
	api.AssertIsEqual(c.NOut, 2)
	audit := Audit{PrivateTxHash: c.PrivateTxHash, Anonymous: 0, TxViewingSk: c.TxViewingSk, EphSk: c.EphSk, AuditorPk: c.AuditorPk, Salt: c.Salt}
	tx := AuditTx{Outputs: c.Outputs, NOut: SelectCount(api, 2, 1, AuditOutputSlots), ShortOrdinary: short}
	for i := range tx.Hashes {
		tx.Hashes[i] = 0
	}
	for i := 0; i < 2; i++ {
		tx.Hashes[i] = c.Outputs[i].Hash(api)
	}
	elements := audit.Define(api, rangecheck.New(api), tx)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, elements[:]))
	return nil
}
