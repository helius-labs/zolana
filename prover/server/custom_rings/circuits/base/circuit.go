// Package base proves that a transaction's viewing key is encrypted to the ring auditor.
package base

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
)

// Properties: the published key is 0x04 || X25519(TxViewingSk) with TxViewingSk clamped, sealed to the X25519 key
// AuditorPk, with the first NOut outputs disclosed. The chain mirrors CustomRingBasePublicInput::hash on chain.

type CustomRingBaseCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Audit
	NOut    frontend.Variable
	Outputs [AuditOutputSlots]AuditOutputWires
}

func (c *CustomRingBaseCircuit) Define(api frontend.API) error {
	var hashes [AuditOutputSlots]frontend.Variable
	for i, output := range c.Outputs {
		hashes[i] = output.Hash(api)
	}
	elements := c.Audit.Define(api, rangecheck.New(api), c.Outputs, hashes, SelectCount(api, c.NOut, 1, AuditOutputSlots))
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, elements[:]))
	return nil
}
