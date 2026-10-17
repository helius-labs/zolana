// Package base proves that a transaction's viewing key is encrypted to the ring auditor.
package base

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Properties: the published key is 0x04 || X25519(TxViewingSk) with TxViewingSk clamped, sealed to AuditorPk, with the
// first NOut outputs disclosed, or in an anonymous ring the sender, its NIn spent notes and every recipient.

type CustomRingBaseCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Audit
	NOut    frontend.Variable
	Outputs [AuditOutputSlots]AuditOutputWires
	// Only an anonymous ring reads these, outside it NIn is zero.
	NIn               frontend.Variable
	Inputs            [AuditInputSlots]AuditUtxoWires
	AnonymousOutputs  [AuditOutputSlots]AuditUtxoWires
	PrivateTxBlinding frontend.Variable
}

func (c *CustomRingBaseCircuit) Define(api frontend.API) error {
	nIn := SelectCount(api, c.NIn, 0, AuditInputSlots+1)
	api.AssertIsEqual(nIn.OneHot[0], api.Sub(1, c.Anonymous))
	tx := AuditTx{
		Outputs: c.Outputs, NOut: SelectCount(api, c.NOut, 1, AuditOutputSlots),
		NIn: Count{OneHot: nIn.OneHot[1:], Active: nIn.Active}, Inputs: c.Inputs, Notes: c.AnonymousOutputs,
	}
	inputHashes, outputHashes := make([]frontend.Variable, AuditInputSlots), make([]frontend.Variable, AuditOutputSlots)
	for i, input := range c.Inputs {
		hash, utxo := input.Hash(api)
		inputHashes[i] = api.Mul(nIn.Active[i], utxo, hash)
	}
	for i, output := range c.AnonymousOutputs {
		opening, utxo := output.Opening(api)
		// Hash the selected opening once. Outside anonymous mode the private
		// transaction opening below is disabled, so it needs no second hash.
		hash := opening.Select(api, c.Anonymous, c.Outputs[i]).Hash(api)
		tx.Hashes[i] = hash
		outputHashes[i] = api.Mul(tx.NOut.Active[i], utxo, hash)
	}
	opened := shared.PrivateTxHashCircuit(api, inputHashes, outputHashes, nil, c.PrivateTxBlinding)
	api.AssertIsEqual(api.Mul(c.Anonymous, api.Sub(c.PrivateTxHash, opened)), 0)
	elements := c.Audit.Define(api, rangecheck.New(api), tx)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain(api, elements[:]))
	return nil
}
