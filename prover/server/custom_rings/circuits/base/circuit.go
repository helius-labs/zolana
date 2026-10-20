// Package base proves that a transaction's viewing key is encrypted to the ring auditor.
package base

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
)

// Properties: the published key is 0x04 || X25519(TxViewingSk) with TxViewingSk clamped, sealed to AuditorPk, with the
// first NOut outputs disclosed, or in an anonymous ring the sender, its NIn spent notes and every recipient, and every
// real ring output body is the recipient's encryption of its committed note.

// BaseElements is the base statement, the audit elements with the output body chain at BodyChainIndex.
const (
	BaseElements   = AuditElements + 1
	BodyChainIndex = 8
)

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
	Delivery          Delivery
}

func (c *CustomRingBaseCircuit) Define(api frontend.API) error {
	return defineBase(api, c.PublicInputHash, c.Audit, c.NOut, c.Outputs,
		c.NIn, c.Inputs[:], c.AnonymousOutputs, c.PrivateTxBlinding, c.Delivery)
}

// CustomRingWideBaseCircuit keeps audit-only anonymous transfers usable above
// four inputs. The same proof obligations apply to all twelve published slots.
type CustomRingWideBaseCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`
	Audit
	NOut              frontend.Variable
	Outputs           [AuditOutputSlots]AuditOutputWires
	NIn               frontend.Variable
	Inputs            [12]AuditUtxoWires
	AnonymousOutputs  [AuditOutputSlots]AuditUtxoWires
	PrivateTxBlinding frontend.Variable
	Delivery          Delivery
}

func (c *CustomRingWideBaseCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Anonymous, 1)
	return defineBase(api, c.PublicInputHash, c.Audit, c.NOut, c.Outputs,
		c.NIn, c.Inputs[:], c.AnonymousOutputs, c.PrivateTxBlinding, c.Delivery)
}

func defineBase(api frontend.API, publicHash frontend.Variable, audit Audit, nOut frontend.Variable,
	outputs [AuditOutputSlots]AuditOutputWires, nInValue frontend.Variable,
	inputs []AuditUtxoWires, notes [AuditOutputSlots]AuditUtxoWires,
	privateBlinding frontend.Variable, delivery Delivery) error {
	nIn := SelectCount(api, nInValue, 0, len(inputs)+1)
	api.AssertIsEqual(nIn.OneHot[0], api.Sub(1, audit.Anonymous))
	tx := AuditTx{
		Outputs: outputs, NOut: SelectCount(api, nOut, 1, AuditOutputSlots),
		NIn: Count{OneHot: nIn.OneHot[1:], Active: nIn.Active}, Inputs: inputs, Notes: notes,
	}
	inputHashes, outputHashes := make([]frontend.Variable, len(inputs)), make([]frontend.Variable, AuditOutputSlots)
	for i, input := range inputs {
		hash, utxo := input.Hash(api)
		inputHashes[i] = api.Mul(nIn.Active[i], utxo, hash)
	}
	for i, output := range notes {
		opening, utxo := output.Opening(api)
		// Hash the selected opening once. Outside anonymous mode the private
		// transaction opening below is disabled, so it needs no second hash.
		hash := opening.Select(api, audit.Anonymous, outputs[i]).Hash(api)
		tx.Hashes[i] = hash
		outputHashes[i] = api.Mul(tx.NOut.Active[i], utxo, hash)
	}
	opened := shared.PrivateTxHashCircuit(api, inputHashes, outputHashes, nil, privateBlinding)
	api.AssertIsEqual(api.Mul(audit.Anonymous, api.Sub(audit.PrivateTxHash, opened)), 0)
	statement := audit.Statement(api, rangecheck.New(api), tx, delivery)
	api.AssertIsEqual(publicHash, gadget.HashChain(api, statement[:]))
	return nil
}
