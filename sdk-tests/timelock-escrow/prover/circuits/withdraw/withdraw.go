package withdraw

import (
	"github.com/consensys/gnark/frontend"

	"circuits/escrowterms"
	"circuits/zkprogram"
	"zolana/gnarksdk"
)

const (
	NInputs          = 1
	NOutputs         = 1
	SlotEscrow       = 0
	SlotSourceOutput = 0
)

type Circuit struct {
	Public PublicInputs

	Tx         zkprogram.Transaction
	EscrowUtxo zkprogram.ProgramUtxo[escrowterms.EscrowTerms]

	OwnerPkField frontend.Variable
	NullifierPk  frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	escrow := c.EscrowUtxo.Utxo
	terms := c.EscrowUtxo.State
	api.AssertIsDifferent(escrow.Amount, 0)
	api.AssertIsEqual(gnarksdk.Poseidon(api, c.OwnerPkField, c.NullifierPk), terms.OwnerHash)

	slots := c.Tx.Slots(NInputs, NOutputs)
	slots.Input(SlotEscrow, c.EscrowUtxo.Hash(api))
	slots.Create(api, SlotSourceOutput, zkprogram.Payment(terms.OwnerHash, escrow.Asset, escrow.Amount))
	api.AssertIsEqual(slots.PrivateTxHash(api), c.Public.PrivateTxHash)

	c.Public.Check(api, terms.Unlock, c.OwnerPkField)
	return nil
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, unlock frontend.Variable, ownerPkField frontend.Variable) {
	api.AssertIsEqual(p.PublicInputHash, gnarksdk.Poseidon(api, p.PrivateTxHash, unlock, ownerPkField))
}
