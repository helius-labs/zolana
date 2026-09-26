package escrow

import (
	"github.com/consensys/gnark/frontend"

	"circuits/escrowterms"
	"circuits/zkprogram"
	"zolana/gnarksdk"
)

const (
	NInputs    = 2
	NOutputs   = 2
	SlotSource = 0
	SlotChange = 0
	SlotEscrow = 1
)

type Circuit struct {
	Public PublicInputs

	Tx     zkprogram.Transaction
	Source gnarksdk.Utxo
	Terms  escrowterms.EscrowTerms
	Amount frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	api.AssertIsDifferent(c.Amount, 0)
	api.AssertIsEqual(c.Source.Owner, c.Terms.OwnerHash)
	asset := c.Source.Asset

	slots := c.Tx.Slots(NInputs, NOutputs)
	slots.Input(SlotSource, zkprogram.PlainHash(api, c.Source))
	slots.Create(api, SlotEscrow, zkprogram.ProgramOutput(api, c.Public.EscrowOwnerHash, c.Terms, asset, c.Amount))
	slots.Create(api, SlotChange, zkprogram.Payment(c.Terms.OwnerHash, asset, api.Sub(c.Source.Amount, c.Amount)))
	api.AssertIsEqual(slots.PrivateTxHash(api), c.Public.PrivateTxHash)

	c.Public.Check(api)
	return nil
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash   frontend.Variable
	EscrowOwnerHash frontend.Variable
}

func (p PublicInputs) Check(api frontend.API) {
	api.AssertIsEqual(p.PublicInputHash, gnarksdk.Poseidon(api, p.PrivateTxHash, p.EscrowOwnerHash))
}
