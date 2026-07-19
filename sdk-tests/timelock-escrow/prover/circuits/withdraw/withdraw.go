package withdraw

import (
	"circuits/escrowterms"

	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	spp "zolana/prover/circuits/spp_transaction"
)

type Circuit struct {
	Public PublicInputs

	Terms escrowterms.EscrowTerms

	EscrowUtxo   spp.UtxoCircuitFields
	SourceOutput spp.UtxoCircuitFields

	OwnerPkField frontend.Variable
	NullifierPk  frontend.Variable

	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	escrowInputUtxoHash := c.checkEscrowInputUtxo(api)
	sourceOutputUtxoHash := c.checkSourceOutputUtxo(api)
	c.checkOwnerAuthorization(api)

	privateTxHashInputs{
		EscrowInputUtxoHash:  escrowInputUtxoHash,
		SourceOutputUtxoHash: sourceOutputUtxoHash,
		ExternalDataHash:     c.ExternalDataHash,
		PrivateTxHash:        c.Public.PrivateTxHash,
	}.Check(api)

	c.Public.Check(api, c.Terms.Unlock, c.OwnerPkField)
	return nil
}

type PublicInputs struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	PrivateTxHash frontend.Variable
}

func (p PublicInputs) Check(api frontend.API, unlock frontend.Variable, ownerPkField frontend.Variable) {
	publicInputHash := gadget.PoseidonHash(api, []frontend.Variable{p.PrivateTxHash, unlock, ownerPkField})
	api.AssertIsEqual(p.PublicInputHash, publicInputHash)
}

type privateTxHashInputs struct {
	EscrowInputUtxoHash  frontend.Variable
	SourceOutputUtxoHash frontend.Variable
	ExternalDataHash     frontend.Variable
	PrivateTxHash        frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	inputHashes := []frontend.Variable{t.EscrowInputUtxoHash}
	outputHashes := []frontend.Variable{t.SourceOutputUtxoHash}
	addressHashes := []frontend.Variable{frontend.Variable(0)}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, t.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, t.PrivateTxHash)
}

func (c *Circuit) checkEscrowInputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.EscrowUtxo.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.EscrowUtxo.ZoneDataHash, 0)
	api.AssertIsEqual(c.EscrowUtxo.ZoneProgramID, 0)
	api.AssertIsEqual(c.EscrowUtxo.DataHash, c.Terms.DataHash(api))
	api.AssertIsDifferent(c.EscrowUtxo.Amount, 0)
	return spp.UtxoHashCircuit(api, c.EscrowUtxo)
}

func (c *Circuit) checkSourceOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.SourceOutput.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.SourceOutput.ZoneDataHash, 0)
	api.AssertIsEqual(c.SourceOutput.ZoneProgramID, 0)
	api.AssertIsEqual(c.SourceOutput.DataHash, 0)
	api.AssertIsEqual(c.SourceOutput.Asset, c.EscrowUtxo.Asset)
	api.AssertIsEqual(c.SourceOutput.Amount, c.EscrowUtxo.Amount)
	api.AssertIsEqual(c.SourceOutput.Owner, c.Terms.OwnerHash)
	return spp.UtxoHashCircuit(api, c.SourceOutput)
}

func (c *Circuit) checkOwnerAuthorization(api frontend.API) {
	recomputedOwnerHash := gadget.PoseidonHash(api, []frontend.Variable{c.OwnerPkField, c.NullifierPk})
	api.AssertIsEqual(recomputedOwnerHash, c.Terms.OwnerHash)
}
