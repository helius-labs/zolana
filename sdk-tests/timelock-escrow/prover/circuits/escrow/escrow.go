package escrow

import (
	"circuits/escrowterms"

	"github.com/consensys/gnark/frontend"

	spp "zolana/prover/circuits/spp_transaction"
)

type Circuit struct {
	PrivateTxHash frontend.Variable `gnark:",public"`

	Terms escrowterms.EscrowTerms

	EscrowUtxo spp.UtxoCircuitFields
	Change     spp.UtxoCircuitFields

	SourceInputHash  frontend.Variable
	ExternalDataHash frontend.Variable
}

func (c *Circuit) Define(api frontend.API) error {
	escrowOutputUtxoHash := c.checkEscrowOutputUtxo(api)
	changeOutputUtxoHash := c.checkChangeOutputUtxo(api)

	privateTxHashInputs{
		SourceInputHash:      c.SourceInputHash,
		ChangeOutputUtxoHash: changeOutputUtxoHash,
		EscrowOutputUtxoHash: escrowOutputUtxoHash,
		ExternalDataHash:     c.ExternalDataHash,
		PrivateTxHash:        c.PrivateTxHash,
	}.Check(api)

	return nil
}

type privateTxHashInputs struct {
	SourceInputHash      frontend.Variable
	ChangeOutputUtxoHash frontend.Variable
	EscrowOutputUtxoHash frontend.Variable
	ExternalDataHash     frontend.Variable
	PrivateTxHash        frontend.Variable
}

func (t privateTxHashInputs) Check(api frontend.API) {
	inputHashes := []frontend.Variable{t.SourceInputHash, frontend.Variable(0)}
	outputHashes := []frontend.Variable{t.ChangeOutputUtxoHash, t.EscrowOutputUtxoHash}
	addressHashes := []frontend.Variable{frontend.Variable(0), frontend.Variable(0)}

	privateTxHash := spp.PrivateTxHashCircuit(api, inputHashes, outputHashes, addressHashes, t.ExternalDataHash)
	api.AssertIsEqual(privateTxHash, t.PrivateTxHash)
}

func (c *Circuit) checkEscrowOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.EscrowUtxo.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.EscrowUtxo.ZoneDataHash, 0)
	api.AssertIsEqual(c.EscrowUtxo.ZoneProgramID, 0)
	api.AssertIsEqual(c.EscrowUtxo.DataHash, c.Terms.DataHash(api))
	api.AssertIsDifferent(c.EscrowUtxo.Amount, 0)
	return spp.UtxoHashCircuit(api, c.EscrowUtxo)
}

func (c *Circuit) checkChangeOutputUtxo(api frontend.API) frontend.Variable {
	api.AssertIsEqual(c.Change.Domain, spp.UtxoDomain)
	api.AssertIsEqual(c.Change.ZoneDataHash, 0)
	api.AssertIsEqual(c.Change.ZoneProgramID, 0)
	api.AssertIsEqual(c.Change.DataHash, 0)
	api.AssertIsEqual(c.Change.Asset, c.EscrowUtxo.Asset)
	api.AssertIsEqual(c.Change.Owner, c.Terms.OwnerHash)
	return spp.UtxoHashCircuit(api, c.Change)
}
