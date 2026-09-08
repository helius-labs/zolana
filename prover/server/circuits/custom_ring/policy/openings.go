package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
)

// The owner commitment binds OwnerPkHash and NullifierPk.
type OpeningWires struct {
	Domain        frontend.Variable
	OwnerPkHash   frontend.Variable
	NullifierPk   frontend.Variable
	Asset         frontend.Variable
	Amount        frontend.Variable
	Blinding      frontend.Variable
	DataHash      frontend.Variable
	RingDataHash  frontend.Variable
	RingProgramID frontend.Variable
}

type slotView struct {
	ownerPkHash frontend.Variable
	asset       frontend.Variable
	amount      frontend.Variable
	live        frontend.Variable
}

type openings struct {
	inputs  [NIn]slotView
	outputs [NOut]slotView
}

func (c *CustomRingPolicyCircuit) checkOpenings(api frontend.API, checker frontend.Rangechecker) openings {
	// Select the transaction slots.
	assertOneHot(api, c.NInOneHot[:])
	assertOneHot(api, c.NOutOneHot[:])
	activeIn := suffixSums(api, c.NInOneHot[:])
	activeOut := suffixSums(api, c.NOutOneHot[:])

	var slots openings
	// Check input domains and commitments.
	inputHashes := make([]frontend.Variable, NIn)
	for i, wires := range c.Inputs {
		inputHashes[i], slots.inputs[i] = wires.checkInput(api, checker, activeIn[i])
	}
	// Check output domains and commitments.
	outputHashes := make([]frontend.Variable, NOut)
	for i, wires := range c.Outputs {
		outputHashes[i], slots.outputs[i] = wires.checkOutput(api, checker, activeOut[i])
	}

	// Bind the openings to the SPP transaction.
	api.AssertIsEqual(c.PrivateTxHash, gadget.PoseidonHash(api, []frontend.Variable{
		hashPrefix(api, inputHashes, c.NInOneHot[:]),
		hashPrefix(api, outputHashes, c.NOutOneHot[:]),
		c.AddressChain,
		c.ExternalDataHash,
	}))
	return slots
}

func (w OpeningWires) checkInput(
	api frontend.API,
	checker frontend.Rangechecker,
	active frontend.Variable,
) (frontend.Variable, slotView) {
	isUtxo := w.isDomain(api, shared.UtxoDomain)
	shared.AssertWhen(api, active, api.Add(isUtxo, w.isDomain(api, shared.AddressDomain), w.isDomain(api, shared.DummyDomain)))
	return w.checkSlot(api, checker, active, isUtxo)
}

func (w OpeningWires) checkOutput(
	api frontend.API,
	checker frontend.Rangechecker,
	active frontend.Variable,
) (frontend.Variable, slotView) {
	isUtxo := w.isDomain(api, shared.UtxoDomain)
	shared.AssertWhen(api, active, api.Add(isUtxo, w.isDomain(api, shared.DummyDomain)))
	return w.checkSlot(api, checker, active, isUtxo)
}

func (w OpeningWires) checkSlot(
	api frontend.API,
	checker frontend.Rangechecker,
	active, isUtxo frontend.Variable,
) (frontend.Variable, slotView) {
	// Amount bounds prevent overflow in guard totals.
	checker.Check(w.Amount, amountBits)
	owner := gadget.PoseidonHash(api, []frontend.Variable{w.OwnerPkHash, w.NullifierPk})
	hash := shared.UtxoHashCircuit(api, shared.UtxoCircuitFields{
		Domain:        w.Domain,
		Owner:         owner,
		Asset:         w.Asset,
		Amount:        w.Amount,
		Blinding:      w.Blinding,
		DataHash:      w.DataHash,
		RingDataHash:  w.RingDataHash,
		RingProgramID: w.RingProgramID,
	})
	return api.Select(isUtxo, hash, frontend.Variable(0)), slotView{
		ownerPkHash: w.OwnerPkHash,
		asset:       w.Asset,
		amount:      w.Amount,
		live:        api.Mul(active, isUtxo),
	}
}

func (w OpeningWires) isDomain(api frontend.API, domain int) frontend.Variable {
	return api.IsZero(api.Sub(w.Domain, domain))
}
