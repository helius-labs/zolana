// Binds policy subjects and amounts to the transaction hash and marks
// selected UTXO slots for evaluation.

package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
)

// OpeningWires supplies a transaction slot's fields for hash binding and
// subject extraction.
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

// slotView supplies transaction subjects for evaluation when live.
type slotView struct {
	ownerPkHash frontend.Variable
	asset       frontend.Variable
	amount      frontend.Variable
	// Only selected UTXO slots can create policy obligations.
	live frontend.Variable
}

// transactionContext supplies checked inputs and outputs to policy evaluation.
type transactionContext struct {
	inputs  [NInputs]slotView
	outputs [NOutputs]slotView
}

// checkOpenings binds subject values and amounts to the transaction checked by
// SPP.
func (c *CustomRingPolicyCircuit) checkOpenings(api frontend.API, checker frontend.Rangechecker) transactionContext {
	// 1. Select the transaction slot prefixes.
	assertOneHot(api, c.InputCountSelected[:])
	assertOneHot(api, c.OutputCountSelected[:])
	activeIn := suffixSums(api, c.InputCountSelected[:])
	activeOut := suffixSums(api, c.OutputCountSelected[:])

	var txContext transactionContext
	// 2. Check input domains and commitments.
	inputHashes := make([]frontend.Variable, NInputs)
	for i, wires := range c.Inputs {
		inputHashes[i], txContext.inputs[i] = wires.checkInput(api, checker, activeIn[i])
	}

	// 3. Check output domains and commitments.
	outputHashes := make([]frontend.Variable, NOutputs)
	for i, wires := range c.Outputs {
		outputHashes[i], txContext.outputs[i] = wires.checkOutput(api, checker, activeOut[i])
	}

	// 4. Bind the openings to the SPP transaction.
	api.AssertIsEqual(c.PrivateTxHash, gadget.PoseidonHash(api, []frontend.Variable{
		hashPrefix(api, inputHashes, c.InputCountSelected[:]),
		hashPrefix(api, outputHashes, c.OutputCountSelected[:]),
		c.AddressChain,
		c.ExternalDataHash,
	}))
	return txContext
}

// checkInput admits UTXO, address and dummy inputs while exposing only UTXO
// subjects.
func (w OpeningWires) checkInput(
	api frontend.API,
	checker frontend.Rangechecker,
	active frontend.Variable,
) (frontend.Variable, slotView) {
	// 1. Restrict selected inputs to supported domains.
	isUtxo := w.isDomain(api, shared.UtxoDomain)
	shared.AssertWhen(api, active, api.Add(isUtxo, w.isDomain(api, shared.AddressDomain), w.isDomain(api, shared.DummyDomain)))

	// 2. Derive the input hash and bounded subject values.
	return w.checkSlot(api, checker, active, isUtxo)
}

// checkOutput admits UTXO and dummy outputs while exposing only UTXO subjects.
func (w OpeningWires) checkOutput(
	api frontend.API,
	checker frontend.Rangechecker,
	active frontend.Variable,
) (frontend.Variable, slotView) {
	// 1. Restrict selected outputs to UTXO or dummy domains.
	isUtxo := w.isDomain(api, shared.UtxoDomain)
	shared.AssertWhen(api, active, api.Add(isUtxo, w.isDomain(api, shared.DummyDomain)))

	// 2. Derive the output hash and bounded subject values.
	return w.checkSlot(api, checker, active, isUtxo)
}

// checkSlot reconstructs the commitment and marks UTXO fields for rule
// evaluation.
func (w OpeningWires) checkSlot(
	api frontend.API,
	checker frontend.Rangechecker,
	active, isUtxo frontend.Variable,
) (frontend.Variable, slotView) {
	// 1. Bound the amount before summing guard totals.
	checker.Check(w.Amount, amountBits)

	// 2. Bind ownership and UTXO fields into the slot hash.
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

	// 3. Mark selected UTXOs for rule evaluation.
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
