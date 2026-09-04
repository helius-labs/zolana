package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
)

// OpeningWires is one transaction slot, its owner commitment derived rather
// than witnessed.
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
	owner  frontend.Variable
	asset  frontend.Variable
	amount frontend.Variable
	live   frontend.Variable
}

type openings struct {
	inputs  [NIn]slotView
	outputs [NOut]slotView
}

func (c *CustomRingPolicyCircuit) defineOpenings(api frontend.API, checker frontend.Rangechecker) openings {
	assertOneHot(api, c.NInOneHot[:])
	assertOneHot(api, c.NOutOneHot[:])
	activeIn := suffixSums(api, c.NInOneHot[:])
	activeOut := suffixSums(api, c.NOutOneHot[:])

	var out openings
	inputs := make([]frontend.Variable, NIn)
	for i, wires := range c.Inputs {
		inputs[i], out.inputs[i] = wires.defineInput(api, checker, activeIn[i])
	}
	outputs := make([]frontend.Variable, NOut)
	for i, wires := range c.Outputs {
		outputs[i], out.outputs[i] = wires.defineOutput(api, checker, activeOut[i])
	}

	// Recomputing PrivateTxHash binds the screened openings to the SPP transaction.
	api.AssertIsEqual(c.PrivateTxHash, gadget.PoseidonHash(api, []frontend.Variable{
		prefixSelect(api, inputs, c.NInOneHot[:]),
		prefixSelect(api, outputs, c.NOutOneHot[:]),
		c.AddressChain,
		c.ExternalDataHash,
	}))
	return out
}

func (w OpeningWires) defineInput(
	api frontend.API,
	checker frontend.Rangechecker,
	active frontend.Variable,
) (frontend.Variable, slotView) {
	isUtxo := w.is(api, shared.UtxoDomain)
	shared.AssertWhen(api, active, api.Add(isUtxo, w.is(api, shared.AddressDomain), w.is(api, shared.DummyDomain)))
	return w.classify(api, checker, active, isUtxo)
}

func (w OpeningWires) defineOutput(
	api frontend.API,
	checker frontend.Rangechecker,
	active frontend.Variable,
) (frontend.Variable, slotView) {
	isUtxo := w.is(api, shared.UtxoDomain)
	shared.AssertWhen(api, active, api.Add(isUtxo, w.is(api, shared.DummyDomain)))
	return w.classify(api, checker, active, isUtxo)
}

// classify mirrors shared.ConstrainOutput.
func (w OpeningWires) classify(
	api frontend.API,
	checker frontend.Rangechecker,
	active, isUtxo frontend.Variable,
) (frontend.Variable, slotView) {
	// The guard comparison needs the amount bounded to 64 bits.
	checker.Check(w.Amount, 64)
	hash := shared.UtxoHashCircuit(api, shared.UtxoCircuitFields{
		Domain:        w.Domain,
		Owner:         gadget.PoseidonHash(api, []frontend.Variable{w.OwnerPkHash, w.NullifierPk}),
		Asset:         w.Asset,
		Amount:        w.Amount,
		Blinding:      w.Blinding,
		DataHash:      w.DataHash,
		RingDataHash:  w.RingDataHash,
		RingProgramID: w.RingProgramID,
	})
	return api.Select(isUtxo, hash, frontend.Variable(0)), slotView{
		owner:  w.OwnerPkHash,
		asset:  w.Asset,
		amount: w.Amount,
		live:   api.Mul(active, isUtxo),
	}
}

func (w OpeningWires) is(api frontend.API, domain int) frontend.Variable {
	return api.IsZero(api.Sub(w.Domain, domain))
}

// prefixSelect hash-chains the first n contributions, n picked by the one-hot.
// Soundness is computational, a lie about n must still land on the
// transaction's private_tx_hash, and that takes a Poseidon preimage.
func prefixSelect(api frontend.API, contributions, oneHot []frontend.Variable) frontend.Variable {
	return foldSelect(api, contributions[0], contributions[1:], oneHot)
}

// foldSelect returns the fold over the first k values, k picked by the one-hot.
func foldSelect(api frontend.API, head frontend.Variable, values, oneHot []frontend.Variable) frontend.Variable {
	chain := head
	selected := api.Mul(oneHot[0], chain)
	for k, value := range values {
		chain = gadget.PoseidonHash(api, []frontend.Variable{chain, value})
		selected = api.Add(selected, api.Mul(oneHot[k+1], chain))
	}
	return selected
}

func assertOneHot(api frontend.API, oneHot []frontend.Variable) {
	sum := frontend.Variable(0)
	for _, bit := range oneHot {
		api.AssertIsBoolean(bit)
		sum = api.Add(sum, bit)
	}
	api.AssertIsEqual(sum, 1)
}

// suffixSums returns the flag that position k is within the selected count.
func suffixSums(api frontend.API, oneHot []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(oneHot))
	sum := frontend.Variable(0)
	for k := len(oneHot) - 1; k >= 0; k-- {
		sum = api.Add(sum, oneHot[k])
		out[k] = sum
	}
	return out
}
