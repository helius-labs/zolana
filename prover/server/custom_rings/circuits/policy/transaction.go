// Binds policy subjects and amounts to the transaction hash and marks
// selected UTXO slots for evaluation.

package policy

import (
	"github.com/consensys/gnark/frontend"

	"zolana/prover/circuits/gadget"
	"zolana/prover/circuits/spp_transaction/shared"
	base "zolana/prover/custom_rings/circuits/base"
)

// UtxoWires supplies a transaction slot's fields for hash binding and
// subject extraction.
type UtxoWires struct {
	Domain frontend.Variable
	// The raw id of the tree the UTXO lives in, SPP hashes under the same id.
	TreeID        frontend.Variable
	OwnerPkHash   frontend.Variable
	NullifierPk   frontend.Variable
	Asset         frontend.Variable
	Amount        frontend.Variable
	Blinding      frontend.Variable
	DataHash      frontend.Variable
	RingDataHash  frontend.Variable
	RingProgramID frontend.Variable
}

// utxoView supplies transaction subjects for evaluation when live.
type utxoView struct {
	ownerPkHash frontend.Variable
	asset       frontend.Variable
	amount      frontend.Variable
	// Poseidon(ownerPkHash, nullifierPk), the owner the leaf commits to.
	owner         frontend.Variable
	ringProgramID frontend.Variable
	// Selected, whatever the domain.
	active frontend.Variable
	// The final selected slot when windowed accounting requires a record.
	record frontend.Variable
	// Only selected UTXO slots outside the record can create policy obligations.
	live frontend.Variable
}

// transactionContext supplies checked inputs and outputs to policy evaluation.
type transactionContext struct {
	inputs  [NInputs]utxoView
	outputs [NOutputs]utxoView
}

func auditOutputs(api frontend.API, outputs [NOutputs]UtxoWires) [base.AuditOutputSlots]base.AuditOutputWires {
	var disclosed [base.AuditOutputSlots]base.AuditOutputWires
	for i, output := range outputs {
		ownerHash := gadget.PoseidonHash(api, []frontend.Variable{output.OwnerPkHash, output.NullifierPk})
		disclosed[i] = base.AuditOutputWires{
			Domain: output.Domain, TreeID: output.TreeID,
			OwnerHash: api.Mul(output.isDomain(api, shared.UtxoDomain), ownerHash),
			Asset:     output.Asset, Amount: output.Amount, Blinding: output.Blinding,
			DataHash: output.DataHash, RingDataHash: output.RingDataHash,
			RingProgramID: output.RingProgramID,
		}
	}
	return disclosed
}

// constrainTransactionContext binds subjects and amounts to the transaction
// checked by SPP.
func (c *CustomRingPolicyCircuit) constrainTransactionContext(api frontend.API, rangeChecker frontend.Rangechecker, recordEnabled frontend.Variable) transactionContext {
	// 1. Select the transaction slot prefixes.
	assertOneHot(api, c.InputCountSelected[:])
	assertOneHot(api, c.OutputCountSelected[:])
	activeIn := suffixSums(api, c.InputCountSelected[:])
	activeOut := suffixSums(api, c.OutputCountSelected[:])

	var txContext transactionContext
	// 2. Check input domains and commitments.
	inputHashes := make([]frontend.Variable, NInputs)
	for i, wires := range c.Inputs {
		record := api.Mul(recordEnabled, c.InputCountSelected[i])
		inputHashes[i], txContext.inputs[i] = wires.checkInput(api, rangeChecker, activeIn[i], record)
	}

	// 3. Check output domains and commitments.
	outputHashes := make([]frontend.Variable, NOutputs)
	for i, wires := range c.Outputs {
		record := api.Mul(recordEnabled, c.OutputCountSelected[i])
		outputHashes[i], txContext.outputs[i] = wires.checkOutput(api, rangeChecker, activeOut[i], record)
	}

	// 4. Bind the openings to the SPP transaction.
	api.AssertIsEqual(c.PrivateTxHash, gadget.PoseidonHash(api, []frontend.Variable{
		hashPrefix4(api, inputHashes, c.InputCountSelected[:]),
		hashPrefix4(api, outputHashes, c.OutputCountSelected[:]),
		c.AddressChain,
		c.ExternalDataHash,
		c.PrivateTxBlinding,
	}))
	return txContext
}

// checkInput admits UTXO, address and dummy inputs while exposing only UTXO
// subjects.
func (w UtxoWires) checkInput(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	active, record frontend.Variable,
) (frontend.Variable, utxoView) {
	// 1. Restrict selected inputs to supported domains.
	isUtxo := w.isDomain(api, shared.UtxoDomain)
	shared.AssertWhen(api, active, api.Add(isUtxo, w.isDomain(api, shared.AddressDomain), w.isDomain(api, shared.DummyDomain)))

	// 2. Derive the input hash and bounded subject values.
	return w.checkSlot(api, rangeChecker, active, isUtxo, record)
}

// checkOutput admits UTXO and dummy outputs while exposing only UTXO subjects.
func (w UtxoWires) checkOutput(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	active, record frontend.Variable,
) (frontend.Variable, utxoView) {
	// 1. Restrict selected outputs to UTXO or dummy domains.
	isUtxo := w.isDomain(api, shared.UtxoDomain)
	shared.AssertWhen(api, active, api.Add(isUtxo, w.isDomain(api, shared.DummyDomain)))

	// 2. Derive the output hash and bounded subject values.
	return w.checkSlot(api, rangeChecker, active, isUtxo, record)
}

// checkSlot reconstructs the commitment and marks UTXO fields for rule
// evaluation.
func (w UtxoWires) checkSlot(
	api frontend.API,
	rangeChecker frontend.Rangechecker,
	active, isUtxo, record frontend.Variable,
) (frontend.Variable, utxoView) {
	// 1. Bound the amount before summing guard totals.
	rangeChecker.Check(w.Amount, amountBits)

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
	}, w.TreeID)

	// 3. Mark selected UTXOs outside the record for rule evaluation.
	return api.Select(isUtxo, hash, frontend.Variable(0)), utxoView{
		ownerPkHash:   w.OwnerPkHash,
		asset:         w.Asset,
		amount:        w.Amount,
		owner:         owner,
		ringProgramID: w.RingProgramID,
		active:        active,
		record:        record,
		live:          api.Mul(active, isUtxo, api.Sub(1, record)),
	}
}

func (w UtxoWires) isDomain(api frontend.API, domain int) frontend.Variable {
	return api.IsZero(api.Sub(w.Domain, domain))
}
