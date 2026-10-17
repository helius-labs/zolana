package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// UtxoWires opens one transaction slot, SPP hashes it under TreeID.
type UtxoWires struct {
	Domain        frontend.Variable
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

// OutputWires adds the hash of the owner's escrowed key ciphertext, read only under escrow.
type OutputWires struct {
	UtxoWires
	CtHash frontend.Variable
}

type utxoView struct {
	ownerPkHash, nullifierPk, asset, amount, ringProgramID frontend.Variable
	// owner is Poseidon(ownerPkHash, nullifierPk), the owner the leaf commits to.
	owner frontend.Variable
	// opening carries the owner masked to zero outside the UTXO domain, hash commits it.
	opening base.AuditOutputWires
	hash    frontend.Variable
	// active is a selected slot, utxo a selected UTXO, only it creates policy obligations.
	active, utxo frontend.Variable
}

type transaction struct {
	inputs  []utxoView
	outputs []utxoView
	nIn     base.Count
	nOut    base.Count
}

// slots lists the inputs then the outputs, the order Subjects follow.
func (tx transaction) slots() []utxoView {
	return append(tx.inputs[:], tx.outputs[:]...)
}

// constrainTransaction binds the openings to the SPP transaction hash.
func (c *CustomRingPolicyCircuit) constrainTransaction(api frontend.API, rc frontend.Rangechecker) transaction {
	nIn, nOut := c.NIn, c.NOut
	inputs, outputs, _, _ := c.wires()
	inputCapacity, outputCapacity := len(inputs), len(outputs)
	if c.FixedInputs != 0 {
		nIn = c.FixedInputs
		inputCapacity = c.FixedInputs
	}
	if c.FixedOutputs != 0 {
		nOut = c.FixedOutputs
		outputCapacity = c.FixedOutputs
	}
	tx := transaction{
		nIn: base.SelectCount(api, nIn, 1, len(inputs)), nOut: base.SelectCount(api, nOut, 1, len(outputs)),
		inputs: make([]utxoView, inputCapacity), outputs: make([]utxoView, outputCapacity),
	}
	inputHashes, outputHashes := make([]frontend.Variable, inputCapacity), make([]frontend.Variable, outputCapacity)
	for i, w := range inputs[:inputCapacity] {
		tx.inputs[i] = w.check(api, rc, tx.nIn.Active[i], true)
		inputHashes[i] = api.Mul(tx.inputs[i].utxo, tx.inputs[i].hash)
	}
	for i, w := range outputs[:outputCapacity] {
		tx.outputs[i] = w.check(api, rc, tx.nOut.Active[i], false)
		outputHashes[i] = api.Mul(tx.outputs[i].utxo, tx.outputs[i].hash)
	}
	api.AssertIsEqual(c.PrivateTxHash, gadget.PoseidonHash(api, []frontend.Variable{
		gadget.NonZeroHashChain(api, inputHashes), gadget.NonZeroHashChain(api, outputHashes), c.AddressChain, c.PrivateTxBlinding,
	}))
	// The anonymous trace discloses no address slot, so its private_tx_hash opens under an empty address chain.
	api.AssertIsEqual(api.Mul(c.Anonymous, c.AddressChain), 0)
	return tx
}

// auditTx hands the audit block the openings an anonymous ring discloses, its count caps the inputs at AuditInputSlots.
func (c *CustomRingPolicyCircuit) auditTx(tx transaction) base.AuditTx {
	inputs, outputs, _, _ := c.wires()
	inputCount := min(base.AuditInputSlots, len(tx.nIn.OneHot))
	out := base.AuditTx{
		Compact: c.specialized(),
		NOut:    tx.nOut,
		NIn:     base.Count{OneHot: tx.nIn.OneHot[:inputCount], Active: tx.nIn.Active[:inputCount]},
	}
	// Anonymous serialization has four fixed slots. Zero extension admits smaller
	// settlement capacities without changing the byte layout or enabling padding.
	for len(out.NIn.Active) < base.AuditInputSlots {
		out.NIn.Active = append(out.NIn.Active, 0)
	}
	for len(out.NIn.OneHot) < base.AuditInputSlots {
		out.NIn.OneHot = append(out.NIn.OneHot, 0)
	}
	for len(out.NOut.Active) < base.AuditOutputSlots {
		out.NOut.Active = append(out.NOut.Active, 0)
	}
	for len(out.NOut.OneHot) < base.AuditOutputSlots {
		out.NOut.OneHot = append(out.NOut.OneHot, 0)
	}
	for i := range out.Outputs {
		out.Outputs[i] = base.AuditOutputWires{Domain: 0, TreeID: 0, OwnerHash: 0, Asset: 0, Amount: 0, Blinding: 0, DataHash: 0, RingDataHash: 0, RingProgramID: 0}
		out.Hashes[i] = 0
		out.Notes[i] = base.AuditUtxoWires{Domain: 0, TreeID: 0, OwnerPkHash: 0, NullifierPk: 0, Asset: 0, Amount: 0, Blinding: 0, DataHash: 0, RingDataHash: 0, RingProgramID: 0}
	}
	for i, output := range tx.outputs {
		out.Outputs[i], out.Hashes[i] = output.opening, output.hash
		out.Notes[i] = base.AuditUtxoWires(outputs[i].UtxoWires)
	}

	for i := range out.Inputs {
		out.Inputs[i] = base.AuditUtxoWires{Domain: 0, TreeID: 0, OwnerPkHash: 0, NullifierPk: 0, Asset: 0, Amount: 0, Blinding: 0, DataHash: 0, RingDataHash: 0, RingProgramID: 0}
		if i < len(tx.inputs) {
			out.Inputs[i] = base.AuditUtxoWires(inputs[i])
		}
	}
	return out
}

// check admits UTXO and dummy slots, and address slots on inputs.
func (w UtxoWires) check(api frontend.API, rc frontend.Rangechecker, active frontend.Variable, input bool) utxoView {
	rc.Check(w.Amount, amountBits)
	isUtxo := api.IsZero(api.Sub(w.Domain, shared.UtxoDomain))
	allowed := api.Add(isUtxo, api.IsZero(api.Sub(w.Domain, shared.DummyDomain)))
	if input {
		allowed = api.Add(allowed, api.IsZero(api.Sub(w.Domain, shared.AddressDomain)))
	}
	shared.AssertWhen(api, active, allowed)
	owner := gadget.PoseidonHash(api, []frontend.Variable{w.OwnerPkHash, w.NullifierPk})
	opening := base.AuditOutputWires{
		Domain: w.Domain, TreeID: w.TreeID, OwnerHash: api.Mul(isUtxo, owner), Asset: w.Asset, Amount: w.Amount,
		Blinding: w.Blinding, DataHash: w.DataHash, RingDataHash: w.RingDataHash, RingProgramID: w.RingProgramID,
	}
	return utxoView{
		ownerPkHash: w.OwnerPkHash, nullifierPk: w.NullifierPk, asset: w.Asset, amount: w.Amount, ringProgramID: w.RingProgramID,
		owner: owner, opening: opening, hash: opening.Hash(api),
		active: active, utxo: api.Mul(active, isUtxo),
	}
}

// The namespace owner administers the ring, it never holds a transaction slot.
func (c *CustomRingPolicyCircuit) constrainNamespace(api frontend.API, tx transaction) {
	for _, slot := range tx.slots() {
		shared.AssertWhen(api, slot.active, base.NonZero(api, api.Sub(slot.owner, c.NamespaceOwnerHash)))
	}
}
