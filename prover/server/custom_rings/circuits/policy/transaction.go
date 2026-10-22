package policy

import (
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana/prover/server/circuits/gadget"
	"github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/base"
)

// OutputWires adds the key ciphertext hash the owner's record escrows, read only under key escrow.
type OutputWires struct {
	base.UtxoWires
	CtHash frontend.Variable
}

type utxoView struct {
	ownerPkHash, nullifierPk, asset, amount, ringProgramID frontend.Variable
	// utxo is set for a UTXO slot, the only kind that carries a policy obligation.
	utxo frontend.Variable
	// hash is the UTXO hash, zero for every other kind as private_tx_hash chains them.
	hash frontend.Variable
}

// openInputs reopens the delegate's inputs and chains their UTXO hashes as SPP does.
func openInputs(api frontend.API, wires []base.UtxoWires) ([]utxoView, frontend.Variable) {
	inputs := make([]utxoView, len(wires))
	hashes := make([]frontend.Variable, len(wires))
	for i, w := range wires {
		inputs[i] = open(api, w)
		hashes[i] = inputs[i].hash
	}
	return inputs, gadget.NonZeroHashChain(api, hashes)
}

// openOutputs reopens every output and binds them, beside the rail's input chain, to private_tx_hash.
func (p *Policy) openOutputs(api frontend.API, inputChain frontend.Variable) []utxoView {
	outputs := make([]utxoView, len(p.Outputs))
	hashes := make([]frontend.Variable, len(p.Outputs))
	for o, w := range p.Outputs {
		outputs[o] = open(api, w.UtxoWires)
		hashes[o] = outputs[o].hash
	}
	outputChain := gadget.NonZeroHashChain(api, hashes)
	// The outputs are the ones SPP settles, the SPP proof binds the same private_tx_hash.
	api.AssertIsEqual(p.PrivateTxHash, shared.PrivateTxHashFromChains(api, inputChain, outputChain, p.AddressChain, p.PrivateTxBlinding))
	return outputs
}

// open reads a slot through its SPP hash, a slot of another kind contributes nothing to private_tx_hash.
func open(api frontend.API, w base.UtxoWires) utxoView {
	opened := w.Open(api)
	return utxoView{
		ownerPkHash:   w.OwnerPkHash,
		nullifierPk:   w.NullifierPk,
		asset:         w.Asset,
		amount:        w.Amount,
		ringProgramID: w.RingProgramID,
		utxo:          opened.Utxo,
		hash:          api.Mul(opened.Utxo, opened.Hash),
	}
}
