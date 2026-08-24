package merge

import (
	mergecircuit "zolana/prover/circuits/spp_merge"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark/frontend"
)

// CreateWitness assigns the pre-computed parameters onto the merge circuit. It
// performs no hashing — every signal is taken verbatim from the client params.
// The merge-ring rail (CircuitType == MergeRingCircuitType) is assigned onto the
// policy-ring circuit, which additionally carries the top-level
// OutputRingDataHash and RingProgramID; every other rail uses the default merge
// circuit.
func (p *MergeParameters) CreateWitness() (frontend.Circuit, error) {
	if p.CircuitType == common.MergeRingCircuitType {
		return p.createRingWitness(), nil
	}
	return p.createDefaultWitness(), nil
}

func (p *MergeParameters) createDefaultWitness() *mergecircuit.Circuit {
	circuit := mergecircuit.NewMergeCircuit()

	circuit.OwnerPkHash = p.OwnerPkHash
	circuit.UserNullifierPk = p.UserNullifierPk
	circuit.UserNullifierSecret = p.UserNullifierSecret
	circuit.Asset = p.Asset
	circuit.ExternalDataHash = p.ExternalDataHash
	circuit.PrivateTxHash = p.PrivateTxHash
	circuit.PrivateTxBlinding = p.PrivateTxBlinding
	circuit.OutputHash = p.Output.Hash
	circuit.AllowDummyInputs = p.AllowDummyInputs
	circuit.UserSigningPkHash = p.OwnerPkHash
	circuit.PublicInputHash = p.PublicInputHash

	for i := range p.Inputs {
		circuit.Inputs[i] = p.inputAt(i)
		circuit.Nullifiers[i] = p.Inputs[i].Nullifier
		circuit.UtxoTreeRoots[i] = p.Inputs[i].UtxoTreeRoot
		circuit.NullifierTreeRoots[i] = p.Inputs[i].NullifierTreeRoot
	}

	circuit.Output = mergecircuit.Output{
		RingDataHash: p.Output.RingDataHash,
	}

	return circuit
}

func (p *MergeParameters) createRingWitness() *mergecircuit.RingCircuit {
	circuit := mergecircuit.NewMergeRingCircuit()

	circuit.OwnerPkHash = p.OwnerPkHash
	circuit.UserNullifierPk = p.UserNullifierPk
	circuit.UserNullifierSecret = p.UserNullifierSecret
	circuit.Asset = p.Asset
	circuit.ExternalDataHash = p.ExternalDataHash
	circuit.PrivateTxHash = p.PrivateTxHash
	circuit.PrivateTxBlinding = p.PrivateTxBlinding
	circuit.OutputHash = p.Output.Hash
	circuit.AllowDummyInputs = p.AllowDummyInputs
	circuit.OutputRingDataHash = p.OutputRingDataHash
	circuit.RingProgramID = p.RingProgramID
	circuit.PublicInputHash = p.PublicInputHash

	for i := range p.Inputs {
		circuit.Inputs[i] = p.inputAt(i)
		circuit.Nullifiers[i] = p.Inputs[i].Nullifier
		circuit.UtxoTreeRoots[i] = p.Inputs[i].UtxoTreeRoot
		circuit.NullifierTreeRoots[i] = p.Inputs[i].NullifierTreeRoot
	}

	circuit.Output = mergecircuit.Output{
		RingDataHash: p.Output.RingDataHash,
	}

	return circuit
}

func (p *MergeParameters) inputAt(i int) mergecircuit.Input {
	in := p.Inputs[i]
	statePath := make([]frontend.Variable, len(in.StatePathElements))
	for j := range in.StatePathElements {
		statePath[j] = in.StatePathElements[j]
	}
	nullifierPath := make([]frontend.Variable, len(in.NullifierLowPathElements))
	for j := range in.NullifierLowPathElements {
		nullifierPath[j] = in.NullifierLowPathElements[j]
	}
	return mergecircuit.Input{
		Domain:                   in.Domain,
		Amount:                   in.Amount,
		Blinding:                 in.Blinding,
		RingDataHash:             in.RingDataHash,
		StatePathElements:        statePath,
		StatePathIndex:           in.StatePathIndex,
		NullifierLowValue:        in.NullifierLowValue,
		NullifierNextValue:       in.NullifierNextValue,
		NullifierLowPathElements: nullifierPath,
		NullifierLowPathIndex:    in.NullifierLowPathIndex,
	}
}
