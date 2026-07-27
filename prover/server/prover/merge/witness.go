package merge

import (
	mergecircuit "zolana/prover/circuits/spp_merge"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark/frontend"
)

// CreateWitness assigns the pre-computed parameters onto the merge circuit. It
// performs no hashing — every signal is taken verbatim from the client params.
// The merge-zone rail (CircuitType == MergeZoneCircuitType) is assigned onto the
// policy-zone circuit, which additionally carries the top-level
// OutputZoneDataHash and ZoneProgramID; every other rail uses the default merge
// circuit.
func (p *MergeParameters) CreateWitness() (frontend.Circuit, error) {
	if p.CircuitType == common.MergeZoneCircuitType {
		return p.createZoneWitness(), nil
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
		ZoneDataHash: p.Output.ZoneDataHash,
	}

	return circuit
}

func (p *MergeParameters) createZoneWitness() *mergecircuit.ZoneCircuit {
	circuit := mergecircuit.NewMergeZoneCircuit()

	circuit.OwnerPkHash = p.OwnerPkHash
	circuit.UserNullifierPk = p.UserNullifierPk
	circuit.UserNullifierSecret = p.UserNullifierSecret
	circuit.Asset = p.Asset
	circuit.ExternalDataHash = p.ExternalDataHash
	circuit.PrivateTxHash = p.PrivateTxHash
	circuit.OutputHash = p.Output.Hash
	circuit.AllowDummyInputs = p.AllowDummyInputs
	circuit.OutputZoneDataHash = p.OutputZoneDataHash
	circuit.ZoneProgramID = p.ZoneProgramID
	circuit.PublicInputHash = p.PublicInputHash

	for i := range p.Inputs {
		circuit.Inputs[i] = p.inputAt(i)
		circuit.Nullifiers[i] = p.Inputs[i].Nullifier
		circuit.UtxoTreeRoots[i] = p.Inputs[i].UtxoTreeRoot
		circuit.NullifierTreeRoots[i] = p.Inputs[i].NullifierTreeRoot
	}

	circuit.Output = mergecircuit.Output{
		ZoneDataHash: p.Output.ZoneDataHash,
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
		ZoneDataHash:             in.ZoneDataHash,
		StatePathElements:        statePath,
		StatePathIndex:           in.StatePathIndex,
		NullifierLowValue:        in.NullifierLowValue,
		NullifierNextValue:       in.NullifierNextValue,
		NullifierLowPathElements: nullifierPath,
		NullifierLowPathIndex:    in.NullifierLowPathIndex,
	}
}
