package merge

import (
	"fmt"

	mergecircuit "zolana/prover/circuits/spp_merge"
	transaction "zolana/prover/circuits/spp_transaction/shared"
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
		return p.createRingWitness()
	}
	return p.createDefaultWitness()
}

func (p *MergeParameters) createDefaultWitness() (*mergecircuit.Circuit, error) {
	circuit := mergecircuit.NewMergeCircuit()

	circuit.OwnerPkHash = p.OwnerPkHash
	circuit.UserNullifierPk = p.UserNullifierPk
	circuit.UserNullifierSecret = p.UserNullifierSecret
	circuit.Asset = p.Asset
	circuit.ExternalDataHash = p.ExternalDataHash
	circuit.PrivateTxHash = p.PrivateTxHash
	circuit.OutputHash = p.Output.Hash
	circuit.AllowDummyInputs = p.AllowDummyInputs
	circuit.OutputTreeID = p.OutputTreeID
	circuit.UserSigningPkHash = p.OwnerPkHash
	circuit.PublicInputHash = p.PublicInputHash

	if err := p.assignTreeSlots(circuit.TreeSlots); err != nil {
		return nil, err
	}
	for i := range p.Inputs {
		circuit.Inputs[i] = p.inputAt(i)
		circuit.Nullifiers[i] = p.Inputs[i].Nullifier
	}

	circuit.Output = mergecircuit.Output{
		RingDataHash: p.Output.RingDataHash,
	}

	return circuit, nil
}

func (p *MergeParameters) createRingWitness() (*mergecircuit.RingCircuit, error) {
	circuit := mergecircuit.NewMergeRingCircuit()

	circuit.OwnerPkHash = p.OwnerPkHash
	circuit.UserNullifierPk = p.UserNullifierPk
	circuit.UserNullifierSecret = p.UserNullifierSecret
	circuit.Asset = p.Asset
	circuit.ExternalDataHash = p.ExternalDataHash
	circuit.PrivateTxHash = p.PrivateTxHash
	circuit.OutputHash = p.Output.Hash
	circuit.AllowDummyInputs = p.AllowDummyInputs
	circuit.OutputTreeID = p.OutputTreeID
	circuit.OutputRingDataHash = p.OutputRingDataHash
	circuit.RingProgramID = p.RingProgramID
	circuit.PublicInputHash = p.PublicInputHash

	if err := p.assignTreeSlots(circuit.TreeSlots); err != nil {
		return nil, err
	}
	for i := range p.Inputs {
		circuit.Inputs[i] = p.inputAt(i)
		circuit.Nullifiers[i] = p.Inputs[i].Nullifier
	}

	circuit.Output = mergecircuit.Output{
		RingDataHash: p.Output.RingDataHash,
	}

	return circuit, nil
}

// assignTreeSlots fills the circuit's pre-allocated slots. The count is fixed
// by the compiled skeleton, so a request with any other count is rejected here
// as well as in ValidateShape: CreateWitness is reachable without it.
func (p *MergeParameters) assignTreeSlots(slots []transaction.TreeSlot) error {
	if len(p.TreeSlots) != len(slots) {
		return fmt.Errorf("merge: tree slot count mismatch: got %d want %d", len(p.TreeSlots), len(slots))
	}
	for k, slot := range p.TreeSlots {
		slots[k] = transaction.TreeSlot{
			ID:            slot.ID,
			UtxoRoot:      slot.UtxoRoot,
			NullifierRoot: slot.NullifierRoot,
		}
	}
	return nil
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
		TreeSlot:                 in.TreeSlot,
		NullifierLowValue:        in.NullifierLowValue,
		NullifierNextValue:       in.NullifierNextValue,
		NullifierLowPathElements: nullifierPath,
		NullifierLowPathIndex:    in.NullifierLowPathIndex,
	}
}
