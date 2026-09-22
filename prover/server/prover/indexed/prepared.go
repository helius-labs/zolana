package indexed

import (
	"encoding/json"
	"fmt"
	"math/big"

	"zolana/prover/prover/common"
	merge "zolana/prover/prover/merge"
	transfer "zolana/prover/prover/transfer_eddsa_only"
)

type inputTarget struct {
	slot, nullifier       *big.Int
	dummy                 bool
	state, exclusion      *[]*big.Int
	stateIndex, low, high **big.Int
	exclusionIndex        **big.Int
}

type preparedProof struct {
	value  json.Marshaler
	inputs []inputTarget
	slots  *[]common.TreeSlotParams
	hash   **big.Int
}

func transferTargets(inputs []transfer.InputParams) []inputTarget {
	result := make([]inputTarget, len(inputs))
	for index := range inputs {
		input := &inputs[index]
		result[index] = inputTarget{
			slot: input.TreeSlot, nullifier: input.Nullifier, dummy: input.IsDummy.Sign() != 0,
			state: &input.StatePathElements, stateIndex: &input.StatePathIndex,
			exclusion: &input.NullifierLowPathElements, exclusionIndex: &input.NullifierLowPathIndex,
			low: &input.NullifierLowValue, high: &input.NullifierNextValue,
		}
	}
	return result
}

func decodePrepared(request Request) (*preparedProof, error) {
	var meta struct {
		Circuit common.CircuitType `json:"circuitType"`
	}
	if json.Unmarshal(request.Prepared, &meta) != nil || meta.Circuit != request.CircuitType {
		return nil, fmt.Errorf("prepared circuit mismatch")
	}
	var prepared preparedProof
	shape := common.ProofShape{Circuit: request.CircuitType}
	switch request.CircuitType {
	case common.TransferConfidentialCircuitType, common.TransferRingCircuitType, common.TransferRingAuthorityCircuitType:
		var value transfer.TransferParameters
		if json.Unmarshal(request.Prepared, &value) != nil {
			return nil, fmt.Errorf("invalid prepared transfer")
		}
		if int(value.NInputs) != len(value.Inputs) || int(value.NOutputs) != len(value.Outputs) {
			return nil, fmt.Errorf("prepared counts mismatch")
		}
		shape.Inputs, shape.Outputs = value.NInputs, value.NOutputs
		prepared = preparedProof{value: &value, inputs: transferTargets(value.Inputs), slots: &value.TreeSlots, hash: &value.PublicInputHash}
	case common.TransferP256RingCircuitType:
		var value transfer.P256TransferParameters
		if json.Unmarshal(request.Prepared, &value) != nil {
			return nil, fmt.Errorf("invalid prepared P256 transfer")
		}
		if int(value.NInputs) != len(value.Inputs) || int(value.NOutputs) != len(value.Outputs) {
			return nil, fmt.Errorf("prepared counts mismatch")
		}
		shape.Inputs, shape.Outputs = value.NInputs, value.NOutputs
		prepared = preparedProof{value: &value, inputs: transferTargets(value.Inputs), slots: &value.TreeSlots, hash: &value.PublicInputHash}
	case common.MergeCircuitType, common.MergeRingCircuitType:
		var value merge.MergeParameters
		if json.Unmarshal(request.Prepared, &value) != nil {
			return nil, fmt.Errorf("invalid prepared merge")
		}
		shape.Inputs, shape.Outputs = uint32(len(value.Inputs)), 1
		inputs := make([]inputTarget, len(value.Inputs))
		for index := range value.Inputs {
			input := &value.Inputs[index]
			inputs[index] = inputTarget{
				slot: input.TreeSlot, nullifier: input.Nullifier, dummy: input.Domain.Cmp(big.NewInt(1)) == 0,
				state: &input.StatePathElements, stateIndex: &input.StatePathIndex,
				exclusion: &input.NullifierLowPathElements, exclusionIndex: &input.NullifierLowPathIndex,
				low: &input.NullifierLowValue, high: &input.NullifierNextValue,
			}
		}
		prepared = preparedProof{value: &value, inputs: inputs, slots: &value.TreeSlots, hash: &value.PublicInputHash}
	default:
		return nil, fmt.Errorf("unsupported indexed circuit")
	}
	if !shape.Supported() || len(prepared.inputs) != len(request.Inputs) || len(prepared.inputs) == 0 || len(prepared.inputs) > 36 || len(*prepared.slots) != 0 || (*prepared.hash).Sign() != 0 {
		return nil, fmt.Errorf("invalid prepared shape")
	}
	for index, input := range prepared.inputs {
		lookup := request.Inputs[index]
		if input.slot == nil || !input.slot.IsUint64() || input.slot.Uint64() != uint64(lookup.TreeSlot) || int(lookup.TreeSlot) >= len(request.Trees) || input.dummy != (lookup.Commitment == nil) {
			return nil, fmt.Errorf("input lookup mismatch")
		}
		if len(*input.state) != 0 || len(*input.exclusion) != 0 || (*input.stateIndex).Sign() != 0 || (*input.exclusionIndex).Sign() != 0 || (*input.low).Sign() != 0 || (*input.high).Sign() != 0 {
			return nil, fmt.Errorf("prepared request contains indexer data")
		}
		if _, err := hashField(input.nullifier); err != nil {
			return nil, err
		}
	}
	return &prepared, nil
}

func (input inputTarget) apply(state *stateProof, exclusion nullifierProof) {
	if state == nil {
		*input.state = make([]*big.Int, 32)
		for index := range *input.state {
			(*input.state)[index] = new(big.Int)
		}
	} else {
		*input.state = fields(state.Path)
		*input.stateIndex = new(big.Int).SetUint64(state.LeafIndex)
	}
	*input.exclusion = fields(exclusion.Path)
	*input.exclusionIndex = new(big.Int).SetUint64(exclusion.LowElementIndex)
	*input.low = new(big.Int).SetBytes(exclusion.LowElement[:])
	*input.high = new(big.Int).SetBytes(exclusion.HighElement[:])
}

func fields(hashes []Hash) []*big.Int {
	result := make([]*big.Int, len(hashes))
	for index, hash := range hashes {
		result[index] = new(big.Int).SetBytes(hash[:])
	}
	return result
}
