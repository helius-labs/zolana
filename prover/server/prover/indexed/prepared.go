package indexed

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	txcircuit "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	merge "github.com/helius-labs/zolana/prover/server/prover/merge"
	transfer "github.com/helius-labs/zolana/prover/server/prover/transfer_eddsa"
)

type Input struct {
	Disabled       bool
	Nullifier      *big.Int
	State          *[]*big.Int
	StateIndex     **big.Int
	Exclusion      *[]*big.Int
	ExclusionIndex **big.Int
	Low, High      **big.Int
}

type inputTarget struct {
	Input
	slot                   *big.Int
	dummy, cached, address bool
}

// The resolver writes paths, tree slots and the hash through these pointers.
type Prepared struct {
	Value  json.Marshaler
	Inputs []Input
	Slots  *[]common.TreeSlotParams
	Hash   **big.Int
	// EmptyTrees admits a tree without a real spend.
	EmptyTrees bool
	// Fetch runs beside the tree fetches.
	Fetch func(context.Context, *Resolver) error
	// Statement defaults to HashChain4 when nil.
	Statement func(public []*big.Int, trees *big.Int) (*big.Int, error)
}

func transferTargets(inputs []transfer.InputParams, cache transfer.CacheSelectionParams) ([]inputTarget, error) {
	if err := cache.Validate(len(inputs)); err != nil {
		return nil, err
	}
	result := make([]inputTarget, len(inputs))
	for index := range inputs {
		input := &inputs[index]
		result[index] = inputTarget{
			slot: input.TreeSlot, dummy: input.IsDummy.Sign() != 0,
			address: input.Utxo.Domain.Cmp(big.NewInt(txcircuit.AddressDomain)) == 0,
			Input: Input{
				Nullifier: input.Nullifier,
				State:     &input.StatePathElements, StateIndex: &input.StatePathIndex,
				Exclusion: &input.NullifierLowPathElements, ExclusionIndex: &input.NullifierLowPathIndex,
				Low: &input.NullifierLowValue, High: &input.NullifierNextValue,
			},
		}
		if len(cache.IsCached) != 0 {
			result[index].cached = cache.IsCached[index].Sign() != 0
		}
	}
	return result, nil
}

func decodePrepared(request Request) (*Prepared, error) {
	for _, tree := range request.Trees {
		if tree.Fallback != nil {
			return nil, fmt.Errorf("unexpected fallback roots")
		}
	}
	var prepared struct {
		value  json.Marshaler
		inputs []inputTarget
		slots  *[]common.TreeSlotParams
		hash   **big.Int
	}
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
		inputs, err := transferTargets(value.Inputs, value.Cache)
		if err != nil {
			return nil, err
		}
		prepared.value, prepared.inputs, prepared.slots, prepared.hash = &value, inputs, &value.TreeSlots, &value.PublicInputHash
	case common.TransferConfidentialEddsaCircuitType:
		var value transfer.ConfidentialEddsaTransferParameters
		if json.Unmarshal(request.Prepared, &value) != nil {
			return nil, fmt.Errorf("invalid prepared confidential EdDSA transfer")
		}
		if int(value.NInputs) != len(value.Inputs) || int(value.NOutputs) != len(value.Outputs) {
			return nil, fmt.Errorf("prepared counts mismatch")
		}
		shape.Inputs, shape.Outputs = value.NInputs, value.NOutputs
		inputs, err := transferTargets(value.Inputs, value.Cache)
		if err != nil {
			return nil, err
		}
		prepared.value, prepared.inputs, prepared.slots, prepared.hash = &value, inputs, &value.TreeSlots, &value.PublicInputHash
	case common.TransferAnonymousRingEddsaCircuitType:
		var value transfer.AnonymousEddsaTransferParameters
		if json.Unmarshal(request.Prepared, &value) != nil {
			return nil, fmt.Errorf("invalid prepared EdDSA transfer")
		}
		if int(value.NInputs) != len(value.Inputs) || int(value.NOutputs) != len(value.Outputs) {
			return nil, fmt.Errorf("prepared counts mismatch")
		}
		shape.Inputs, shape.Outputs = value.NInputs, value.NOutputs
		inputs, err := transferTargets(value.Inputs, value.Cache)
		if err != nil {
			return nil, err
		}
		prepared.value, prepared.inputs, prepared.slots, prepared.hash = &value, inputs, &value.TreeSlots, &value.PublicInputHash
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
				slot: input.TreeSlot, dummy: input.Domain.Cmp(big.NewInt(1)) == 0,
				Input: Input{
					Nullifier: input.Nullifier,
					State:     &input.StatePathElements, StateIndex: &input.StatePathIndex,
					Exclusion: &input.NullifierLowPathElements, ExclusionIndex: &input.NullifierLowPathIndex,
					Low: &input.NullifierLowValue, High: &input.NullifierNextValue,
				},
			}
		}
		prepared.value, prepared.inputs, prepared.slots, prepared.hash = &value, inputs, &value.TreeSlots, &value.PublicInputHash
	default:
		return nil, fmt.Errorf("unsupported indexed circuit")
	}
	if !shape.Supported() || len(prepared.inputs) != len(request.Inputs) || len(prepared.inputs) == 0 || len(*prepared.slots) != 0 || (*prepared.hash).Sign() != 0 {
		return nil, fmt.Errorf("invalid prepared shape")
	}
	// Inputs from different trees may interleave, so a dummy only needs an
	// earlier input to have opened the tree it names.
	opened := make([]bool, len(request.Trees))
	for index, input := range prepared.inputs {
		lookup := request.Inputs[index]
		if input.cached && (input.dummy || request.CircuitType == common.TransferRingAuthorityCircuitType) {
			return nil, fmt.Errorf("invalid cached input")
		}
		if input.dummy && (int(lookup.TreeSlot) >= len(opened) || !opened[lookup.TreeSlot]) {
			return nil, fmt.Errorf("input tree starts with a dummy")
		}
		if input.slot == nil || !input.slot.IsUint64() || input.slot.Uint64() != uint64(lookup.TreeSlot) || int(lookup.TreeSlot) >= len(request.Trees) || (input.dummy || input.cached || input.address) != (lookup.Commitment == nil) {
			return nil, fmt.Errorf("input lookup mismatch")
		}
		opened[lookup.TreeSlot] = true
		if len(*input.State) != 0 || len(*input.Exclusion) != 0 || (*input.StateIndex).Sign() != 0 || (*input.ExclusionIndex).Sign() != 0 || (*input.Low).Sign() != 0 || (*input.High).Sign() != 0 {
			return nil, fmt.Errorf("prepared request contains indexer data")
		}
		// Compact padding publishes nullifier 0 but proves non-inclusion of its
		// derived dummy nullifier, which the lookup carries.
		compact := input.dummy && input.Nullifier.Sign() == 0
		if compact != (lookup.Nullifier != nil) {
			return nil, fmt.Errorf("input lookup mismatch")
		}
		if compact {
			nullifier, err := lookup.Nullifier.Field()
			if err != nil {
				return nil, err
			}
			prepared.inputs[index].Nullifier = nullifier
		}
		if _, err := HashField(prepared.inputs[index].Nullifier); err != nil {
			return nil, err
		}
	}
	inputs := make([]Input, len(prepared.inputs))
	for index, input := range prepared.inputs {
		inputs[index] = input.Input
	}
	return &Prepared{Value: prepared.value, Inputs: inputs, Slots: prepared.slots, Hash: prepared.hash}, nil
}

func (input Input) apply(state *stateProof, exclusion nullifierProof) {
	if state == nil {
		*input.State = make([]*big.Int, 32)
		for index := range *input.State {
			(*input.State)[index] = new(big.Int)
		}
	} else {
		*input.State = fields(state.Path)
		*input.StateIndex = new(big.Int).SetUint64(state.LeafIndex)
	}
	*input.Exclusion = fields(exclusion.Path)
	*input.ExclusionIndex = new(big.Int).SetUint64(exclusion.LowElementIndex)
	*input.Low = new(big.Int).SetBytes(exclusion.LowElement[:])
	*input.High = new(big.Int).SetBytes(exclusion.HighElement[:])
}

func fields(hashes []Hash) []*big.Int {
	result := make([]*big.Int, len(hashes))
	for index, hash := range hashes {
		result[index] = new(big.Int).SetBytes(hash[:])
	}
	return result
}
