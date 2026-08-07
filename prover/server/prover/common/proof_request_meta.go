package common

import (
	"encoding/json"
	"fmt"
)

type ProofRequestMeta struct {
	CircuitType       CircuitType
	Version           uint32
	StateTreeHeight   uint32
	AddressTreeHeight uint32
	TreeHeight        uint32
	NumInputs         uint32
	NumOutputs        uint32
	NumAddresses      uint32
	// TreeID is the merkle tree pubkey. The queue schedules fairly across trees.
	TreeID string
	// BatchIndex orders batches within a tree. Lower indices are processed first
	// so transactions can be submitted sequentially.
	BatchIndex int64
}

func ParseProofRequestMeta(data []byte) (ProofRequestMeta, error) {
	var rawInput map[string]interface{}
	err := json.Unmarshal(data, &rawInput)
	if err != nil {
		return ProofRequestMeta{}, fmt.Errorf("failed to parse JSON: %w", err)
	}

	addressTreeHeight := uint32(0)
	if height, ok := rawInput["addressTreeHeight"].(float64); ok && height > 0 {
		addressTreeHeight = uint32(height)
	}

	treeHeight := uint32(0)
	if height, ok := rawInput["treeHeight"].(float64); ok && height > 0 {
		treeHeight = uint32(height)
	}

	if height, ok := rawInput["height"].(float64); ok && height > 0 && treeHeight == 0 {
		treeHeight = uint32(height)
	}
	stateTreeHeight := uint32(0)
	if height, ok := rawInput["stateTreeHeight"].(float64); ok && height > 0 {
		stateTreeHeight = uint32(height)
	}

	circuitType, ok := rawInput["circuitType"].(string)
	if !ok || circuitType == "" {
		return ProofRequestMeta{}, fmt.Errorf("missing or invalid 'circuitType' %s", rawInput)
	}

	// Transfer, merge, aggregate, and merge-chain circuits are keyed by their
	// fixed shape instead of a tree height, so they are exempt from the
	// tree-height requirement below.
	isShapeKeyed := CircuitType(circuitType) == TransferConfidentialCircuitType ||
		CircuitType(circuitType) == TransferRingCircuitType ||
		CircuitType(circuitType) == TransferP256RingCircuitType ||
		CircuitType(circuitType) == TransferRingAuthorityCircuitType ||
		CircuitType(circuitType) == AggregateCircuitType ||
		CircuitType(circuitType) == MergeCircuitType ||
		CircuitType(circuitType) == MergeRingCircuitType ||
		CircuitType(circuitType) == MergeChainCircuitType

	// nInputs/nOutputs feed logging and metrics only. The handler re-reads the
	// authoritative values from the unmarshalled params.
	nInputs := uint32(0)
	if v, ok := rawInput["nInputs"].(float64); ok && v > 0 {
		nInputs = uint32(v)
	}
	nOutputs := uint32(0)
	if v, ok := rawInput["nOutputs"].(float64); ok && v > 0 {
		nOutputs = uint32(v)
	}

	if !isShapeKeyed && addressTreeHeight == 0 && stateTreeHeight == 0 && treeHeight == 0 {
		return ProofRequestMeta{}, fmt.Errorf("no 'addressTreeHeight', 'stateTreeHeight', or 'treeHeight' provided")
	}

	version := uint32(1)
	publicInputsHash, _ := rawInput["publicInputHash"].(string)
	if publicInputsHash != "" {
		version = 2
	}

	numInputs := 0
	if inclusionInputs, ok := rawInput["inputCompressedAccounts"].([]interface{}); ok {
		numInputs = len(inclusionInputs)
	}
	// Transfer circuits report their shape via nInputs/nOutputs.
	if isShapeKeyed {
		numInputs = int(nInputs)
	}

	numAddresses := 0
	if nonInclusionInputs, ok := rawInput["newAddresses"].([]interface{}); ok {
		numAddresses = len(nonInclusionInputs)
	}

	treeID := ""
	if id, ok := rawInput["treeId"].(string); ok {
		treeID = id
	}

	// -1 means the request carries no batch index.
	batchIndex := int64(-1)
	if idx, ok := rawInput["batchIndex"].(float64); ok {
		batchIndex = int64(idx)
	}

	return ProofRequestMeta{
		Version:           version,
		CircuitType:       CircuitType(circuitType),
		StateTreeHeight:   stateTreeHeight,
		AddressTreeHeight: addressTreeHeight,
		NumInputs:         uint32(numInputs),
		NumOutputs:        nOutputs,
		NumAddresses:      uint32(numAddresses),
		TreeID:            treeID,
		BatchIndex:        batchIndex,
	}, nil
}
