package common

import (
	"fmt"
	"strconv"
	"strings"
)

var transferPreloadCircuits = []CircuitType{
	TransferConfidentialCircuitType, TransferRingCircuitType, TransferRingAuthorityCircuitType,
	TransferP256RingCircuitType, MergeCircuitType, MergeRingCircuitType,
}

func (m *LazyKeyManager) transferPreloadPaths(circuits []CircuitType) []string {
	var paths []string
	for _, circuit := range circuits {
		for _, shape := range transferSupportedShapes {
			if path := m.determineTransferKeyPath(circuit, shape[0], shape[1]); path != "" {
				paths = append(paths, path)
			}
		}
		for _, inputs := range mergeSupportedInputCounts {
			if path := m.determineTransferKeyPath(circuit, inputs, 1); path != "" {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

func (m *LazyKeyManager) selectedTransferPaths(selector string) ([]string, bool, error) {
	parts := strings.Split(selector, ":")
	circuit := CircuitType(parts[0])
	found := false
	for _, supported := range transferPreloadCircuits {
		found = found || circuit == supported
	}
	if !found {
		return nil, false, nil
	}
	if len(parts) == 1 {
		return m.transferPreloadPaths([]CircuitType{circuit}), true, nil
	}
	if len(parts) != 3 {
		return nil, true, fmt.Errorf("invalid preload shape")
	}
	inputs, inputErr := strconv.ParseUint(parts[1], 10, 32)
	outputs, outputErr := strconv.ParseUint(parts[2], 10, 32)
	if inputErr != nil || outputErr != nil {
		return nil, true, fmt.Errorf("invalid preload shape")
	}
	path := m.determineTransferKeyPath(circuit, uint32(inputs), uint32(outputs))
	if path == "" {
		return nil, true, fmt.Errorf("unsupported preload shape")
	}
	return []string{path}, true, nil
}
