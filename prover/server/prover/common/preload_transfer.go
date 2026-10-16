package common

import (
	"fmt"
	"strconv"
	"strings"
)

var transferPreloadCircuits = []CircuitType{
	TransferConfidentialCircuitType, TransferRingCircuitType, TransferRingAuthorityCircuitType,
	TransferAnonymousRingEd25519CircuitType, MergeCircuitType, MergeRingCircuitType,
}

// TransferCircuitTypes returns the shared transfer/merge routing and preload set.
func TransferCircuitTypes() []CircuitType {
	return append([]CircuitType(nil), transferPreloadCircuits...)
}

// IsTransfer selects fixed-shape SPP requests, including merge circuits.
func (c CircuitType) IsTransfer() bool {
	for _, supported := range transferPreloadCircuits {
		if c == supported {
			return true
		}
	}
	return false
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
	if !circuit.IsTransfer() {
		return nil, false, nil
	}
	if len(parts) == 1 {
		return m.transferPreloadPaths([]CircuitType{circuit}), true, nil
	}
	if len(parts) != 3 {
		return nil, true, fmt.Errorf("invalid preload shape %q", selector)
	}
	inputs, inputErr := strconv.ParseUint(parts[1], 10, 32)
	outputs, outputErr := strconv.ParseUint(parts[2], 10, 32)
	if inputErr != nil || outputErr != nil {
		return nil, true, fmt.Errorf("invalid preload shape %q", selector)
	}
	path := m.determineTransferKeyPath(circuit, uint32(inputs), uint32(outputs))
	if path == "" {
		return nil, true, fmt.Errorf("unsupported preload shape %q", selector)
	}
	return []string{path}, true, nil
}
