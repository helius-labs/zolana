package common

import (
	"fmt"
	"slices"

	"zolana/prover/logging"
)

// GetAggregateSystem loads the outer proving system for one batched rail,
// shape, and batch size.
func (m *LazyKeyManager) GetAggregateSystem(inner CircuitType, nInputs, nOutputs, batch uint32) (*AggregateProofSystem, error) {
	slots := make([]AggregateSlot, batch)
	for i := range slots {
		slots[i] = AggregateSlot{Inner: inner, NInputs: nInputs, NOutputs: nOutputs}
	}
	return m.GetAggregateSystemSlots(slots)
}

// GetAggregateSystemSlots loads the outer proving system for one ordered slot
// list, mixed or uniform.
func (m *LazyKeyManager) GetAggregateSystemSlots(slots []AggregateSlot) (*AggregateProofSystem, error) {
	key := AggregateKeyName(slots)

	m.mu.RLock()
	if ps, exists := m.aggregateSystems[key]; exists {
		m.mu.RUnlock()
		return ps, nil
	}
	m.mu.RUnlock()

	return m.loadAggregateSystem(key, slots)
}

func (m *LazyKeyManager) loadAggregateSystem(key string, slots []AggregateSlot) (*AggregateProofSystem, error) {
	loadChan := m.acquireLoadingLock(key)
	if loadChan == nil {
		m.waitForLoading(key)
		m.mu.RLock()
		ps, exists := m.aggregateSystems[key]
		m.mu.RUnlock()
		if exists {
			return ps, nil
		}
		return nil, fmt.Errorf("loading completed but system not found in cache")
	}
	defer m.releaseLoadingLock(key, loadChan)

	keyPath := m.determineAggregateKeyPath(slots)
	if keyPath == "" {
		return nil, fmt.Errorf("no key file mapping for the aggregate %s", key)
	}

	logging.Logger().Info().
		Str("key_path", keyPath).
		Str("cache_key", key).
		Msg("Loading AggregateProofSystem")

	if err := EnsureProvingKey(keyPath, m.downloadConfig.AutoDownload, m.downloadConfig); err != nil {
		return nil, fmt.Errorf("failed to download key %s: %w", keyPath, err)
	}

	system, err := ReadSystemFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %s: %w", keyPath, err)
	}
	ps, ok := system.(*AggregateProofSystem)
	if !ok {
		return nil, fmt.Errorf("expected AggregateProofSystem but got different type")
	}
	// The header is authoritative over the file name. A mismatch means the key
	// batches different circuits than the request asked for.
	if !slices.Equal(ps.Slots, slots) {
		return nil, fmt.Errorf("key %s batches %s, request asked for %s", keyPath, ps.KeyName(), key)
	}

	m.mu.Lock()
	m.aggregateSystems[key] = ps
	m.mu.Unlock()

	logging.Logger().Info().
		Str("cache_key", key).
		Msg("AggregateProofSystem loaded and cached successfully")
	return ps, nil
}

// determineAggregateKeyPath maps a slot list to its key file. Every transfer
// slot must be a supported shape, so a request cannot pull an arbitrary file
// name from disk.
func (m *LazyKeyManager) determineAggregateKeyPath(slots []AggregateSlot) string {
	for _, slot := range slots {
		if slot.Inner == SwapTakeCircuitType {
			continue
		}
		if _, err := AggregatableRail(slot.Inner); err != nil {
			return ""
		}
		supported := false
		for _, shape := range transferSupportedShapes {
			if shape[0] == slot.NInputs && shape[1] == slot.NOutputs {
				supported = true
				break
			}
		}
		if !supported {
			return ""
		}
	}
	return m.keyPath(AggregateKeyName(slots))
}
