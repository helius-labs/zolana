package common

import (
	"fmt"

	"zolana/prover/logging"
)

// keyEncryptionFoldSupportedKeys is the per-leg recipient count a fold key
// exists for. A fold widens the recipient set by leg count, so only the widest
// leg needs a key.
//
// MUST stay in sync with the zone program's
// `KEY_ENCRYPTION_FOLD_SUPPORTED_LEGS` selector.
var keyEncryptionFoldSupportedKeys = []uint32{3}

// zoneFoldSupportedShapes is the leg shape a zone fold key exists for. Only
// the transfer shape folds. A withdrawal already spends its whole balance.
var zoneFoldSupportedShapes = [][2]uint32{
	{2, 2},
}

// foldSupportedLegs is the leg count both folds have a key for. Two legs is the
// smallest that amortizes a verification.
var foldSupportedLegs = []uint32{2, 3}

// GetKeyEncryptionFoldSystem loads the outer proving system for one per-leg
// recipient count and leg count.
func (m *LazyKeyManager) GetKeyEncryptionFoldSystem(keysPerLeg, legs uint32) (*SquadsKeyEncryptionFoldProofSystem, error) {
	key := fmt.Sprintf("%s_%d_l%d", SquadsKeyEncryptionFoldCircuitType, keysPerLeg, legs)

	m.mu.RLock()
	if ps, exists := m.keyEncFoldSystems[key]; exists {
		m.mu.RUnlock()
		return ps, nil
	}
	m.mu.RUnlock()

	return m.loadKeyEncryptionFoldSystem(key, keysPerLeg, legs)
}

func (m *LazyKeyManager) loadKeyEncryptionFoldSystem(key string, keysPerLeg, legs uint32) (*SquadsKeyEncryptionFoldProofSystem, error) {
	loadChan := m.acquireLoadingLock(key)
	if loadChan == nil {
		m.waitForLoading(key)
		m.mu.RLock()
		ps, exists := m.keyEncFoldSystems[key]
		m.mu.RUnlock()
		if exists {
			return ps, nil
		}
		return nil, fmt.Errorf("loading completed but system not found in cache")
	}
	defer m.releaseLoadingLock(key, loadChan)

	keyPath := m.determineKeyEncryptionFoldKeyPath(keysPerLeg, legs)
	if keyPath == "" {
		return nil, fmt.Errorf("no key file mapping for a fold of %d squads-key-encryption legs of %d keys", legs, keysPerLeg)
	}

	logging.Logger().Info().
		Str("key_path", keyPath).
		Str("cache_key", key).
		Msg("Loading SquadsKeyEncryptionFoldProofSystem")

	if err := EnsureProvingKey(keyPath, m.downloadConfig.AutoDownload, m.downloadConfig); err != nil {
		return nil, fmt.Errorf("failed to ensure key %s: %w", keyPath, err)
	}

	system, err := ReadSystemFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %s: %w", keyPath, err)
	}
	ps, ok := system.(*SquadsKeyEncryptionFoldProofSystem)
	if !ok {
		return nil, fmt.Errorf("expected SquadsKeyEncryptionFoldProofSystem but got different type")
	}
	if ps.KeysPerLeg != keysPerLeg || ps.Legs != legs {
		return nil, fmt.Errorf(
			"key %s folds %d legs of %d keys, request asked for %d legs of %d",
			keyPath, ps.Legs, ps.KeysPerLeg, legs, keysPerLeg,
		)
	}

	m.mu.Lock()
	m.keyEncFoldSystems[key] = ps
	m.mu.Unlock()

	logging.Logger().Info().
		Str("cache_key", key).
		Uint32("keys_per_leg", ps.KeysPerLeg).
		Uint32("legs", ps.Legs).
		Msg("SquadsKeyEncryptionFoldProofSystem loaded and cached successfully")
	return ps, nil
}

// GetZoneFoldSystem loads the outer proving system for one leg shape and leg
// count.
func (m *LazyKeyManager) GetZoneFoldSystem(nInputs, nOutputs, legs uint32) (*SquadsZoneFoldProofSystem, error) {
	key := fmt.Sprintf("%s_%d_%d_l%d", SquadsZoneFoldCircuitType, nInputs, nOutputs, legs)

	m.mu.RLock()
	if ps, exists := m.zoneFoldSystems[key]; exists {
		m.mu.RUnlock()
		return ps, nil
	}
	m.mu.RUnlock()

	return m.loadZoneFoldSystem(key, nInputs, nOutputs, legs)
}

func (m *LazyKeyManager) loadZoneFoldSystem(key string, nInputs, nOutputs, legs uint32) (*SquadsZoneFoldProofSystem, error) {
	loadChan := m.acquireLoadingLock(key)
	if loadChan == nil {
		m.waitForLoading(key)
		m.mu.RLock()
		ps, exists := m.zoneFoldSystems[key]
		m.mu.RUnlock()
		if exists {
			return ps, nil
		}
		return nil, fmt.Errorf("loading completed but system not found in cache")
	}
	defer m.releaseLoadingLock(key, loadChan)

	keyPath := m.determineZoneFoldKeyPath(nInputs, nOutputs, legs)
	if keyPath == "" {
		return nil, fmt.Errorf("no key file mapping for a fold of %d squads-zone %dx%d legs", legs, nInputs, nOutputs)
	}

	logging.Logger().Info().
		Str("key_path", keyPath).
		Str("cache_key", key).
		Msg("Loading SquadsZoneFoldProofSystem")

	if err := EnsureProvingKey(keyPath, m.downloadConfig.AutoDownload, m.downloadConfig); err != nil {
		return nil, fmt.Errorf("failed to ensure key %s: %w", keyPath, err)
	}

	system, err := ReadSystemFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %s: %w", keyPath, err)
	}
	ps, ok := system.(*SquadsZoneFoldProofSystem)
	if !ok {
		return nil, fmt.Errorf("expected SquadsZoneFoldProofSystem but got different type")
	}
	if ps.NInputs != nInputs || ps.NOutputs != nOutputs || ps.Legs != legs {
		return nil, fmt.Errorf(
			"key %s folds %d %dx%d legs, request asked for %d %dx%d",
			keyPath, ps.Legs, ps.NInputs, ps.NOutputs, legs, nInputs, nOutputs,
		)
	}

	m.mu.Lock()
	m.zoneFoldSystems[key] = ps
	m.mu.Unlock()

	logging.Logger().Info().
		Str("cache_key", key).
		Uint32("legs", ps.Legs).
		Msg("SquadsZoneFoldProofSystem loaded and cached successfully")
	return ps, nil
}

func (m *LazyKeyManager) determineKeyEncryptionFoldKeyPath(keysPerLeg, legs uint32) string {
	if !supportedLegs(legs) {
		return ""
	}
	for _, supported := range keyEncryptionFoldSupportedKeys {
		if supported == keysPerLeg {
			return m.keyPath(fmt.Sprintf("squads_key_encryption_fold_%d_l%d.key", keysPerLeg, legs))
		}
	}
	return ""
}

func (m *LazyKeyManager) determineZoneFoldKeyPath(nInputs, nOutputs, legs uint32) string {
	if !supportedLegs(legs) {
		return ""
	}
	for _, shape := range zoneFoldSupportedShapes {
		if shape[0] == nInputs && shape[1] == nOutputs {
			return m.keyPath(fmt.Sprintf("squads_zone_fold_%d_%d_l%d.key", nInputs, nOutputs, legs))
		}
	}
	return ""
}

func supportedLegs(legs uint32) bool {
	for _, supported := range foldSupportedLegs {
		if supported == legs {
			return true
		}
	}
	return false
}
