package common

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"zolana/prover/logging"
)

type LazyKeyManager struct {
	mu                   sync.RWMutex
	batchSystems         map[string]*BatchProofSystem
	transferSystems      map[string]*TransferProofSystem
	aggregateSystems     map[string]*AggregateProofSystem
	nullifierFoldSystems map[string]*NullifierFoldProofSystem
	mergeChainSystems    map[string]*MergeChainProofSystem
	ringSystems          map[string]*SquadsRingProofSystem
	keyEncSystems        map[string]*SquadsKeyEncryptionProofSystem
	ringFoldSystems      map[string]*SquadsRingFoldProofSystem
	keyEncFoldSystems    map[string]*SquadsKeyEncryptionFoldProofSystem
	keysDir              string
	downloadConfig       *DownloadConfig
	loadingInProgress    map[string]chan struct{}
}

func NewLazyKeyManager(keysDir string, downloadConfig *DownloadConfig) *LazyKeyManager {
	if downloadConfig == nil {
		downloadConfig = DefaultDownloadConfig()
	}
	return &LazyKeyManager{
		batchSystems:         make(map[string]*BatchProofSystem),
		transferSystems:      make(map[string]*TransferProofSystem),
		aggregateSystems:     make(map[string]*AggregateProofSystem),
		nullifierFoldSystems: make(map[string]*NullifierFoldProofSystem),
		mergeChainSystems:    make(map[string]*MergeChainProofSystem),
		ringSystems:          make(map[string]*SquadsRingProofSystem),
		keyEncSystems:        make(map[string]*SquadsKeyEncryptionProofSystem),
		ringFoldSystems:      make(map[string]*SquadsRingFoldProofSystem),
		keyEncFoldSystems:    make(map[string]*SquadsKeyEncryptionFoldProofSystem),
		keysDir:              keysDir,
		downloadConfig:       downloadConfig,
		loadingInProgress:    make(map[string]chan struct{}),
	}
}

func (m *LazyKeyManager) GetBatchSystem(circuitType CircuitType, treeHeight uint32, batchSize uint32) (*BatchProofSystem, error) {
	key := fmt.Sprintf("%s_%d_%d", circuitType, treeHeight, batchSize)

	m.mu.RLock()
	if ps, exists := m.batchSystems[key]; exists {
		m.mu.RUnlock()
		logging.Logger().Debug().
			Str("key", key).
			Msg("Found cached BatchProofSystem")
		return ps, nil
	}
	m.mu.RUnlock()

	return m.loadBatchSystem(key, circuitType, treeHeight, batchSize)
}

func (m *LazyKeyManager) GetTransferSystem(circuitType CircuitType, nInputs uint32, nOutputs uint32) (*TransferProofSystem, error) {
	key := fmt.Sprintf("%s_%d_%d", circuitType, nInputs, nOutputs)

	m.mu.RLock()
	if ps, exists := m.transferSystems[key]; exists {
		m.mu.RUnlock()
		logging.Logger().Debug().
			Str("key", key).
			Msg("Found cached TransferProofSystem")
		return ps, nil
	}
	m.mu.RUnlock()

	return m.loadTransferSystem(key, circuitType, nInputs, nOutputs)
}

func (m *LazyKeyManager) GetRingSystem(nInputs uint32, nOutputs uint32) (*SquadsRingProofSystem, error) {
	key := fmt.Sprintf("%s_%d_%d", SquadsRingCircuitType, nInputs, nOutputs)

	m.mu.RLock()
	if ps, exists := m.ringSystems[key]; exists {
		m.mu.RUnlock()
		logging.Logger().Debug().
			Str("key", key).
			Msg("Found cached SquadsRingProofSystem")
		return ps, nil
	}
	m.mu.RUnlock()

	return m.loadRingSystem(key, nInputs, nOutputs)
}

func (m *LazyKeyManager) loadRingSystem(key string, nInputs uint32, nOutputs uint32) (*SquadsRingProofSystem, error) {
	loadChan := m.acquireLoadingLock(key)
	if loadChan == nil {
		m.waitForLoading(key)
		m.mu.RLock()
		ps, exists := m.ringSystems[key]
		m.mu.RUnlock()
		if exists {
			return ps, nil
		}
		return nil, fmt.Errorf("loading completed but system not found in cache")
	}
	defer m.releaseLoadingLock(key, loadChan)

	keyPath := m.determineRingKeyPath(nInputs, nOutputs)
	if keyPath == "" {
		return nil, fmt.Errorf("no key file mapping for squads-ring with %d inputs and %d outputs", nInputs, nOutputs)
	}

	logging.Logger().Info().
		Str("key_path", keyPath).
		Str("cache_key", key).
		Msg("Loading SquadsRingProofSystem")

	if err := EnsureProvingKey(keyPath, m.downloadConfig.AutoDownload, m.downloadConfig); err != nil {
		return nil, fmt.Errorf("failed to ensure key %s: %w", keyPath, err)
	}

	system, err := ReadSystemFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %s: %w", keyPath, err)
	}

	ps, ok := system.(*SquadsRingProofSystem)
	if !ok {
		return nil, fmt.Errorf("expected SquadsRingProofSystem but got different type")
	}

	m.mu.Lock()
	m.ringSystems[key] = ps
	m.mu.Unlock()

	logging.Logger().Info().
		Str("cache_key", key).
		Uint32("n_inputs", ps.NInputs).
		Uint32("n_outputs", ps.NOutputs).
		Msg("SquadsRingProofSystem loaded and cached successfully")

	return ps, nil
}

func (m *LazyKeyManager) GetKeyEncryptionSystem(numKeys uint32) (*SquadsKeyEncryptionProofSystem, error) {
	key := fmt.Sprintf("%s_%d", SquadsKeyEncryptionCircuitType, numKeys)

	m.mu.RLock()
	if ps, exists := m.keyEncSystems[key]; exists {
		m.mu.RUnlock()
		logging.Logger().Debug().
			Str("key", key).
			Msg("Found cached SquadsKeyEncryptionProofSystem")
		return ps, nil
	}
	m.mu.RUnlock()

	return m.loadKeyEncryptionSystem(key, numKeys)
}

func (m *LazyKeyManager) loadKeyEncryptionSystem(key string, numKeys uint32) (*SquadsKeyEncryptionProofSystem, error) {
	loadChan := m.acquireLoadingLock(key)
	if loadChan == nil {
		m.waitForLoading(key)
		m.mu.RLock()
		ps, exists := m.keyEncSystems[key]
		m.mu.RUnlock()
		if exists {
			return ps, nil
		}
		return nil, fmt.Errorf("loading completed but system not found in cache")
	}
	defer m.releaseLoadingLock(key, loadChan)

	keyPath := m.determineKeyEncryptionKeyPath(numKeys)
	if keyPath == "" {
		return nil, fmt.Errorf("no key file mapping for squads-key-encryption with %d keys", numKeys)
	}

	logging.Logger().Info().
		Str("key_path", keyPath).
		Str("cache_key", key).
		Msg("Loading SquadsKeyEncryptionProofSystem")

	if err := EnsureProvingKey(keyPath, m.downloadConfig.AutoDownload, m.downloadConfig); err != nil {
		return nil, fmt.Errorf("failed to ensure key %s: %w", keyPath, err)
	}

	system, err := ReadSystemFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %s: %w", keyPath, err)
	}

	ps, ok := system.(*SquadsKeyEncryptionProofSystem)
	if !ok {
		return nil, fmt.Errorf("expected SquadsKeyEncryptionProofSystem but got different type")
	}

	m.mu.Lock()
	m.keyEncSystems[key] = ps
	m.mu.Unlock()

	logging.Logger().Info().
		Str("cache_key", key).
		Uint32("num_keys", ps.NumKeys).
		Msg("SquadsKeyEncryptionProofSystem loaded and cached successfully")

	return ps, nil
}

func (m *LazyKeyManager) loadBatchSystem(key string, circuitType CircuitType, treeHeight uint32, batchSize uint32) (*BatchProofSystem, error) {
	loadChan := m.acquireLoadingLock(key)
	if loadChan == nil {
		m.waitForLoading(key)
		m.mu.RLock()
		ps, exists := m.batchSystems[key]
		m.mu.RUnlock()
		if exists {
			return ps, nil
		}
		return nil, fmt.Errorf("loading completed but system not found in cache")
	}
	defer m.releaseLoadingLock(key, loadChan)

	keyPath := m.determineBatchKeyPath(circuitType, treeHeight, batchSize)
	if keyPath == "" {
		return nil, fmt.Errorf("no key file mapping for %s with height %d and batch size %d", circuitType, treeHeight, batchSize)
	}

	logging.Logger().Info().
		Str("key_path", keyPath).
		Str("cache_key", key).
		Msg("Loading BatchProofSystem")

	if err := EnsureProvingKey(keyPath, m.downloadConfig.AutoDownload, m.downloadConfig); err != nil {
		return nil, fmt.Errorf("failed to download key %s: %w", keyPath, err)
	}

	system, err := ReadSystemFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %s: %w", keyPath, err)
	}

	ps, ok := system.(*BatchProofSystem)
	if !ok {
		return nil, fmt.Errorf("expected BatchProofSystem but got different type")
	}

	m.mu.Lock()
	m.batchSystems[key] = ps
	m.mu.Unlock()

	logging.Logger().Info().
		Str("cache_key", key).
		Uint32("tree_height", ps.TreeHeight).
		Uint32("batch_size", ps.BatchSize).
		Str("circuit_type", string(ps.CircuitType)).
		Msg("BatchProofSystem loaded and cached successfully")

	return ps, nil
}

func (m *LazyKeyManager) loadTransferSystem(key string, circuitType CircuitType, nInputs uint32, nOutputs uint32) (*TransferProofSystem, error) {
	loadChan := m.acquireLoadingLock(key)
	if loadChan == nil {
		m.waitForLoading(key)
		m.mu.RLock()
		ps, exists := m.transferSystems[key]
		m.mu.RUnlock()
		if exists {
			return ps, nil
		}
		return nil, fmt.Errorf("loading completed but system not found in cache")
	}
	defer m.releaseLoadingLock(key, loadChan)

	keyPath := m.determineTransferKeyPath(circuitType, nInputs, nOutputs)
	if keyPath == "" {
		return nil, fmt.Errorf("no key file mapping for %s with %d inputs and %d outputs", circuitType, nInputs, nOutputs)
	}

	logging.Logger().Info().
		Str("key_path", keyPath).
		Str("cache_key", key).
		Msg("Loading TransferProofSystem")

	if err := EnsureProvingKey(keyPath, m.downloadConfig.AutoDownload, m.downloadConfig); err != nil {
		return nil, fmt.Errorf("failed to download key %s: %w", keyPath, err)
	}

	system, err := ReadSystemFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %s: %w", keyPath, err)
	}

	ps, ok := system.(*TransferProofSystem)
	if !ok {
		return nil, fmt.Errorf("expected TransferProofSystem but got different type")
	}

	m.mu.Lock()
	m.transferSystems[key] = ps
	m.mu.Unlock()

	logging.Logger().Info().
		Str("cache_key", key).
		Uint32("n_inputs", ps.NInputs).
		Uint32("n_outputs", ps.NOutputs).
		Bool("requires_p256", ps.RequiresP256).
		Str("circuit_type", string(ps.CircuitType)).
		Msg("TransferProofSystem loaded and cached successfully")

	return ps, nil
}

func (m *LazyKeyManager) acquireLoadingLock(key string) chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, loading := m.loadingInProgress[key]; loading {
		return nil
	}

	ch := make(chan struct{})
	m.loadingInProgress[key] = ch
	return ch
}

func (m *LazyKeyManager) waitForLoading(key string) {
	m.mu.RLock()
	ch := m.loadingInProgress[key]
	m.mu.RUnlock()

	if ch != nil {
		<-ch
	}
}

func (m *LazyKeyManager) releaseLoadingLock(key string, ch chan struct{}) {
	m.mu.Lock()
	delete(m.loadingInProgress, key)
	m.mu.Unlock()
	close(ch)
}

func (m *LazyKeyManager) keyPath(filename string) string {
	return filepath.Join(m.keysDir, filename)
}

func (m *LazyKeyManager) determineBatchKeyPath(circuitType CircuitType, treeHeight uint32, batchSize uint32) string {
	switch circuitType {
	case BatchAddressAppendCircuitType:
		if treeHeight == 40 && batchSize == 250 {
			return m.keyPath("batch_address-append_40_250.key")
		} else if treeHeight == 40 && batchSize == 10 {
			return m.keyPath("batch_address-append_40_10.key")
		}
	}

	return ""
}

// transferSupportedShapes mirrors protocol.SupportedShapes (the on-chain
// canonical shape set). It lives here because common must not import
// prover-test. Keep in sync with prover-test/spp/protocol/shape.go.
var transferSupportedShapes = [][2]uint32{
	{1, 1},
	{1, 2},
	{2, 2},
	{2, 3},
	{3, 3},
	{4, 3},
	{4, 4},
	{5, 3},
	{5, 4},
	{1, 8},
}

func (m *LazyKeyManager) determineTransferKeyPath(circuitType CircuitType, nInputs uint32, nOutputs uint32) string {
	var prefix string
	switch circuitType {
	case TransferConfidentialCircuitType:
		prefix = "transfer_confidential"
	case TransferRingCircuitType:
		prefix = "transfer_ring"
	case TransferP256RingCircuitType:
		prefix = "transfer_p256_ring"
	case TransferRingAuthorityCircuitType:
		prefix = "transfer_ring_authority"
	case MergeCircuitType:
		if nInputs == 8 && nOutputs == 1 {
			return m.keyPath("merge_8_1.key")
		}
		return ""
	case MergeRingCircuitType:
		if nInputs == 8 && nOutputs == 1 {
			return m.keyPath("merge_ring_8_1.key")
		}
		return ""
	default:
		return ""
	}

	for _, shape := range transferSupportedShapes {
		if shape[0] == nInputs && shape[1] == nOutputs {
			return m.keyPath(fmt.Sprintf("%s_%d_%d.key", prefix, nInputs, nOutputs))
		}
	}

	return ""
}

// ringSupportedShapes is the squads ring circuit's supported (nInputs,
// nOutputs) set. (1,1) is a withdrawal and (2,2) is a transfer.
var ringSupportedShapes = [][2]uint32{
	{1, 1},
	{2, 2},
}

func (m *LazyKeyManager) determineRingKeyPath(nInputs uint32, nOutputs uint32) string {
	for _, shape := range ringSupportedShapes {
		if shape[0] == nInputs && shape[1] == nOutputs {
			return m.keyPath(fmt.Sprintf("squads_ring_%d_%d.key", nInputs, nOutputs))
		}
	}
	return ""
}

// keyEncryptionSupportedKeys is the squads key encryption circuit's supported
// recipient-count (recovery + auditor) set.
var keyEncryptionSupportedKeys = []uint32{1, 2, 3}

func (m *LazyKeyManager) determineKeyEncryptionKeyPath(numKeys uint32) string {
	for _, n := range keyEncryptionSupportedKeys {
		if n == numKeys {
			return m.keyPath(fmt.Sprintf("squads_key_encryption_%d.key", numKeys))
		}
	}
	return ""
}

func (m *LazyKeyManager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Every tier a proof request can load. A missing tier makes its keys
	// invisible to the preload log and to any operator reading the stats.
	return map[string]interface{}{
		"batch_systems_loaded":               len(m.batchSystems),
		"transfer_systems_loaded":            len(m.transferSystems),
		"aggregate_systems_loaded":           len(m.aggregateSystems),
		"nullifier_fold_systems_loaded":      len(m.nullifierFoldSystems),
		"merge_chain_systems_loaded":         len(m.mergeChainSystems),
		"ring_systems_loaded":                len(m.ringSystems),
		"key_encryption_systems_loaded":      len(m.keyEncSystems),
		"ring_fold_systems_loaded":           len(m.ringFoldSystems),
		"key_encryption_fold_systems_loaded": len(m.keyEncFoldSystems),
		"keys_loading":                       len(m.loadingInProgress),
	}
}

func (m *LazyKeyManager) PreloadForRunMode(runMode RunMode) error {
	logging.Logger().Info().
		Str("run_mode", string(runMode)).
		Msg("Preloading keys for run mode")

	keys := GetKeys(m.keysDir, runMode, nil)
	return m.preloadKeys(keys)
}

func (m *LazyKeyManager) PreloadAll() error {
	logging.Logger().Info().Msg("Preloading all keys")

	allKeys := make(map[string]bool)
	runModes := []RunMode{Full, FullTest}
	for _, runMode := range runModes {
		keys := GetKeys(m.keysDir, runMode, nil)
		for _, key := range keys {
			allKeys[key] = true
		}
	}

	keySlice := make([]string, 0, len(allKeys))
	for key := range allKeys {
		keySlice = append(keySlice, key)
	}

	return m.preloadKeys(keySlice)
}

func (m *LazyKeyManager) PreloadCircuits(circuits []string) error {
	logging.Logger().Info().
		Strs("circuits", circuits).
		Msg("Preloading keys for circuits")

	var keyPaths []string
	seen := make(map[string]bool)

	for _, circuit := range circuits {
		if specificPath := m.tryParseSpecificConfig(circuit); specificPath != "" {
			if !seen[specificPath] {
				keyPaths = append(keyPaths, specificPath)
				seen[specificPath] = true
			}
			continue
		}

		circuitKeys := GetKeys(m.keysDir, "", []string{circuit})
		for _, key := range circuitKeys {
			if !seen[key] {
				keyPaths = append(keyPaths, key)
				seen[key] = true
			}
		}
	}

	return m.preloadKeys(keyPaths)
}

func (m *LazyKeyManager) tryParseSpecificConfig(config string) string {
	if strings.HasPrefix(config, "batch_") {
		return m.keyPath(fmt.Sprintf("%s.key", config))
	}
	return ""
}

func (m *LazyKeyManager) preloadKeys(keyPaths []string) error {
	if len(keyPaths) == 0 {
		logging.Logger().Info().Msg("No keys to preload")
		return nil
	}

	logging.Logger().Info().
		Int("count", len(keyPaths)).
		Msg("Starting to preload keys")

	for i, keyPath := range keyPaths {
		logging.Logger().Info().
			Int("current", i+1).
			Int("total", len(keyPaths)).
			Str("key_path", keyPath).
			Msg("Preloading key")

		if err := EnsureProvingKey(keyPath, m.downloadConfig.AutoDownload, m.downloadConfig); err != nil {
			return fmt.Errorf("failed to download key %s: %w", keyPath, err)
		}

		system, err := ReadSystemFromFile(keyPath)
		if err != nil {
			return fmt.Errorf("failed to load key %s: %w", keyPath, err)
		}

		if err := m.cacheSystem(system); err != nil {
			return fmt.Errorf("failed to cache key %s: %w", keyPath, err)
		}
	}

	logging.Logger().Info().
		Int("count", len(keyPaths)).
		Msg("Successfully preloaded all keys")

	return nil
}

func (m *LazyKeyManager) cacheSystem(system interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch ps := system.(type) {
	case *BatchProofSystem:
		key := fmt.Sprintf("%s_%d_%d", ps.CircuitType, ps.TreeHeight, ps.BatchSize)
		m.batchSystems[key] = ps
		logging.Logger().Debug().
			Str("cache_key", key).
			Msg("Cached BatchProofSystem")

	case *TransferProofSystem:
		key := fmt.Sprintf("%s_%d_%d", ps.CircuitType, ps.NInputs, ps.NOutputs)
		m.transferSystems[key] = ps
		logging.Logger().Debug().
			Str("cache_key", key).
			Msg("Cached TransferProofSystem")

	case *SquadsRingProofSystem:
		key := fmt.Sprintf("%s_%d_%d", ps.CircuitType, ps.NInputs, ps.NOutputs)
		m.ringSystems[key] = ps
		logging.Logger().Debug().
			Str("cache_key", key).
			Msg("Cached SquadsRingProofSystem")

	case *SquadsKeyEncryptionProofSystem:
		key := fmt.Sprintf("%s_%d", ps.CircuitType, ps.NumKeys)
		m.keyEncSystems[key] = ps
		logging.Logger().Debug().
			Str("cache_key", key).
			Msg("Cached SquadsKeyEncryptionProofSystem")

	case *SquadsRingFoldProofSystem:
		key := fmt.Sprintf("%s_%d_%d_l%d", SquadsRingFoldCircuitType, ps.NInputs, ps.NOutputs, ps.Legs)
		m.ringFoldSystems[key] = ps
		logging.Logger().Debug().
			Str("cache_key", key).
			Msg("Cached SquadsRingFoldProofSystem")

	case *SquadsKeyEncryptionFoldProofSystem:
		key := fmt.Sprintf("%s_%d_l%d", SquadsKeyEncryptionFoldCircuitType, ps.KeysPerLeg, ps.Legs)
		m.keyEncFoldSystems[key] = ps
		logging.Logger().Debug().
			Str("cache_key", key).
			Msg("Cached SquadsKeyEncryptionFoldProofSystem")

	default:
		return fmt.Errorf("unknown system type: %T", system)
	}

	return nil
}
