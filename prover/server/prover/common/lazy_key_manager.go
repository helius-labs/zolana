package common

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"zolana/prover/logging"
)

type LazyKeyManager struct {
	mu                sync.RWMutex
	batchSystems      map[string]*BatchProofSystem
	transferSystems   map[string]*TransferProofSystem
	ringSystems       map[string]*RingProofSystem
	keysDir           string
	downloadConfig    *DownloadConfig
	loadingInProgress map[string]chan struct{}
	// loadedDigests maps a loaded key's file name to the sha256 of the bytes
	// read, for GET /proving-keys.
	loadedDigests map[string][32]byte
}

func NewLazyKeyManager(keysDir string, downloadConfig *DownloadConfig) *LazyKeyManager {
	if downloadConfig == nil {
		downloadConfig = DefaultDownloadConfig()
	}
	return &LazyKeyManager{
		batchSystems:      make(map[string]*BatchProofSystem),
		transferSystems:   make(map[string]*TransferProofSystem),
		ringSystems:       make(map[string]*RingProofSystem),
		keysDir:           keysDir,
		downloadConfig:    downloadConfig,
		loadingInProgress: make(map[string]chan struct{}),
		loadedDigests:     make(map[string][32]byte),
	}
}

func (m *LazyKeyManager) GetRingSystem(circuitType CircuitType) (*RingProofSystem, error) {
	key := string(circuitType)
	m.mu.RLock()
	if ps, exists := m.ringSystems[key]; exists {
		m.mu.RUnlock()
		return ps, nil
	}
	m.mu.RUnlock()

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

	keyPath := m.determineRingKeyPath(circuitType)
	if keyPath == "" {
		return nil, fmt.Errorf("no key file mapping for circuit %s", circuitType)
	}
	if err := EnsureProvingKey(keyPath, m.downloadConfig.AutoDownload, m.downloadConfig); err != nil {
		return nil, fmt.Errorf("failed to download key %s: %w", keyPath, err)
	}
	system, err := ReadSystemFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %s: %w", keyPath, err)
	}
	ps, ok := system.(*RingProofSystem)
	if !ok {
		return nil, fmt.Errorf("expected RingProofSystem but got %T", system)
	}
	m.mu.Lock()
	m.ringSystems[key] = ps
	m.loadedDigests[filepath.Base(keyPath)] = ps.ProvingKeySha256
	m.mu.Unlock()
	return ps, nil
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
	m.loadedDigests[filepath.Base(keyPath)] = ps.ProvingKeySha256
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
	m.loadedDigests[filepath.Base(keyPath)] = ps.ProvingKeySha256
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

// keyPathOf is keyPath for a key file name that may be empty, meaning no key.
func (m *LazyKeyManager) keyPathOf(filename string) string {
	if filename == "" {
		return ""
	}
	return m.keyPath(filename)
}

// batchAddressAppendShapes are the (tree height, batch size) pairs with a key.
var batchAddressAppendShapes = [][2]uint32{{40, 10}, {40, 250}}

// BatchKeyFile names the key file that proves a batch, or "" for none.
func BatchKeyFile(circuitType CircuitType, treeHeight uint32, batchSize uint32) string {
	if circuitType != BatchAddressAppendCircuitType {
		return ""
	}
	for _, shape := range batchAddressAppendShapes {
		if shape[0] == treeHeight && shape[1] == batchSize {
			return fmt.Sprintf("batch_address-append_%d_%d.key", treeHeight, batchSize)
		}
	}
	return ""
}

func (m *LazyKeyManager) determineBatchKeyPath(circuitType CircuitType, treeHeight uint32, batchSize uint32) string {
	return m.keyPathOf(BatchKeyFile(circuitType, treeHeight, batchSize))
}

// transferSupportedShapes mirrors protocol.SupportedShapes (the on-chain
// canonical shape set). Kept here because common must not import prover-test;
// keep in sync with prover-test/spp/protocol/shape.go.
var transferSupportedShapes = [][2]uint32{
	{1, 2},
	{1, 4},
	{1, 8},
	{2, 2},
	{2, 4},
	{1, 16},
	{2, 8},
	{3, 2},
	{3, 4},
	{2, 16},
	{3, 8},
	{4, 2},
	{4, 4},
	{4, 8},
	{5, 2},
	{5, 4},
	{4, 16},
	{5, 8},
	{6, 2},
	{6, 4},
	{5, 16},
	{6, 8},
	{4, 32},
	{8, 2},
	{8, 4},
	{8, 8},
	{8, 16},
	{4, 64},
	{12, 2},
	{12, 4},
	{12, 8},
	{16, 2},
	{16, 4},
	{16, 8},
	{4, 146},
	{4, 148},
	{24, 2},
	{24, 4},
	{32, 2},
	{16, 140},
	{16, 142},
	{40, 2},
	{48, 2},
	{49, 2},
	{57, 120},
	{57, 121},
	{58, 121},
}

// batchSettlementShapes are the batch-settlement shapes each rail has keys
// for; every rail sizes its widest shapes to its own instruction data. Mirrors
// the batch sections of circuit_key_item! in
// program-libs/interface/src/verifying_keys/circuit.rs.
var batchSettlementShapes = map[CircuitType][][2]uint32{
	TransferConfidentialCircuitType: {{4, 32}, {4, 64}, {4, 148}, {16, 142}, {58, 121}},
	TransferRingCircuitType:         {{4, 32}, {4, 64}, {4, 148}, {16, 142}, {57, 121}},
	TransferP256RingCircuitType:     {{4, 32}, {4, 64}, {4, 146}, {16, 140}, {57, 120}},
}

func isBatchSettlementShape(nInputs uint32, nOutputs uint32) bool {
	for _, shapes := range batchSettlementShapes {
		for _, shape := range shapes {
			if shape[0] == nInputs && shape[1] == nOutputs {
				return true
			}
		}
	}
	return false
}

// mergeSupportedInputCounts mirrors mergeshared.SupportedInputCounts. Kept here
// because common must not import the circuit packages; keep in sync with
// circuits/spp_merge/shared/transaction.go.
var mergeSupportedInputCounts = []uint32{8, 24, 54}

type ProofShape struct {
	Circuit CircuitType
	Inputs  uint32
	Outputs uint32
}

func (shape ProofShape) Supported() bool {
	if shape.Circuit == TransferRingAuthorityCircuitType && (shape.Inputs != shape.Outputs || shape.Inputs > 4) {
		return false
	}
	switch shape.Circuit {
	case MergeCircuitType, MergeRingCircuitType:
		for _, inputs := range mergeSupportedInputCounts {
			if shape.Inputs == inputs && shape.Outputs == 1 {
				return true
			}
		}
	case TransferConfidentialCircuitType, TransferRingCircuitType, TransferRingAuthorityCircuitType, TransferP256RingCircuitType:
		if isBatchSettlementShape(shape.Inputs, shape.Outputs) {
			for _, keyed := range batchSettlementShapes[shape.Circuit] {
				if shape.Inputs == keyed[0] && shape.Outputs == keyed[1] {
					return true
				}
			}
			return false
		}
		for _, supported := range transferSupportedShapes {
			if shape.Inputs == supported[0] && shape.Outputs == supported[1] {
				return true
			}
		}
	}
	return false
}

// mergeKeyFile names a merge key file. Merge always produces one output, so
// only the input count varies across shapes.
func mergeKeyFile(prefix string, nInputs uint32, nOutputs uint32) string {
	if nOutputs != 1 {
		return ""
	}
	for _, supported := range mergeSupportedInputCounts {
		if supported == nInputs {
			return fmt.Sprintf("%s_%d_1.key", prefix, nInputs)
		}
	}
	return ""
}

// TransferKeyFile names the key file that proves a transfer or merge shape, or
// "" for an unsupported one.
func TransferKeyFile(circuitType CircuitType, nInputs uint32, nOutputs uint32) string {
	if !(ProofShape{Circuit: circuitType, Inputs: nInputs, Outputs: nOutputs}).Supported() {
		return ""
	}
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
		return mergeKeyFile("merge", nInputs, nOutputs)
	case MergeRingCircuitType:
		return mergeKeyFile("merge_ring", nInputs, nOutputs)
	default:
		return ""
	}

	for _, shape := range transferSupportedShapes {
		if shape[0] == nInputs && shape[1] == nOutputs {
			return fmt.Sprintf("%s_%d_%d.key", prefix, nInputs, nOutputs)
		}
	}

	return ""
}

func (m *LazyKeyManager) determineTransferKeyPath(circuitType CircuitType, nInputs uint32, nOutputs uint32) string {
	return m.keyPathOf(TransferKeyFile(circuitType, nInputs, nOutputs))
}

// RingKeyFile names a custom-ring circuit's key file, or "" for none.
func RingKeyFile(circuitType CircuitType) string {
	return RingKeyFiles[circuitType]
}

func (m *LazyKeyManager) determineRingKeyPath(circuitType CircuitType) string {
	return m.keyPathOf(RingKeyFile(circuitType))
}

// keyFileCircuits maps every proving key file the prover proves with to the
// circuit it proves.
func keyFileCircuits() map[string]CircuitType {
	files := map[string]CircuitType{}
	for _, circuit := range []CircuitType{
		TransferConfidentialCircuitType,
		TransferRingCircuitType,
		TransferP256RingCircuitType,
		TransferRingAuthorityCircuitType,
	} {
		for _, shape := range transferSupportedShapes {
			if file := TransferKeyFile(circuit, shape[0], shape[1]); file != "" {
				files[file] = circuit
			}
		}
	}
	for _, circuit := range []CircuitType{MergeCircuitType, MergeRingCircuitType} {
		for _, inputs := range mergeSupportedInputCounts {
			files[TransferKeyFile(circuit, inputs, 1)] = circuit
		}
	}
	for _, shape := range batchAddressAppendShapes {
		files[BatchKeyFile(BatchAddressAppendCircuitType, shape[0], shape[1])] = BatchAddressAppendCircuitType
	}
	for circuit, file := range RingKeyFiles {
		files[file] = circuit
	}
	return files
}

// KeyFiles lists every proving key file the prover proves with, sorted.
func KeyFiles() []string {
	return slices.Sorted(maps.Keys(keyFileCircuits()))
}

// KeyFileCircuit is the circuit a proving key file proves, or "" for none.
func KeyFileCircuit(file string) CircuitType {
	return keyFileCircuits()[file]
}

func (m *LazyKeyManager) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]interface{}{
		"batch_systems_loaded":    len(m.batchSystems),
		"transfer_systems_loaded": len(m.transferSystems),
		"groth16_systems_loaded":  len(m.ringSystems),
		"keys_loading":            len(m.loadingInProgress),
	}
}

func (m *LazyKeyManager) PreloadForRunMode(runMode RunMode) error {
	logging.Logger().Info().
		Str("run_mode", string(runMode)).
		Msg("Preloading keys for run mode")

	keys := GetKeys(m.keysDir, runMode, nil)
	switch runMode {
	case Rpc, LocalRpc, Full, FullTest:
		keys = append(keys, m.transferPreloadPaths(transferPreloadCircuits)...)
	}
	return m.preloadKeys(keys)
}

func (m *LazyKeyManager) PreloadAll() error {
	logging.Logger().Info().Msg("Preloading all keys")

	allKeys := make(map[string]bool)
	for _, key := range m.transferPreloadPaths(transferPreloadCircuits) {
		allKeys[key] = true
	}
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

	keyPaths, err := m.CircuitKeyPaths(circuits)
	if err != nil {
		return err
	}
	return m.preloadKeys(keyPaths)
}

// CircuitKeyPaths resolves preload selectors without touching the key files.
func (m *LazyKeyManager) CircuitKeyPaths(circuits []string) ([]string, error) {
	var keyPaths []string
	seen := make(map[string]bool)

	for _, circuit := range circuits {
		paths, matched, err := m.selectedTransferPaths(circuit)
		if err != nil {
			return nil, err
		}
		if !matched {
			if path := m.determineRingKeyPath(CircuitType(circuit)); path != "" {
				paths, matched = []string{path}, true
			}
		}
		if matched {
			for _, path := range paths {
				if !seen[path] {
					keyPaths = append(keyPaths, path)
					seen[path] = true
				}
			}
			continue
		}
		if specificPath := m.tryParseSpecificConfig(circuit); specificPath != "" {
			if !seen[specificPath] {
				keyPaths = append(keyPaths, specificPath)
				seen[specificPath] = true
			}
			continue
		}

		circuitKeys := GetKeys(m.keysDir, "", []string{circuit})
		if len(circuitKeys) == 0 {
			return nil, fmt.Errorf("unknown preload circuit %q", circuit)
		}
		for _, key := range circuitKeys {
			if !seen[key] {
				keyPaths = append(keyPaths, key)
				seen[key] = true
			}
		}
	}
	return keyPaths, nil
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

		if err := m.cacheSystem(keyPath, system); err != nil {
			return fmt.Errorf("failed to cache key %s: %w", keyPath, err)
		}
	}

	logging.Logger().Info().
		Int("count", len(keyPaths)).
		Msg("Successfully preloaded all keys")

	return nil
}

func (m *LazyKeyManager) cacheSystem(keyPath string, system interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	switch ps := system.(type) {
	case *BatchProofSystem:
		key := fmt.Sprintf("%s_%d_%d", ps.CircuitType, ps.TreeHeight, ps.BatchSize)
		m.batchSystems[key] = ps
		m.loadedDigests[filepath.Base(keyPath)] = ps.ProvingKeySha256
		logging.Logger().Debug().
			Str("cache_key", key).
			Msg("Cached BatchProofSystem")

	case *TransferProofSystem:
		key := fmt.Sprintf("%s_%d_%d", ps.CircuitType, ps.NInputs, ps.NOutputs)
		m.transferSystems[key] = ps
		m.loadedDigests[filepath.Base(keyPath)] = ps.ProvingKeySha256
		logging.Logger().Debug().
			Str("cache_key", key).
			Msg("Cached TransferProofSystem")

	case *RingProofSystem:
		m.ringSystems[string(ps.CircuitType)] = ps
		m.loadedDigests[filepath.Base(keyPath)] = ps.ProvingKeySha256

	default:
		return fmt.Errorf("unknown system type: %T", system)
	}

	return nil
}
