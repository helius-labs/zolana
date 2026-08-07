package common

import (
	"fmt"

	"zolana/prover/logging"
)

// nullifierFoldSupportedShapes is the (tree height, inner batch size, run) a
// fold key exists for. Every entry has a nullifier_fold_* verifying key in the
// program. An ungated shape lets a request name any file on disk and grow the
// system cache without bound.
var nullifierFoldSupportedShapes = [][3]uint32{
	{40, 10, 2},
}

// GetNullifierFoldSystem loads the outer proving system for one tree height,
// inner batch size, and run length.
func (m *LazyKeyManager) GetNullifierFoldSystem(treeHeight, batchSize, run uint32) (*NullifierFoldProofSystem, error) {
	// Gated before the loading lock and the filesystem, so an unsupported shape
	// costs a comparison and nothing else.
	keyPath := m.determineNullifierFoldKeyPath(treeHeight, batchSize, run)
	if keyPath == "" {
		return nil, fmt.Errorf(
			"no key file mapping for a fold of height %d batch %d run %d",
			treeHeight, batchSize, run,
		)
	}

	key := fmt.Sprintf("%s_%d_%d_r%d", NullifierFoldCircuitType, treeHeight, batchSize, run)

	m.mu.RLock()
	if ps, exists := m.nullifierFoldSystems[key]; exists {
		m.mu.RUnlock()
		return ps, nil
	}
	m.mu.RUnlock()

	return m.loadNullifierFoldSystem(key, keyPath, treeHeight, batchSize, run)
}

func (m *LazyKeyManager) determineNullifierFoldKeyPath(treeHeight, batchSize, run uint32) string {
	for _, shape := range nullifierFoldSupportedShapes {
		if shape[0] == treeHeight && shape[1] == batchSize && shape[2] == run {
			return m.keyPath(fmt.Sprintf("nullifier-fold_%d_%d_r%d.key", treeHeight, batchSize, run))
		}
	}
	return ""
}

func (m *LazyKeyManager) loadNullifierFoldSystem(key, keyPath string, treeHeight, batchSize, run uint32) (*NullifierFoldProofSystem, error) {
	loadChan := m.acquireLoadingLock(key)
	if loadChan == nil {
		m.waitForLoading(key)
		m.mu.RLock()
		ps, exists := m.nullifierFoldSystems[key]
		m.mu.RUnlock()
		if exists {
			return ps, nil
		}
		return nil, fmt.Errorf("loading completed but system not found in cache")
	}
	defer m.releaseLoadingLock(key, loadChan)

	logging.Logger().Info().
		Str("key_path", keyPath).
		Str("cache_key", key).
		Msg("Loading NullifierFoldProofSystem")

	if err := EnsureProvingKey(keyPath, m.downloadConfig.AutoDownload, m.downloadConfig); err != nil {
		return nil, fmt.Errorf("failed to download key %s: %w", keyPath, err)
	}

	system, err := ReadSystemFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %s: %w", keyPath, err)
	}
	ps, ok := system.(*NullifierFoldProofSystem)
	if !ok {
		return nil, fmt.Errorf("expected NullifierFoldProofSystem but got different type")
	}
	if ps.TreeHeight != treeHeight || ps.BatchSize != batchSize || ps.Run != run {
		return nil, fmt.Errorf(
			"key %s folds height %d batch %d run %d, request asked for height %d batch %d run %d",
			keyPath, ps.TreeHeight, ps.BatchSize, ps.Run, treeHeight, batchSize, run,
		)
	}

	m.mu.Lock()
	m.nullifierFoldSystems[key] = ps
	m.mu.Unlock()

	logging.Logger().Info().
		Str("cache_key", key).
		Uint32("run", ps.Run).
		Msg("NullifierFoldProofSystem loaded and cached successfully")
	return ps, nil
}
