package common

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"zolana/prover/logging"
)

// mergeChainSupportedLevels is the level shape a merge-chain key exists for,
// bottom level first. Every entry has a merge_chain_* verifying key in the
// program. An ungated shape lets a request name any file on disk and grow the
// system cache without bound.
var mergeChainSupportedLevels = [][]uint32{
	{1, 1},
	{2, 1},
}

// GetMergeChainSystem loads the outer proving system for one level shape.
func (m *LazyKeyManager) GetMergeChainSystem(levels []uint32) (*MergeChainProofSystem, error) {
	name := MergeChainLevelName(levels)

	// Gated before the loading lock and the filesystem, so an unsupported shape
	// costs a comparison and nothing else.
	keyPath := m.determineMergeChainKeyPath(levels, name)
	if keyPath == "" {
		return nil, fmt.Errorf("no key file mapping for a merge chain of levels %s", name)
	}

	key := fmt.Sprintf("%s_%s", MergeChainCircuitType, name)

	m.mu.RLock()
	if ps, exists := m.mergeChainSystems[key]; exists {
		m.mu.RUnlock()
		return ps, nil
	}
	m.mu.RUnlock()

	return m.loadMergeChainSystem(key, name, keyPath)
}

// MergeChainLevelName renders a level shape the way its key file names it.
func MergeChainLevelName(levels []uint32) string {
	parts := make([]string, len(levels))
	for i, n := range levels {
		parts[i] = strconv.FormatUint(uint64(n), 10)
	}
	return strings.Join(parts, "_")
}

func (m *LazyKeyManager) determineMergeChainKeyPath(levels []uint32, name string) string {
	for _, supported := range mergeChainSupportedLevels {
		if slices.Equal(supported, levels) {
			return m.keyPath(fmt.Sprintf("merge-chain_%s.key", name))
		}
	}
	return ""
}

func (m *LazyKeyManager) loadMergeChainSystem(key, name, keyPath string) (*MergeChainProofSystem, error) {
	loadChan := m.acquireLoadingLock(key)
	if loadChan == nil {
		m.waitForLoading(key)
		m.mu.RLock()
		ps, exists := m.mergeChainSystems[key]
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
		Msg("Loading MergeChainProofSystem")

	if err := EnsureProvingKey(keyPath, m.downloadConfig.AutoDownload, m.downloadConfig); err != nil {
		return nil, fmt.Errorf("failed to download key %s: %w", keyPath, err)
	}

	system, err := ReadSystemFromFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load key %s: %w", keyPath, err)
	}
	ps, ok := system.(*MergeChainProofSystem)
	if !ok {
		return nil, fmt.Errorf("expected MergeChainProofSystem but got different type")
	}
	if got := MergeChainLevelName(ps.Levels); got != name {
		return nil, fmt.Errorf("key %s chains levels %s, request asked for %s", keyPath, got, name)
	}

	m.mu.Lock()
	m.mergeChainSystems[key] = ps
	m.mu.Unlock()

	logging.Logger().Info().
		Str("cache_key", key).
		Msg("MergeChainProofSystem loaded and cached successfully")
	return ps, nil
}
