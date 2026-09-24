package transfereddsaonly

import (
	"fmt"
	"math/big"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
)

func entryOrZero(values []*big.Int, i int) *big.Int {
	if i < 0 || i >= len(values) {
		return big.NewInt(0)
	}
	return orZero(values[i])
}

func (c CacheSelectionParams) circuitInputs(nInputs int) txcircuit.CachedInputs {
	cached := txcircuit.NewCachedInputs(nInputs)
	cached.TreeID = orZero(c.TreeID)
	cached.ReadHashChain = orZero(c.ReadHashChain)
	for i := 0; i < nInputs; i++ {
		cached.ReadHashes[i] = entryOrZero(c.ReadHashes, i)
		cached.IsCached[i] = entryOrZero(c.IsCached, i)
		cached.ReadIndex[i] = entryOrZero(c.ReadIndex, i)
	}
	return cached
}

func (p *TransferParameters) needsStateRoot(i int) bool {
	if p.Variant == RingAuthorityVariant {
		return true
	}
	input := p.Inputs[i]
	isUtxo := input.Utxo.Domain != nil && input.Utxo.Domain.Cmp(big.NewInt(txcircuit.UtxoDomain)) == 0
	return isUtxo && entryOrZero(p.Cache.IsCached, i).Sign() == 0
}

func (c CacheSelectionParams) validate(nInputs int) error {
	if c.TreeID != nil && (c.TreeID.Sign() < 0 || c.TreeID.BitLen() > 16) {
		return fmt.Errorf("spp: cacheTreeId must fit a u16")
	}
	for _, list := range []struct {
		name   string
		values []*big.Int
	}{
		{"cacheReadHashes", c.ReadHashes},
		{"cacheIsCached", c.IsCached},
		{"cacheReadIndex", c.ReadIndex},
	} {
		if len(list.values) != 0 && len(list.values) != nInputs {
			return fmt.Errorf("spp: %s holds %d values, want 0 or %d", list.name, len(list.values), nInputs)
		}
	}
	reads := false
	for i := 0; i < nInputs; i++ {
		if entryOrZero(c.ReadHashes, i).Sign() != 0 {
			reads = true
		}
	}
	if !reads && c.TreeID != nil && c.TreeID.Sign() != 0 {
		return fmt.Errorf("spp: cacheTreeId must be 0 when cacheReadHashes reads no slot")
	}
	for i := 0; i < nInputs; i++ {
		cached := entryOrZero(c.IsCached, i)
		index := entryOrZero(c.ReadIndex, i)
		if cached.Sign() != 0 && cached.Cmp(big.NewInt(1)) != 0 {
			return fmt.Errorf("spp: cacheIsCached[%d] must be 0 or 1", i)
		}
		if index.Sign() < 0 || index.Cmp(big.NewInt(int64(nInputs))) >= 0 {
			return fmt.Errorf("spp: cacheReadIndex[%d] must name one of the %d read entries", i, nInputs)
		}
		if cached.Sign() != 0 && entryOrZero(c.ReadHashes, int(index.Int64())).Sign() == 0 {
			return fmt.Errorf("spp: cached input %d reads an empty entry", i)
		}
	}
	return nil
}
