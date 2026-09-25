package transfereddsaonly

import (
	"math/big"
	"testing"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"
)

func ints(values ...int64) []*big.Int {
	out := make([]*big.Int, len(values))
	for i, v := range values {
		out[i] = big.NewInt(v)
	}
	return out
}

func TestValidateCacheSelection(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cache CacheSelectionParams
		valid bool
	}{
		{"absent selection", CacheSelectionParams{}, true},
		{"empty selection, tree zero", CacheSelectionParams{TreeID: big.NewInt(0), ReadHashes: ints(0, 0)}, true},
		{"empty selection, cache tree", CacheSelectionParams{TreeID: big.NewInt(7), ReadHashes: ints(0, 0)}, false},
		{"absent reads, cache tree", CacheSelectionParams{TreeID: big.NewInt(7)}, false},
		{"second input reads the first entry", CacheSelectionParams{
			TreeID: big.NewInt(7), ReadHashes: ints(9, 0), IsCached: ints(0, 1), ReadIndex: ints(0, 0),
		}, true},
		{"unused entry with no cached input", CacheSelectionParams{
			TreeID: big.NewInt(7), ReadHashes: ints(9, 0),
		}, true},
		{"cached input reads padding", CacheSelectionParams{
			TreeID: big.NewInt(7), ReadHashes: ints(9, 0), IsCached: ints(1, 0), ReadIndex: ints(1, 0),
		}, false},
		{"cached flag is not a bit", CacheSelectionParams{
			TreeID: big.NewInt(7), ReadHashes: ints(9, 0), IsCached: ints(2, 0), ReadIndex: ints(0, 0),
		}, false},
		{"read index past the list", CacheSelectionParams{
			TreeID: big.NewInt(7), ReadHashes: ints(9, 0), IsCached: ints(0, 0), ReadIndex: ints(0, 2),
		}, false},
		{"list shorter than the inputs", CacheSelectionParams{TreeID: big.NewInt(7), ReadHashes: ints(9)}, false},
		{"tree id beyond u16", CacheSelectionParams{TreeID: big.NewInt(1 << 16), ReadHashes: ints(9, 0)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cache.validate(2)
			if tc.valid && err != nil {
				t.Fatalf("rejected a valid selection: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("accepted an invalid selection")
			}
		})
	}
}

func TestTreeSlotRootsFollowTheCache(t *testing.T) {
	utxo := UtxoParams{Domain: big.NewInt(txcircuit.UtxoDomain)}
	padding := UtxoParams{Domain: big.NewInt(txcircuit.DummyDomain)}
	withoutRoot := []common.TreeSlotParams{{ID: big.NewInt(4), UtxoRoot: big.NewInt(0), NullifierRoot: big.NewInt(9)}}
	withRoot := []common.TreeSlotParams{{ID: big.NewInt(4), UtxoRoot: big.NewInt(8), NullifierRoot: big.NewInt(9)}}
	cases := []struct {
		name    string
		variant Variant
		inputs  []UtxoParams
		cached  []*big.Int
		slots   []common.TreeSlotParams
		valid   bool
	}{
		{"a fully cached group needs no state root", ConfidentialVariant, []UtxoParams{utxo, padding}, ints(1, 0), withoutRoot, true},
		{"an uncached input needs a state root", ConfidentialVariant, []UtxoParams{utxo, utxo}, ints(1, 0), withoutRoot, false},
		{"a mixed group proves against its state root", ConfidentialVariant, []UtxoParams{utxo, utxo}, ints(1, 0), withRoot, true},
		{"an uncached spend needs a state root", ConfidentialVariant, []UtxoParams{utxo, padding}, nil, withoutRoot, false},
		{"ring authority always needs a state root", RingAuthorityVariant, []UtxoParams{padding, padding}, nil, withoutRoot, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &TransferParameters{Variant: tc.variant, Cache: CacheSelectionParams{IsCached: tc.cached}}
			for _, input := range tc.inputs {
				p.Inputs = append(p.Inputs, InputParams{Utxo: input, TreeSlot: big.NewInt(0)})
			}
			err := common.ValidateTreeSlotRoots(tc.slots, ints(0, 0), 1, p.needsStateRoot)
			if tc.valid && err != nil {
				t.Fatalf("rejected valid tree slots: %v", err)
			}
			if !tc.valid && err == nil {
				t.Fatal("accepted tree slots without a required state root")
			}
		})
	}
}
