package common

import (
	"math/big"
	"testing"
)

func TestCachedInputStillRequiresNullifierRoot(t *testing.T) {
	slots := []TreeSlotParams{{ID: big.NewInt(0), UtxoRoot: big.NewInt(0), NullifierRoot: big.NewInt(7)}}
	inputs := []*big.Int{big.NewInt(0)}
	if err := ValidateTreeSlotsWithCache(slots, inputs, 1, big.NewInt(1)); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTreeSlots(slots, inputs, 1); err == nil {
		t.Fatal("ordinary input accepted without a state root")
	}
	slots[0].NullifierRoot = big.NewInt(0)
	if err := ValidateTreeSlotsWithCache(slots, inputs, 1, big.NewInt(1)); err == nil {
		t.Fatal("cached input accepted without a nullifier root")
	}
}
