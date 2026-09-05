package spptest

import (
	"math/big"
	"testing"

	"zolana/prover/prover-test/spp/protocol"
)

// MustTreeSlotsHashChain fails the test if the tree slot chain cannot be
// computed.
func MustTreeSlotsHashChain(t testing.TB, slots []protocol.TreeSlot) *big.Int {
	t.Helper()
	value, err := protocol.TreeSlotsHashChain(slots)
	return MustHash(t, value, err)
}
