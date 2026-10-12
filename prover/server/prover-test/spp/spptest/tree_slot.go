package spptest

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

// MustTreeSlotsHashChain fails the test if the tree slot chain cannot be
// computed.
func MustTreeSlotsHashChain(t testing.TB, slots []protocol.TreeSlot) *big.Int {
	t.Helper()
	value, err := protocol.TreeSlotsHashChain(slots)
	return MustHash(t, value, err)
}
