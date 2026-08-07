package merge_chain

import (
	"fmt"

	chaincircuit "zolana/prover/circuits/spp_merge_chain"
	"zolana/prover/prover/common"
)

// MinLegs is the smallest chain that beats a plain merge. One leg is a merge,
// and the outer proof would only cost more than the merge it replaced.
const MinLegs = 2

// MaxLegs bounds the catalogue. The transaction sets the limit, not the
// circuit. Every tree-backed input publishes a nullifier and two root indices,
// so a chain of MaxLegs already spends more instruction data than a legacy
// Solana transaction carries. See docs/RECURSION.md for the reachable shapes.
const MaxLegs = 9

// Params identifies one merge-chain proving system. The level shape is the
// whole key, because the outer circuit compiles in both the merge verifying key
// and the tree.
type Params struct {
	Levels []int
}

func (p Params) Shape() (chaincircuit.Shape, error) {
	if len(p.Levels) > common.MaxMergeChainLevels {
		return chaincircuit.Shape{}, fmt.Errorf(
			"%d levels, at most %d", len(p.Levels), common.MaxMergeChainLevels,
		)
	}
	shape, err := chaincircuit.NewShape(p.Levels)
	if err != nil {
		return chaincircuit.Shape{}, err
	}
	if shape.Legs() < MinLegs || shape.Legs() > MaxLegs {
		return chaincircuit.Shape{}, fmt.Errorf(
			"chain of %d legs outside [%d, %d]", shape.Legs(), MinLegs, MaxLegs,
		)
	}
	return shape, nil
}

// KeyName leads with "merge-chain" so common.ReadSystemFromFile picks the
// merge-chain header before the merge one.
func (p Params) KeyName() string {
	return fmt.Sprintf("merge-chain_%s.key", common.MergeChainLevelName(p.Levels32()))
}

// Levels32 renders the shape the way the key manager keys a proving system.
func (p Params) Levels32() []uint32 {
	levels := make([]uint32, len(p.Levels))
	for i, n := range p.Levels {
		levels[i] = uint32(n)
	}
	return levels
}
