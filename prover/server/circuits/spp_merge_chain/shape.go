package merge_chain

import (
	"fmt"

	mergeshared "zolana/prover/circuits/spp_merge/shared"
)

// Slots is the merge circuit's fixed input width. A leg is one merge proof, so
// a leg always has this many input slots whatever fills them.
const Slots = mergeshared.MergeInputs

// Shape is the compile-time merge tree. It fixes which slot of which leg a
// previous leg's output fills, so the outer verifying key alone names the tree
// a proof collapsed.
type Shape struct {
	levels []int
	// feeds[leg][slot] is the leg whose output fills that slot, or -1 when the
	// slot spends a UTXO the state tree holds.
	feeds [][Slots]int
}

// NewShape builds the tree from the leg count of each level, level 0 first.
//
// Level 0 legs spend only tree-backed UTXOs. Every later level consumes the
// previous level's outputs in order, up to Slots per leg, and fills its
// remaining slots from the tree. The last level is one leg, and its output is
// the only one the pool inserts.
//
// Chained slots take the high slots of a leg, so the tree-backed inputs of
// every leg keep a contiguous low range and the on-chain vectors stay in leg
// then slot order.
func NewShape(levels []int) (Shape, error) {
	if len(levels) < 2 {
		return Shape{}, fmt.Errorf("%d levels, a chain needs at least two", len(levels))
	}
	if last := levels[len(levels)-1]; last != 1 {
		return Shape{}, fmt.Errorf("top level has %d legs, want 1", last)
	}
	legs := 0
	base := make([]int, len(levels))
	for k, n := range levels {
		if n < 1 {
			return Shape{}, fmt.Errorf("level %d has %d legs", k, n)
		}
		base[k] = legs
		legs += n
	}

	feeds := make([][Slots]int, legs)
	for i := range feeds {
		for s := range feeds[i] {
			feeds[i][s] = -1
		}
	}
	for k := 1; k < len(levels); k++ {
		source := base[k-1]
		end := base[k-1] + levels[k-1]
		for i := base[k]; i < base[k]+levels[k]; i++ {
			chained := min(end-source, Slots)
			for s := Slots - chained; s < Slots; s++ {
				feeds[i][s] = source
				source++
			}
		}
		if source != end {
			return Shape{}, fmt.Errorf(
				"level %d has %d legs, too few to absorb %d outputs",
				k, levels[k], levels[k-1],
			)
		}
	}
	return Shape{levels: append([]int(nil), levels...), feeds: feeds}, nil
}

// Legs is the number of merge proofs the outer circuit verifies.
func (s Shape) Legs() int { return len(s.feeds) }

// TreeInputs is the number of UTXOs the chain spends out of the state tree,
// which is the number of nullifiers the transaction carries. Every leg but the
// top one fills exactly one slot, so this is 7*Legs+1.
func (s Shape) TreeInputs() int { return Slots*s.Legs() - (s.Legs() - 1) }

// Source names the leg whose output fills a slot. The second result is false
// when the slot spends a UTXO the state tree holds, which is the only kind the
// transaction publishes a nullifier for.
func (s Shape) Source(leg, slot int) (int, bool) {
	source := s.feeds[leg][slot]
	return source, source >= 0
}

// Name identifies the shape in a key file and a verifying-key module.
func (s Shape) Name() string {
	name := ""
	for i, n := range s.levels {
		if i > 0 {
			name += "_"
		}
		name += fmt.Sprint(n)
	}
	return name
}
