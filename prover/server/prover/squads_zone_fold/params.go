// Package squads_zone_fold is the proving-system glue for the outer circuit
// that folds several zone spends of one account into one proof.
package squads_zone_fold

import "fmt"

// MinLegs is the smallest fold that amortizes a verification.
const MinLegs uint32 = 2

// MaxLegs bounds the catalogue. The limit is proving time and key size, not the
// circuit. See docs/RECURSION.md.
const MaxLegs uint32 = 8

// Params identifies one fold proving system. Every field selects the key file,
// because the inner verifying key is compiled into the outer circuit.
type Params struct {
	NInputs  uint32
	NOutputs uint32
	Legs     uint32
}

func (p Params) Validate() error {
	if p.Legs < MinLegs || p.Legs > MaxLegs {
		return fmt.Errorf("%d legs outside [%d, %d]", p.Legs, MinLegs, MaxLegs)
	}
	if p.NInputs == 0 {
		return fmt.Errorf("shape %dx%d has an empty input side", p.NInputs, p.NOutputs)
	}
	if p.NOutputs != 1 && p.NOutputs != 2 {
		return fmt.Errorf("%d outputs per leg", p.NOutputs)
	}
	return nil
}

// Inputs is the UTXO count a fold can spend.
func (p Params) Inputs() uint32 {
	return p.NInputs * p.Legs
}

// KeyName carries "fold" so common.ReadSystemFromFile picks the fold header
// rather than the unfolded zone one.
func (p Params) KeyName() string {
	return fmt.Sprintf("squads_zone_fold_%d_%d_l%d.key", p.NInputs, p.NOutputs, p.Legs)
}
