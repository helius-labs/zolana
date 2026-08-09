// Package squads_key_encryption_fold is the proving-system glue for the outer
// circuit that folds several key-encryption legs into one wider recipient set.
package squads_key_encryption_fold

import "fmt"

// MinLegs is the smallest fold that amortizes a verification. Folding one leg
// costs more on chain than verifying it.
const MinLegs uint32 = 2

// MaxLegs bounds the catalogue. The limit is proving time and key size, not the
// circuit. See docs/RECURSION.md.
const MaxLegs uint32 = 8

// Params identifies one fold proving system. Both fields select the key file,
// because the inner verifying key is compiled into the outer circuit.
type Params struct {
	KeysPerLeg uint32
	Legs       uint32
}

func (p Params) Validate() error {
	if p.Legs < MinLegs || p.Legs > MaxLegs {
		return fmt.Errorf("%d legs outside [%d, %d]", p.Legs, MinLegs, MaxLegs)
	}
	if p.KeysPerLeg == 0 {
		return fmt.Errorf("0 keys per leg")
	}
	return nil
}

// Keys is the recipient count a fold proves.
func (p Params) Keys() uint32 {
	return p.KeysPerLeg * p.Legs
}

// KeyName carries "fold" so common.ReadSystemFromFile picks the fold header
// rather than the unfolded key-encryption one.
func (p Params) KeyName() string {
	return fmt.Sprintf("squads_key_encryption_fold_%d_l%d.key", p.KeysPerLeg, p.Legs)
}
