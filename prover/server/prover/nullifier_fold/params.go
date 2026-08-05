// Package nullifier_fold is the proving-system glue for the outer circuit that
// folds a run of consecutive nullifier-tree appends.
package nullifier_fold

import (
	"fmt"
)

// MinRun is the smallest run that amortizes a verification. Folding one append
// costs more on chain than submitting it.
const MinRun uint32 = 2

// MaxRun bounds the catalogue. Proving time and key size set the limit, not
// the circuit. See docs/RECURSION.md.
const MaxRun uint32 = 8

// Params identifies one fold proving system. Every field selects the key file,
// because the inner verifying key is compiled into the outer circuit.
type Params struct {
	TreeHeight uint32
	BatchSize  uint32
	Run        uint32
}

func (p Params) Validate() error {
	if p.Run < MinRun || p.Run > MaxRun {
		return fmt.Errorf("run %d outside [%d, %d]", p.Run, MinRun, MaxRun)
	}
	if p.TreeHeight == 0 {
		return fmt.Errorf("tree height 0")
	}
	if p.BatchSize == 0 {
		return fmt.Errorf("batch size 0")
	}
	return nil
}

// KeyName leads with "nullifier-fold" so common.ReadSystemFromFile picks the
// fold header rather than the address-append one.
func (p Params) KeyName() string {
	return fmt.Sprintf("nullifier-fold_%d_%d_r%d.key", p.TreeHeight, p.BatchSize, p.Run)
}
