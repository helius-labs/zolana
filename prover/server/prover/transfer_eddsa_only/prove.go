package transfereddsaonly

import (
	"fmt"
	"math/big"

	txcircuit "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func (p *TransferParameters) ValidateShape() error {
	if len(p.Inputs) != int(p.NInputs) {
		return fmt.Errorf("wrong number of inputs: %d, expected: %d", len(p.Inputs), p.NInputs)
	}
	if len(p.Outputs) != int(p.NOutputs) {
		return fmt.Errorf("wrong number of outputs: %d, expected: %d", len(p.Outputs), p.NOutputs)
	}
	inputSlots := make([]*big.Int, len(p.Inputs))
	for i := range p.Inputs {
		if got := len(p.Inputs[i].StatePathElements); got != txcircuit.StateTreeHeight {
			return fmt.Errorf("input %d: wrong state path length: got %d, expected %d", i, got, txcircuit.StateTreeHeight)
		}
		if got := len(p.Inputs[i].NullifierLowPathElements); got != txcircuit.NullifierTreeHeight {
			return fmt.Errorf("input %d: wrong nullifier path length: got %d, expected %d", i, got, txcircuit.NullifierTreeHeight)
		}
		inputSlots[i] = p.Inputs[i].TreeSlot
	}
	// The circuit only fails an out-of-range or unused slot inside
	// SelectTreeSlot, and a slot the packed InputFlags does not publish inside
	// the flag decode, both as opaque proving errors; reject them as request
	// errors.
	if err := common.ValidateTreeSlotRoots(
		p.TreeSlots, inputSlots, txcircuit.InputTrees, p.needsStateRoot,
	); err != nil {
		return err
	}
	if err := common.ValidateInputFlags(p.InputFlags, inputSlots); err != nil {
		return err
	}
	if p.OutputTreeID == nil {
		return fmt.Errorf("spp: outputTreeId is required")
	}
	if err := p.Cache.Validate(int(p.NInputs)); err != nil {
		return err
	}
	return nil
}
