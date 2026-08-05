package aggregate

import (
	"fmt"

	"zolana/prover/prover/common"
)

// MinBatch is the smallest batch that amortizes a verification. One outer
// verification costs more on chain than the one inner proof it would replace.
const MinBatch uint32 = 2

// MaxBatch bounds the catalogue. The limit is the transaction, not the circuit.
// See docs/RECURSION.md for the reachable sizes.
const MaxBatch uint32 = 5

// Params identifies one aggregate proving system by its ordered slot list of
// inner kinds. The order selects the key file, because the hash-chain
// statement binds slot order and every slot's verifying key is compiled into
// the outer circuit.
type Params struct {
	Slots []common.AggregateSlot
}

// Uniform names the batch of one rail and shape.
func Uniform(inner common.CircuitType, nInputs, nOutputs, batch uint32) Params {
	slots := make([]common.AggregateSlot, batch)
	for i := range slots {
		slots[i] = common.AggregateSlot{Inner: inner, NInputs: nInputs, NOutputs: nOutputs}
	}
	return Params{Slots: slots}
}

func (p Params) Batch() uint32 {
	return uint32(len(p.Slots))
}

func (p Params) Validate() error {
	if p.Batch() < MinBatch || p.Batch() > MaxBatch {
		return fmt.Errorf("batch %d outside [%d, %d]", p.Batch(), MinBatch, MaxBatch)
	}
	settleable := false
	for i, slot := range p.Slots {
		if err := slot.Validate(); err != nil {
			return fmt.Errorf("slot %d: %w", i, err)
		}
		if _, err := common.AggregatableRail(slot.Inner); err == nil {
			settleable = true
		}
	}
	if !settleable {
		return fmt.Errorf("no slot is a transfer rail, the batch settles nothing")
	}
	return nil
}

func (p Params) KeyName() string {
	return common.AggregateKeyName(p.Slots)
}
