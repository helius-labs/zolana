package transfereddsaonly

import (
	"fmt"
	"math/big"

	txcircuit "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
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
	if err := common.ValidateTreeSlotsWithCache(
		p.TreeSlots, inputSlots, txcircuit.InputTrees, p.CacheInputBitmap,
	); err != nil {
		return err
	}
	if err := common.ValidateInputFlags(p.InputFlags, inputSlots); err != nil {
		return err
	}
	if p.OutputTreeID == nil {
		return fmt.Errorf("spp: outputTreeId is required")
	}
	if err := validateCacheSelection(p.CacheInputBitmap, p.CacheTreeID, int(p.NInputs)); err != nil {
		return err
	}
	return nil
}

// validateCacheSelection rejects a selection the circuit would only fail inside
// its bitmap decode or tree-id range check, both as opaque proving errors.
// A nil or zero bitmap is an ordinary spend and constrains nothing.
func validateCacheSelection(bitmap, treeID *big.Int, nInputs int) error {
	if treeID != nil && treeID.BitLen() > 16 {
		return fmt.Errorf("spp: cacheTreeId must fit a u16")
	}
	if bitmap == nil || bitmap.Sign() == 0 {
		return nil
	}
	if bitmap.Sign() < 0 {
		return fmt.Errorf("spp: cacheInputBitmap must not be negative")
	}
	if nInputs > txcircuit.CacheCapacity {
		return fmt.Errorf(
			"spp: cached UTXO proving supports at most %d inputs, got %d",
			txcircuit.CacheCapacity, nInputs,
		)
	}
	if bitmap.BitLen() > nInputs {
		return fmt.Errorf(
			"spp: cacheInputBitmap selects beyond the %d declared inputs", nInputs,
		)
	}
	return nil
}

func ProveTransfer(ps *common.TransferProofSystem, params *TransferParameters) (*common.Proof, error) {
	if params == nil {
		panic("params cannot be nil")
	}

	if err := params.ValidateShape(); err != nil {
		return nil, err
	}

	assignment, err := params.CreateWitness()
	if err != nil {
		return nil, fmt.Errorf("error creating circuit: %v", err)
	}

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("error creating witness: %v", err)
	}

	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, witness)
	if err != nil {
		return nil, fmt.Errorf("error proving: %v", err)
	}

	return &common.Proof{Proof: proof}, nil
}
