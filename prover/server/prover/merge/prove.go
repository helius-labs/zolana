package merge

import (
	"fmt"
	"math/big"

	mergeshared "zolana/prover/circuits/spp_merge/shared"
	transaction "zolana/prover/circuits/spp_transaction/shared"
	"zolana/prover/prover/common"
	"zolana/prover/prover/timing"

	"github.com/consensys/gnark/frontend"
	"zolana/prover/prover/backend"
)

type MergeProof struct {
	System     *common.TransferProofSystem
	Parameters *MergeParameters
	Timing     *timing.Trace
}

// ValidateShape checks the parameter arity is a supported merge shape, and the
// Merkle path heights and tree slot layout are right, before witness
// assignment. Merge parameters carry no explicit shape: the input count is the
// declared one, so this is where a caller's count is accepted or rejected.
func (p *MergeParameters) ValidateShape() error {
	if !mergeshared.IsSupportedInputCount(len(p.Inputs)) {
		return fmt.Errorf(
			"merge: unsupported number of inputs: got %d, expected one of %v",
			len(p.Inputs),
			mergeshared.SupportedInputCounts,
		)
	}
	inputSlots := make([]*big.Int, len(p.Inputs))
	for i := range p.Inputs {
		if got := len(p.Inputs[i].StatePathElements); got != transaction.StateTreeHeight {
			return fmt.Errorf("merge: input %d state path length: got %d, expected %d", i, got, transaction.StateTreeHeight)
		}
		if got := len(p.Inputs[i].NullifierLowPathElements); got != transaction.NullifierTreeHeight {
			return fmt.Errorf("merge: input %d nullifier path length: got %d, expected %d", i, got, transaction.NullifierTreeHeight)
		}
		inputSlots[i] = p.Inputs[i].TreeSlot
	}
	if err := common.ValidateTreeSlots(p.TreeSlots, inputSlots, transaction.InputTrees); err != nil {
		return err
	}
	// The output UTXO hash commits to its tree id, so an absent signal would be
	// an unassigned witness rather than a defaultable zero.
	if p.OutputTreeID == nil {
		return fmt.Errorf("merge: outputTreeId is required")
	}
	return nil
}

func (request MergeProof) Prove() (*common.Proof, error) {
	ps, params := request.System, request.Parameters
	proof, err := backend.ProveAssignment(request.Timing, ps.ConstraintSystem, ps.ProvingKey, func() (frontend.Circuit, error) {
		if err := params.ValidateShape(); err != nil {
			return nil, err
		}
		// The witness is allocated from the parameter count, so a proof system for
		// another shape would only surface as gnark's opaque witness-size error.
		if got := uint32(len(params.Inputs)); got != ps.NInputs {
			return nil, fmt.Errorf(
				"merge: proof system is %d-in but the request has %d inputs",
				ps.NInputs,
				got,
			)
		}
		assignment, err := params.CreateWitness()
		if err != nil {
			return nil, fmt.Errorf("create merge witness: %w", err)
		}
		return assignment, nil
	})
	if err != nil {
		return nil, err
	}
	return &common.Proof{Proof: proof, ProvingKeySha256: ps.ProvingKeySha256}, nil
}
