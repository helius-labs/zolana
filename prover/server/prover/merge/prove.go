package merge

import (
	"fmt"
	"math/big"

	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/custom_rings/circuits/registry"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

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
	if p.CircuitType == common.MergeRingCircuitType {
		registered := p.RegisteredCiphertextHash != nil && p.RegisteredCiphertextHash.Sign() != 0
		if p.MemberRegistryRoot == nil || p.MemberRegistryRoot.Sign() == 0 || registered == p.Anonymous ||
			p.MemberRecord == nil || len(p.MemberRecord.Path) != registry.Height ||
			p.MemberRecord.Next.Int == nil || p.MemberRecord.EscrowKey.Int == nil {
			return fmt.Errorf("merge ring: complete recovery registration is required")
		}
		for i, field := range p.MemberRecord.Path {
			if field.Int == nil {
				return fmt.Errorf("merge ring: member record path %d is missing", i)
			}
		}
	}
	return nil
}
