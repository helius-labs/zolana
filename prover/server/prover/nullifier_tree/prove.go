package nullifiertree

import (
	"fmt"

	"zolana/prover/prover/backend"
	"zolana/prover/prover/common"
	"zolana/prover/prover/timing"

	"github.com/consensys/gnark/frontend"
)

func (p *BatchAddressAppendParameters) ValidateShape() error {
	expectedArrayLen := int(p.BatchSize)
	expectedProofLen := int(p.TreeHeight)

	if len(p.LowElementValues) != expectedArrayLen {
		return fmt.Errorf("wrong number of low element values: %d, expected: %d",
			len(p.LowElementValues), expectedArrayLen)
	}
	if len(p.LowElementIndices) != expectedArrayLen {
		return fmt.Errorf("wrong number of low element indices: %d, expected: %d",
			len(p.LowElementIndices), expectedArrayLen)
	}
	if len(p.LowElementNextValues) != expectedArrayLen {
		return fmt.Errorf("wrong number of low element next values: %d, expected: %d",
			len(p.LowElementNextValues), expectedArrayLen)
	}
	if len(p.NewElementValues) != expectedArrayLen {
		return fmt.Errorf("wrong number of new element values: %d, expected: %d",
			len(p.NewElementValues), expectedArrayLen)
	}

	if len(p.LowElementProofs) != expectedArrayLen {
		return fmt.Errorf("wrong number of low element proofs: %d, expected: %d",
			len(p.LowElementProofs), expectedArrayLen)
	}
	if len(p.NewElementProofs) != expectedArrayLen {
		return fmt.Errorf("wrong number of new element proofs: %d, expected: %d",
			len(p.NewElementProofs), expectedArrayLen)
	}

	for i, proof := range p.LowElementProofs {
		if len(proof) != expectedProofLen {
			return fmt.Errorf("wrong proof length for LowElementProofs[%d]: got %d, expected %d",
				i, len(proof), expectedProofLen)
		}
	}
	for i, proof := range p.NewElementProofs {
		if len(proof) != expectedProofLen {
			return fmt.Errorf("wrong proof length for NewElementProofs[%d]: got %d, expected %d",
				i, len(proof), expectedProofLen)
		}
	}

	return nil
}

type BatchAddressAppendProof struct {
	System     *common.BatchProofSystem
	Parameters *BatchAddressAppendParameters
	Timing     *timing.Trace
}

func (request BatchAddressAppendProof) Prove() (*common.Proof, error) {
	ps, params := request.System, request.Parameters
	proof, err := backend.ProveAssignment(request.Timing, ps.ConstraintSystem, ps.ProvingKey, func() (frontend.Circuit, error) {
		if err := params.ValidateShape(); err != nil {
			return nil, err
		}
		assignment, err := params.CreateWitness()
		if err != nil {
			return nil, fmt.Errorf("create batch address append witness: %w", err)
		}
		return assignment, nil
	})
	if err != nil {
		return nil, err
	}
	return &common.Proof{Proof: proof, ProvingKeySha256: ps.ProvingKeySha256}, nil
}
