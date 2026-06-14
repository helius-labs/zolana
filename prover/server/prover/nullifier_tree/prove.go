package nullifiertree

import (
	"fmt"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
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

func ProveBatchAddressAppend(ps *common.BatchProofSystem, params *BatchAddressAppendParameters) (*common.Proof, error) {
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
