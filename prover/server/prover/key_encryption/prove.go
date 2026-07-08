package keyencryption

import (
	"fmt"

	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

func (p *KeyEncryptionParameters) ValidateShape() error {
	if p.NumKeys < 1 {
		return fmt.Errorf("squads key encryption: NumKeys must be >= 1, got %d", p.NumKeys)
	}
	if len(p.RecipientKeys) != int(p.NumKeys) {
		return fmt.Errorf("wrong number of recipient keys: %d, expected: %d", len(p.RecipientKeys), p.NumKeys)
	}
	return nil
}

func ProveKeyEncryption(ps *common.SquadsKeyEncryptionProofSystem, params *KeyEncryptionParameters) (*common.Proof, error) {
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
