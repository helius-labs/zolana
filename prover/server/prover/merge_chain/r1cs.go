package merge_chain

import (
	"fmt"

	chaincircuit "zolana/prover/circuits/spp_merge_chain"
	"zolana/prover/prover/merge"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// InnerSystem compiles the merge circuit so the outer circuit can be built
// against its constraint system. Setup also needs the merge verifying key,
// which only exists in the merge proving system, so the caller supplies it.
func InnerSystem() (constraint.ConstraintSystem, error) {
	return merge.R1CSMerge()
}

// R1CSMergeChain compiles the outer circuit for p against the merge constraint
// system and verifying key.
//
// The verifying key is fixed at compile time, so a change to the merge key
// changes the chain key. Regenerate both together.
func R1CSMergeChain(p Params, innerCcs constraint.ConstraintSystem, innerVk groth16.VerifyingKey) (constraint.ConstraintSystem, error) {
	shape, err := p.Shape()
	if err != nil {
		return nil, err
	}
	fixed, err := stdgroth16.ValueOfVerifyingKeyFixed[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](innerVk)
	if err != nil {
		return nil, fmt.Errorf("fix merge verifying key: %w", err)
	}
	circuit, err := chaincircuit.NewCircuit(shape, fixed, innerCcs)
	if err != nil {
		return nil, fmt.Errorf("new merge chain circuit: %w", err)
	}
	// WithCompressThreshold(300) matches the merge rail, keeping one compression
	// policy across every committed verifying key in the tree.
	return frontend.Compile(
		ecc.BN254.ScalarField(),
		r1cs.NewBuilder,
		circuit,
		frontend.WithCompressThreshold(300),
	)
}
