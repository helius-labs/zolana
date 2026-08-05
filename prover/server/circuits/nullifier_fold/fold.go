// Package nullifier_fold holds the outer circuit that folds a run of
// consecutive nullifier-tree appends into one proof.
//
// Appends are strictly sequential on chain. Each checks its old root against
// the tree's current root, so the forester submits one transaction per
// zkp-batch. Folding the run proves the whole span advanced the root correctly,
// which collapses those transactions into one.
//
// The inner verifying key is a compile-time constant, so the outer verifying
// key alone names the height and batch size a fold proved.
package nullifier_fold

import (
	"fmt"

	"zolana/prover/circuits/gadget"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// The append circuit's public input is HashChain over these four, in this
// order. Opening it lets the fold constrain root continuity.
const (
	oldRootIndex = iota
	newRootIndex
	hashchainIndex
	startIndexIndex
	// PreimageLen is exported so the prover assigns exactly this many fields.
	PreimageLen
)

type (
	InnerProof        = stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	InnerWitness      = stdgroth16.Witness[sw_bn254.ScalarField]
	InnerVerifyingKey = stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
)

// Circuit proves that every append in Proofs verifies, that they form one
// unbroken run, and that FoldInputHash commits to the span's endpoints.
type Circuit struct {
	// HashChain(OldRoot_0, NewRoot_N, HashChain(hashchain hashes), StartIndex_0).
	// The only public input, so the on-chain key keeps the shape the pool
	// already verifies.
	FoldInputHash frontend.Variable `gnark:",public"`

	Proofs    []InnerProof
	Witnesses []InnerWitness
	// Per leg, the append circuit's public-input preimage. Witnessed, then
	// bound to the proof's public input, so a leg cannot claim a span it did
	// not prove.
	Preimages [][PreimageLen]frontend.Variable

	// Every leg appends this many elements, so StartIndex continuity is a
	// fixed step. It matches the inner key, so it is a constant.
	BatchSize int `gnark:"-"`

	// Excluded from the witness. A key supplied at proving time would let a
	// fold choose which circuit it verified against.
	VerifyingKey InnerVerifyingKey `gnark:"-"`
}

// NewCircuit returns the compile-time skeleton for a run of n appends of
// batchSize elements each, against vk.
func NewCircuit(n, batchSize int, vk InnerVerifyingKey, innerCcs constraint.ConstraintSystem) (*Circuit, error) {
	if n < 2 {
		return nil, fmt.Errorf("run of %d does not amortize a verification", n)
	}
	if batchSize < 1 {
		return nil, fmt.Errorf("batch size %d", batchSize)
	}
	c := &Circuit{
		Proofs:       make([]InnerProof, n),
		Witnesses:    make([]InnerWitness, n),
		Preimages:    make([][PreimageLen]frontend.Variable, n),
		BatchSize:    batchSize,
		VerifyingKey: vk,
	}
	for i := range c.Proofs {
		c.Proofs[i] = stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs)
		c.Witnesses[i] = stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs)
	}
	return c, nil
}

func (c *Circuit) Define(api frontend.API) error {
	if len(c.Proofs) != len(c.Witnesses) || len(c.Proofs) != len(c.Preimages) {
		return fmt.Errorf("%d proofs, %d witnesses, %d preimages",
			len(c.Proofs), len(c.Witnesses), len(c.Preimages))
	}
	if len(c.Proofs) < 2 {
		return fmt.Errorf("run of %d", len(c.Proofs))
	}

	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}

	hashchains := make([]frontend.Variable, len(c.Proofs))
	for i := range c.Proofs {
		if err := verifier.AssertProof(c.VerifyingKey, c.Proofs[i], c.Witnesses[i]); err != nil {
			return fmt.Errorf("append %d: %w", i, err)
		}
		if len(c.Witnesses[i].Public) != 1 {
			return fmt.Errorf("append %d has %d public inputs, want 1", i, len(c.Witnesses[i].Public))
		}
		preimage := c.Preimages[i][:]
		if _, err := gadget.OpenPublicInput(api, field, &c.Witnesses[i].Public[0], preimage); err != nil {
			return fmt.Errorf("append %d: %w", i, err)
		}
		hashchains[i] = c.Preimages[i][hashchainIndex]

		if i == 0 {
			continue
		}
		// The run must be unbroken. Without both checks a fold could stitch
		// together appends from different tree states, or replay one leg's
		// elements at another leg's indices, and still expose endpoints the
		// program would accept.
		api.AssertIsEqual(c.Preimages[i][oldRootIndex], c.Preimages[i-1][newRootIndex])
		api.AssertIsEqual(
			c.Preimages[i][startIndexIndex],
			api.Add(c.Preimages[i-1][startIndexIndex], c.BatchSize),
		)
	}

	// The span's endpoints plus every leg's element chain, so the program can
	// nullify exactly the elements the run appended.
	api.AssertIsEqual(c.FoldInputHash, gadget.HashChain(api, []frontend.Variable{
		c.Preimages[0][oldRootIndex],
		c.Preimages[len(c.Preimages)-1][newRootIndex],
		gadget.HashChain(api, hashchains),
		c.Preimages[0][startIndexIndex],
	}))
	return nil
}
