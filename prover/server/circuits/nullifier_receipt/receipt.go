// Package receipt implements the nullifier receipt circuit: a batch
// non-inclusion proof for published nullifiers against a nullifier tree root.
//
// Non-inclusion is a statement about public data, so it does not have to live
// inside a spend proof. The program verifies one receipt proof, stores the
// nullifier list with the root it was proven against, and lets receipt-backed
// merges spend slices of that list without proving non-inclusion themselves.
// Anyone holding the nullifier list can produce the proof.
package receipt

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction/shared"
)

// Domain separates the receipt statement from every other public-input hash.
const Domain = 0x4e525031 // "NRP1"

// MaxNullifiers bounds one receipt; the program's receipt account holds the
// same number of slots.
const MaxNullifiers = 512

// NonInclusion is one indexed-tree low-leaf witness: the leaf (Low, Next) sits
// at Index under the root and brackets the nullifier.
type NonInclusion struct {
	Low   frontend.Variable
	Next  frontend.Variable
	Index frontend.Variable
	Path  []frontend.Variable
}

// Circuit proves that every active nullifier is absent from the nullifier
// tree at Root. Slots are active while Nullifiers[i] != 0 and must form a
// prefix; Count is the number of active slots. Every nullifier-tree hash goes
// through the GKR compressor; the public input is
// HashChain4(Domain, TreeID, Root, Count, HashChain4(Nullifiers)).
type Circuit struct {
	TreeID     frontend.Variable
	Root       frontend.Variable
	Count      frontend.Variable
	Nullifiers []frontend.Variable
	Witnesses  []NonInclusion

	PublicInputHash frontend.Variable `gnark:",public"`
}

func New(n int) *Circuit {
	c := &Circuit{Nullifiers: make([]frontend.Variable, n), Witnesses: make([]NonInclusion, n)}
	for i := range c.Witnesses {
		c.Witnesses[i].Path = make([]frontend.Variable, transaction.NullifierTreeHeight)
	}
	return c
}

func (c *Circuit) Define(api frontend.API) error {
	if len(c.Nullifiers) == 0 || len(c.Nullifiers) > MaxNullifiers || len(c.Witnesses) != len(c.Nullifiers) {
		return fmt.Errorf("receipt: invalid shape")
	}
	compressor, err := gadget.NewGKRCompressor(api)
	if err != nil {
		return err
	}
	api.ToBinary(c.TreeID, 16)
	api.AssertIsDifferent(c.Count, 0)
	count, previous := frontend.Variable(0), frontend.Variable(1)
	for i, witness := range c.Witnesses {
		if len(witness.Path) != transaction.NullifierTreeHeight {
			return fmt.Errorf("receipt: invalid path %d", i)
		}
		active := api.Sub(1, api.IsZero(c.Nullifiers[i]))
		api.AssertIsEqual(api.Mul(active, api.Sub(1, previous)), 0)
		previous = active
		count = api.Add(count, active)
		root := merkleRoot(api, compressor, gadget.IndexedLeafHash(api, witness.Low, witness.Next), witness.Index, witness.Path)
		api.AssertIsEqual(api.Mul(active, api.Sub(root, c.Root)), 0)
		abstractor.CallVoid(api, transaction.AssertStrictlyOrdered{
			Lo: api.Select(active, witness.Low, 0), Mid: api.Select(active, c.Nullifiers[i], 1),
			Hi: api.Select(active, witness.Next, 2),
		})
	}
	api.AssertIsEqual(c.Count, count)
	api.AssertIsEqual(c.PublicInputHash, gadget.HashChain4(api, c.Fields(api)))
	return nil
}

// Fields is the public-input-hash preimage; the program folds the same list.
func (c *Circuit) Fields(api frontend.API) []frontend.Variable {
	return []frontend.Variable{Domain, c.TreeID, c.Root, c.Count, gadget.HashChain4(api, c.Nullifiers)}
}

func merkleRoot(api frontend.API, compressor *gadget.GKRCompressor, leaf, index frontend.Variable, path []frontend.Variable) frontend.Variable {
	bits := api.ToBinary(index, len(path))
	current := leaf
	for i, sibling := range path {
		left := api.Select(bits[i], sibling, current)
		right := api.Select(bits[i], current, sibling)
		current = compressor.Compress(left, right)
	}
	return current
}

// Compile builds the R1CS for n slots with the threshold every committed
// verifying key is produced with.
func Compile(n int) (constraint.ConstraintSystem, error) {
	return frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, New(n), frontend.WithCompressThreshold(300))
}
