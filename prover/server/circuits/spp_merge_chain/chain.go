// Package merge_chain holds the outer circuit that chains the fixed 8-to-1 SPP
// merge into a tree.
//
// A merge collapses eight UTXOs into one. Collapsing more takes several rounds
// today, and the rounds are sequential because round two spends round one's
// output out of the state tree under an advanced root. Chaining the rounds
// inside one proof removes that dependency. An intermediate output feeds the
// next level directly and never reaches the tree, and only the top leg's output
// is inserted. Every tree-backed input still publishes its nullifier, so the
// ceiling is the transaction size rather than the circuit width.
//
// The inner verifying key and the tree are both compile-time constants, so the
// outer verifying key alone names which merge circuit and which tree a proof
// collapsed.
package merge_chain

import (
	"fmt"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/emulated"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
)

// The default merge circuit's public input is HashChain over these eight, in
// this order (prover/server/circuits/spp_merge/default.go). Opening it is what
// lets the chain reach a leg's per-slot values. Exported so the prover folds
// the same preimage the circuit expects.
const (
	NullifierChainIndex = iota
	OutputHashIndex
	UtxoRootChainIndex
	NullifierRootChainIndex
	PrivateTxHashIndex
	ExternalDataHashIndex
	AllowDummyInputsIndex
	SigningPkHashIndex
	PreimageLen
)

type (
	InnerProof        = stdgroth16.Proof[sw_bn254.G1Affine, sw_bn254.G2Affine]
	InnerWitness      = stdgroth16.Witness[sw_bn254.ScalarField]
	InnerVerifyingKey = stdgroth16.VerifyingKey[sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl]
)

// Circuit proves that every leg is a merge under one key, that each chained
// slot spends exactly the output the level below produced, and that
// MergeChainInputHash commits to the tree-backed inputs and the top output.
type Circuit struct {
	// The only public input, so the on-chain key keeps the shape the shielded
	// pool already verifies. Its preimage mirrors a single merge's, with the
	// per-leg vectors concatenated over tree-backed slots and the private tx
	// hashes chained.
	MergeChainInputHash frontend.Variable `gnark:",public"`

	Proofs    []InnerProof
	Witnesses []InnerWitness
	// Per leg, the merge circuit's public-input preimage, bound to the proof.
	Preimages [][PreimageLen]frontend.Variable

	// Per leg and slot, the components the merge folds into the chained fields
	// of that preimage. Witnessed, then bound back to the fold, so a leg cannot
	// restate a slot it did not prove.
	Nullifiers     [][Slots]frontend.Variable
	UtxoRoots      [][Slots]frontend.Variable
	NullifierRoots [][Slots]frontend.Variable
	InputHashes    [][Slots]frontend.Variable

	// Excluded from the witness. A tree supplied at proving time would let a
	// proof choose which slots skip the state tree, and a key supplied at
	// proving time would let it choose which circuit it verified against.
	Shape        Shape             `gnark:"-"`
	VerifyingKey InnerVerifyingKey `gnark:"-"`
}

// NewCircuit returns the compile-time skeleton for shape against vk. The inner
// constraint system shapes the proof and witness placeholders.
func NewCircuit(shape Shape, vk InnerVerifyingKey, innerCcs constraint.ConstraintSystem) (*Circuit, error) {
	if shape.Legs() < 2 {
		return nil, fmt.Errorf("chain of %d does not amortize a verification", shape.Legs())
	}
	c := &Circuit{
		Proofs:         make([]InnerProof, shape.Legs()),
		Witnesses:      make([]InnerWitness, shape.Legs()),
		Preimages:      make([][PreimageLen]frontend.Variable, shape.Legs()),
		Nullifiers:     make([][Slots]frontend.Variable, shape.Legs()),
		UtxoRoots:      make([][Slots]frontend.Variable, shape.Legs()),
		NullifierRoots: make([][Slots]frontend.Variable, shape.Legs()),
		InputHashes:    make([][Slots]frontend.Variable, shape.Legs()),
		Shape:          shape,
		VerifyingKey:   vk,
	}
	for i := range c.Proofs {
		c.Proofs[i] = stdgroth16.PlaceholderProof[sw_bn254.G1Affine, sw_bn254.G2Affine](innerCcs)
		c.Witnesses[i] = stdgroth16.PlaceholderWitness[sw_bn254.ScalarField](innerCcs)
	}
	return c, nil
}

func (c *Circuit) Define(api frontend.API) error {
	legs := c.Shape.Legs()
	if legs < 2 {
		return fmt.Errorf("chain of %d", legs)
	}
	for _, part := range []int{
		len(c.Proofs), len(c.Witnesses), len(c.Preimages),
		len(c.Nullifiers), len(c.UtxoRoots), len(c.NullifierRoots), len(c.InputHashes),
	} {
		if part != legs {
			return fmt.Errorf("shape has %d legs, witness has %d", legs, part)
		}
	}

	verifier, err := stdgroth16.NewVerifier[sw_bn254.ScalarField, sw_bn254.G1Affine, sw_bn254.G2Affine, sw_bn254.GTEl](api)
	if err != nil {
		return fmt.Errorf("new verifier: %w", err)
	}
	field, err := emulated.NewField[sw_bn254.ScalarField](api)
	if err != nil {
		return fmt.Errorf("new field: %w", err)
	}

	outputs := make([]frontend.Variable, legs)
	privateTxHashes := make([]frontend.Variable, legs)
	everyNullifier := make([]frontend.Variable, 0, legs*Slots)
	nullifiers := make([]frontend.Variable, 0, c.Shape.TreeInputs())
	utxoRoots := make([]frontend.Variable, 0, c.Shape.TreeInputs())
	nullifierRoots := make([]frontend.Variable, 0, c.Shape.TreeInputs())

	for i := range c.Proofs {
		if err := verifier.AssertProof(c.VerifyingKey, c.Proofs[i], c.Witnesses[i]); err != nil {
			return fmt.Errorf("leg %d: %w", i, err)
		}
		if len(c.Witnesses[i].Public) != 1 {
			return fmt.Errorf("leg %d has %d public inputs, want 1", i, len(c.Witnesses[i].Public))
		}
		if _, err := gadget.OpenPublicInput(api, field, &c.Witnesses[i].Public[0], c.Preimages[i][:]); err != nil {
			return fmt.Errorf("leg %d: %w", i, err)
		}
		c.openSlots(api, i)

		// One merge collapses one owner's UTXOs under one dummy policy against
		// one external data hash. The pool checks a single value of each against
		// the registry, the tree, and the instruction, so a leg that disagreed
		// would settle unchecked.
		if i > 0 {
			for _, index := range []int{ExternalDataHashIndex, AllowDummyInputsIndex, SigningPkHashIndex} {
				api.AssertIsEqual(c.Preimages[i][index], c.Preimages[0][index])
			}
		}

		outputs[i] = c.Preimages[i][OutputHashIndex]
		privateTxHashes[i] = c.Preimages[i][PrivateTxHashIndex]
		for s := 0; s < Slots; s++ {
			everyNullifier = append(everyNullifier, c.Nullifiers[i][s])
			if source := c.Shape.feeds[i][s]; source >= 0 {
				// The slot spends a UTXO no tree holds, so only this equality says it
				// existed. Without it a leg could invent an input.
				api.AssertIsEqual(c.InputHashes[i][s], outputs[source])
				continue
			}
			nullifiers = append(nullifiers, c.Nullifiers[i][s])
			utxoRoots = append(utxoRoots, c.UtxoRoots[i][s])
			nullifierRoots = append(nullifierRoots, c.NullifierRoots[i][s])
		}
	}

	// A merge already rejects a repeat within its own eight. Across legs the
	// repeat is what would let one UTXO be summed twice into the top output.
	transaction.AssertDistinctNullifiers(api, everyNullifier)

	api.AssertIsEqual(c.MergeChainInputHash, gadget.HashChain(api, []frontend.Variable{
		gadget.HashChain(api, nullifiers),
		outputs[legs-1],
		gadget.HashChain(api, utxoRoots),
		gadget.HashChain(api, nullifierRoots),
		gadget.HashChain(api, privateTxHashes),
		c.Preimages[0][ExternalDataHashIndex],
		c.Preimages[0][AllowDummyInputsIndex],
		c.Preimages[0][SigningPkHashIndex],
	}))
	return nil
}

// openSlots binds a leg's witnessed per-slot vectors to the folded fields its
// proof committed to. The chained fields are opaque otherwise, and a chain that
// only forwarded them could neither drop a chained slot from the on-chain
// nullifiers nor bind one to the level below.
func (c *Circuit) openSlots(api frontend.API, leg int) {
	folds := []struct {
		index  int
		values []frontend.Variable
	}{
		{NullifierChainIndex, c.Nullifiers[leg][:]},
		{UtxoRootChainIndex, c.UtxoRoots[leg][:]},
		{NullifierRootChainIndex, c.NullifierRoots[leg][:]},
	}
	for _, fold := range folds {
		api.AssertIsEqual(c.Preimages[leg][fold.index], gadget.HashChain(api, fold.values))
	}

	// The per-slot input hashes reach the preimage only through the private tx
	// hash, so opening it is the only way to name a slot's UTXO. A merge spends
	// no addresses, so the address side of the gadget is a constant.
	addresses := make([]frontend.Variable, Slots)
	for i := range addresses {
		addresses[i] = frontend.Variable(0)
	}
	api.AssertIsEqual(c.Preimages[leg][PrivateTxHashIndex], transaction.PrivateTxHashCircuit(
		api,
		c.InputHashes[leg][:],
		[]frontend.Variable{c.Preimages[leg][OutputHashIndex]},
		addresses,
		c.Preimages[leg][ExternalDataHashIndex],
	))
}
