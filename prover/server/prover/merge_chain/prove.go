package merge_chain

import (
	"fmt"
	"math/big"

	chaincircuit "zolana/prover/circuits/spp_merge_chain"
	"zolana/prover/prover/common"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	stdgroth16 "github.com/consensys/gnark/std/recursion/groth16"
	"github.com/iden3/go-iden3-crypto/poseidon"
)

// Slots is the merge input width one leg fills.
const Slots = chaincircuit.Slots

// Leg is one merge proof together with the per-slot values its public input
// folds. The chain reads a leg through those values, so the caller sends them
// rather than the folds.
type Leg struct {
	Proof groth16.Proof

	Nullifiers         [Slots]*big.Int
	UtxoTreeRoots      [Slots]*big.Int
	NullifierTreeRoots [Slots]*big.Int
	InputUtxoHashes    [Slots]*big.Int

	OutputUtxoHash   *big.Int
	ExternalDataHash *big.Int
	AllowDummyInputs *big.Int
	SigningPkHash    *big.Int
}

// ProveMergeChain collapses the legs into one recursive proof.
//
// The legs are unchanged. Chaining does not re-prove them, but only the top
// leg's output ever reaches the state tree, so an intermediate leg is not
// separately submittable.
func ProveMergeChain(ps *common.MergeChainProofSystem, p Params, legs []Leg) (*common.Proof, error) {
	if ps == nil {
		return nil, fmt.Errorf("merge chain proving system is not loaded")
	}
	shape, err := p.Shape()
	if err != nil {
		return nil, err
	}
	if len(legs) != shape.Legs() {
		return nil, fmt.Errorf("%d legs against a chain of %d", len(legs), shape.Legs())
	}

	assignment, err := chainAssignment(shape, legs)
	if err != nil {
		return nil, err
	}

	full, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("witness: %w", err)
	}
	proof, err := groth16.Prove(ps.ConstraintSystem, ps.ProvingKey, full)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}
	return &common.Proof{Proof: proof}, nil
}

// chainAssignment fills the outer witness from the legs, refolding each leg's
// public input from the per-slot values the caller sent.
func chainAssignment(shape chaincircuit.Shape, legs []Leg) (*chaincircuit.Circuit, error) {
	assignment := &chaincircuit.Circuit{
		Proofs:         make([]chaincircuit.InnerProof, len(legs)),
		Witnesses:      make([]chaincircuit.InnerWitness, len(legs)),
		Preimages:      make([][chaincircuit.PreimageLen]frontend.Variable, len(legs)),
		Nullifiers:     make([][Slots]frontend.Variable, len(legs)),
		UtxoRoots:      make([][Slots]frontend.Variable, len(legs)),
		NullifierRoots: make([][Slots]frontend.Variable, len(legs)),
		InputHashes:    make([][Slots]frontend.Variable, len(legs)),
		Shape:          shape,
	}
	for i, leg := range legs {
		if err := checkFed(shape, legs, i); err != nil {
			return nil, err
		}
		fields, err := leg.preimage()
		if err != nil {
			return nil, fmt.Errorf("leg %d: %w", i, err)
		}
		public, err := publicWitness(fields)
		if err != nil {
			return nil, fmt.Errorf("leg %d: %w", i, err)
		}
		proof, err := stdgroth16.ValueOfProof[sw_bn254.G1Affine, sw_bn254.G2Affine](leg.Proof)
		if err != nil {
			return nil, fmt.Errorf("leg %d proof: %w", i, err)
		}
		circuitWitness, err := stdgroth16.ValueOfWitness[sw_bn254.ScalarField](public)
		if err != nil {
			return nil, fmt.Errorf("leg %d witness: %w", i, err)
		}
		assignment.Proofs[i], assignment.Witnesses[i] = proof, circuitWitness
		for j, f := range fields {
			assignment.Preimages[i][j] = f
		}
		for s := 0; s < Slots; s++ {
			assignment.Nullifiers[i][s] = leg.Nullifiers[s]
			assignment.UtxoRoots[i][s] = leg.UtxoTreeRoots[s]
			assignment.NullifierRoots[i][s] = leg.NullifierTreeRoots[s]
			assignment.InputHashes[i][s] = leg.InputUtxoHashes[s]
		}
	}

	chainHash, err := ChainInputHash(shape, legs)
	if err != nil {
		return nil, err
	}
	assignment.MergeChainInputHash = chainHash
	return assignment, nil
}

// ChainInputHash folds the statement the shielded pool recomputes. The order
// binds the tree-backed slots in leg then slot order, the top output, every
// leg's private tx hash, and the shared identity.
func ChainInputHash(shape chaincircuit.Shape, legs []Leg) (*big.Int, error) {
	if len(legs) != shape.Legs() {
		return nil, fmt.Errorf("%d legs against a chain of %d", len(legs), shape.Legs())
	}
	var nullifiers, utxoRoots, nullifierRoots, privateTxHashes []*big.Int
	for i, leg := range legs {
		privateTxHash, err := leg.privateTxHash()
		if err != nil {
			return nil, fmt.Errorf("leg %d: %w", i, err)
		}
		privateTxHashes = append(privateTxHashes, privateTxHash)
		for s := 0; s < Slots; s++ {
			if _, chained := shape.Source(i, s); chained {
				continue
			}
			nullifiers = append(nullifiers, leg.Nullifiers[s])
			utxoRoots = append(utxoRoots, leg.UtxoTreeRoots[s])
			nullifierRoots = append(nullifierRoots, leg.NullifierTreeRoots[s])
		}
	}
	first, top := legs[0], legs[len(legs)-1]
	nullifierChain, err := hashChain(nullifiers)
	if err != nil {
		return nil, err
	}
	utxoRootChain, err := hashChain(utxoRoots)
	if err != nil {
		return nil, err
	}
	nullifierRootChain, err := hashChain(nullifierRoots)
	if err != nil {
		return nil, err
	}
	privateTxHashChain, err := hashChain(privateTxHashes)
	if err != nil {
		return nil, err
	}
	return hashChain([]*big.Int{
		nullifierChain,
		top.OutputUtxoHash,
		utxoRootChain,
		nullifierRootChain,
		privateTxHashChain,
		first.ExternalDataHash,
		first.AllowDummyInputs,
		first.SigningPkHash,
	})
}

// checkFed reports a chained slot the caller did not fill with the output its
// source leg produced. The circuit would reject it, deep inside a pairing and
// without naming the slot.
func checkFed(shape chaincircuit.Shape, legs []Leg, i int) error {
	for s := 0; s < Slots; s++ {
		source, chained := shape.Source(i, s)
		if !chained {
			continue
		}
		fed, produced := legs[i].InputUtxoHashes[s], legs[source].OutputUtxoHash
		if fed == nil || produced == nil || fed.Cmp(produced) != 0 {
			return fmt.Errorf("leg %d slot %d does not spend the output of leg %d", i, s, source)
		}
	}
	return nil
}

// preimage folds the eight fields the merge circuit committed to.
func (l Leg) preimage() ([chaincircuit.PreimageLen]*big.Int, error) {
	var fields [chaincircuit.PreimageLen]*big.Int
	privateTxHash, err := l.privateTxHash()
	if err != nil {
		return fields, err
	}
	folds := []struct {
		index  int
		values [Slots]*big.Int
	}{
		{chaincircuit.NullifierChainIndex, l.Nullifiers},
		{chaincircuit.UtxoRootChainIndex, l.UtxoTreeRoots},
		{chaincircuit.NullifierRootChainIndex, l.NullifierTreeRoots},
	}
	for _, fold := range folds {
		folded, err := hashChain(fold.values[:])
		if err != nil {
			return fields, err
		}
		fields[fold.index] = folded
	}
	fields[chaincircuit.OutputHashIndex] = l.OutputUtxoHash
	fields[chaincircuit.PrivateTxHashIndex] = privateTxHash
	fields[chaincircuit.ExternalDataHashIndex] = l.ExternalDataHash
	fields[chaincircuit.AllowDummyInputsIndex] = l.AllowDummyInputs
	fields[chaincircuit.SigningPkHashIndex] = l.SigningPkHash
	for i, f := range fields {
		if f == nil {
			return fields, fmt.Errorf("preimage field %d is unset", i)
		}
	}
	return fields, nil
}

// privateTxHash mirrors the merge's fold. The address side is Slots empty
// slots, because a merge spends no addresses.
func (l Leg) privateTxHash() (*big.Int, error) {
	inputs, err := hashChain(l.InputUtxoHashes[:])
	if err != nil {
		return nil, err
	}
	addresses := make([]*big.Int, Slots)
	for i := range addresses {
		addresses[i] = big.NewInt(0)
	}
	addressChain, err := hashChain(addresses)
	if err != nil {
		return nil, err
	}
	return poseidon.Hash([]*big.Int{inputs, l.OutputUtxoHash, addressChain, l.ExternalDataHash})
}

// singlePublicInput mirrors the witness shape of the merge circuit, one public
// input and nothing else.
type singlePublicInput struct {
	PublicInputHash frontend.Variable `gnark:",public"`
}

// Define satisfies frontend.Circuit. The witness is filled, never compiled.
func (*singlePublicInput) Define(frontend.API) error { return nil }

func publicWitness(fields [chaincircuit.PreimageLen]*big.Int) (witness.Witness, error) {
	hash, err := hashChain(fields[:])
	if err != nil {
		return nil, err
	}
	w, err := frontend.NewWitness(
		&singlePublicInput{PublicInputHash: hash},
		ecc.BN254.ScalarField(),
		frontend.PublicOnly(),
	)
	if err != nil {
		return nil, fmt.Errorf("public witness: %w", err)
	}
	return w, nil
}

// hashChain is the Poseidon left fold the circuit and the shielded pool both
// use. Order is part of every statement it appears in.
func hashChain(values []*big.Int) (*big.Int, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("empty hash chain")
	}
	acc := values[0]
	for _, next := range values[1:] {
		if acc == nil || next == nil {
			return nil, fmt.Errorf("hash chain has an unset element")
		}
		folded, err := poseidon.Hash([]*big.Int{acc, next})
		if err != nil {
			return nil, err
		}
		acc = folded
	}
	if acc == nil {
		return nil, fmt.Errorf("hash chain has an unset element")
	}
	return acc, nil
}
