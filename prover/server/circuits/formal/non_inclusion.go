package formal

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
	transaction "zolana/prover/circuits/spp_transaction"
)

// NonInclusionProof mirrors the live nullifier-tree non-inclusion block
// (spp_transaction / spp_merge constrainInput): the low leaf
// IndexedLeafHash(LeafLowerRangeValues[i], LeafHigherRangeValues[i]) is in the
// tree at Roots[i], and the value is bracketed with the full-field strict
// ordering gadget.
type NonInclusionProof struct {
	Roots  []frontend.Variable
	Values []frontend.Variable

	LeafLowerRangeValues  []frontend.Variable
	LeafHigherRangeValues []frontend.Variable

	InPathIndices  []frontend.Variable
	InPathElements [][]frontend.Variable

	NumberOfNullifiers uint32
	Height             uint32
}

func (g NonInclusionProof) DefineGadget(api frontend.API) interface{} {
	currentHash := make([]frontend.Variable, g.NumberOfNullifiers)
	for i := 0; i < int(g.NumberOfNullifiers); i++ {
		lowLeafHash := gadget.IndexedLeafHash(api, g.LeafLowerRangeValues[i], g.LeafHigherRangeValues[i])

		pathBits := api.ToBinary(g.InPathIndices[i], int(g.Height))
		root := abstractor.Call(api, gadget.MerkleRootGadget{
			Hash:   lowLeafHash,
			Index:  pathBits,
			Path:   g.InPathElements[i],
			Height: int(g.Height),
		})
		api.AssertIsEqual(root, g.Roots[i])

		abstractor.CallVoid(api, transaction.AssertStrictlyOrdered{
			Lo:  g.LeafLowerRangeValues[i],
			Mid: g.Values[i],
			Hi:  g.LeafHigherRangeValues[i],
		})
		currentHash[i] = root
	}
	return currentHash
}

// NonInclusionCircuit proves each Values[i] is absent from the nullifier tree
// with root Roots[i]: a low leaf (lo, next) exists in the tree with
// lo < Values[i] < next over full canonical field values.
type NonInclusionCircuit struct {
	PublicInputHash frontend.Variable `gnark:",public"`

	Roots  []frontend.Variable `gnark:",secret"`
	Values []frontend.Variable `gnark:",secret"`

	LeafLowerRangeValues  []frontend.Variable `gnark:",secret"`
	LeafHigherRangeValues []frontend.Variable `gnark:",secret"`

	InPathIndices  []frontend.Variable   `gnark:",secret"`
	InPathElements [][]frontend.Variable `gnark:",secret"`

	NumberOfNullifiers uint32
	Height             uint32
}

func (circuit *NonInclusionCircuit) Define(api frontend.API) error {
	publicInputsHash := gadget.HashChain(api, []frontend.Variable{
		gadget.HashChain(api, circuit.Roots),
		gadget.HashChain(api, circuit.Values),
	})
	api.AssertIsEqual(circuit.PublicInputHash, publicInputsHash)

	abstractor.Call1(api, NonInclusionProof{
		Roots:  circuit.Roots,
		Values: circuit.Values,

		LeafLowerRangeValues:  circuit.LeafLowerRangeValues,
		LeafHigherRangeValues: circuit.LeafHigherRangeValues,

		InPathIndices:  circuit.InPathIndices,
		InPathElements: circuit.InPathElements,

		NumberOfNullifiers: circuit.NumberOfNullifiers,
		Height:             circuit.Height,
	})
	return nil
}
