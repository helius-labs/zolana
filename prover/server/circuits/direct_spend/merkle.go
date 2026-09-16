package directspend

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"

	"zolana/prover/circuits/gadget"
)

func merkleRoot(api frontend.API, leaf, index frontend.Variable, path []frontend.Variable, compressor *gadget.GKRCompressor) frontend.Variable {
	bits := api.ToBinary(index, len(path))
	if compressor == nil {
		return abstractor.Call(api, gadget.MerkleRootGadget{Hash: leaf, Index: bits, Path: path, Height: len(path)})
	}
	current := leaf
	for i, sibling := range path {
		left := api.Select(bits[i], sibling, current)
		right := api.Select(bits[i], current, sibling)
		current = compressor.Compress(left, right)
	}
	return current
}
