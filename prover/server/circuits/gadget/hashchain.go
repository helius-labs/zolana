package gadget

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// HashChainGadget folds Poseidon over the inputs: h = inputs[0], then
// h = Poseidon(h, inputs[i]). Wrapped as an abstractor gadget so Lean
// extraction names one def per chain length; abstractor.Call is a passthrough
// on a real builder, so the R1CS is unchanged.
type HashChainGadget struct {
	Inputs []frontend.Variable
}

func (g HashChainGadget) DefineGadget(api frontend.API) interface{} {
	h := g.Inputs[0]
	for i := 1; i < len(g.Inputs); i++ {
		h = PoseidonHash(api, []frontend.Variable{h, g.Inputs[i]})
	}
	return h
}

func HashChain(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	if len(inputs) == 0 {
		return frontend.Variable(0)
	}

	return abstractor.Call(api, HashChainGadget{Inputs: inputs})
}

// RightHashChain folds Poseidon from right to left:
//
//	h = inputs[len(inputs)-1]
//	for i := len(inputs)-2; i >= 0; i--:
//	    h = Poseidon(inputs[i], h)
//
// The signer transcript uses this direction so an on-chain verifier can start
// from a precomputed all-zero suffix and hash only the populated prefix.
func RightHashChain(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	if len(inputs) == 0 {
		return frontend.Variable(0)
	}
	h := inputs[len(inputs)-1]
	for i := len(inputs) - 2; i >= 0; i-- {
		h = PoseidonHash(api, []frontend.Variable{inputs[i], h})
	}
	return h
}

// HashChain4Gadget folds Poseidon over the inputs three elements at a time:
// h = inputs[0], then h = Poseidon(h, g0, g1, g2) for each group of up to three
// consecutive elements of inputs[1:], zero-padding a short trailing group so
// every call is the 4-input permutation. No domain separation: every chain
// hashed this way has a length fixed by the compiled circuit.
type HashChain4Gadget struct {
	Inputs []frontend.Variable
}

func (g HashChain4Gadget) DefineGadget(api frontend.API) interface{} {
	h := g.Inputs[0]
	for start := 1; start < len(g.Inputs); start += 3 {
		group := []frontend.Variable{h, 0, 0, 0}
		for j := 0; j < 3 && start+j < len(g.Inputs); j++ {
			group[1+j] = g.Inputs[start+j]
		}
		h = PoseidonHash(api, group)
	}
	return h
}

func HashChain4(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	if len(inputs) == 0 {
		return frontend.Variable(0)
	}
	if len(inputs) == 1 {
		return inputs[0]
	}

	return abstractor.Call(api, HashChain4Gadget{Inputs: inputs})
}

// RightHashChain4Gadget folds Poseidon over the inputs three elements at a
// time, from right to left: h = inputs[len-1], then, walking the preceding
// elements backwards in groups of up to three that keep their order,
// h = Poseidon(g0, g1, g2, h). The short group is the leftmost one and its
// elements stay left-aligned, so an all-zero suffix folds to a value that
// depends on its length alone: the cached-commitment chain uses this direction
// so SPP starts from that precomputed constant and hashes only the populated
// prefix. The call count matches HashChain4Gadget, so a circuit pays the same.
// No domain separation: every chain hashed this way has a length fixed by the
// compiled circuit.
type RightHashChain4Gadget struct {
	Inputs []frontend.Variable
}

func (g RightHashChain4Gadget) DefineGadget(api frontend.API) interface{} {
	h := g.Inputs[len(g.Inputs)-1]
	for end := len(g.Inputs) - 1; end > 0; {
		start := end - 3
		if start < 0 {
			start = 0
		}
		group := []frontend.Variable{0, 0, 0, h}
		for j := start; j < end; j++ {
			group[j-start] = g.Inputs[j]
		}
		h = PoseidonHash(api, group)
		end = start
	}
	return h
}

func RightHashChain4(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	if len(inputs) == 0 {
		return frontend.Variable(0)
	}
	if len(inputs) == 1 {
		return inputs[0]
	}

	return abstractor.Call(api, RightHashChain4Gadget{Inputs: inputs})
}
