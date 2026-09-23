// Keeps padded slots outside transaction and policy commitments through
// prefix hashes and slot flags derived from a checked count.

package policy

import (
	"github.com/consensys/gnark/frontend"
	"zolana/prover/circuits/gadget"
)

// hashPrefix4 binds a nonempty prefix of transaction contributions with the
// SPP hash_chain_4 fold: oneHot[k-1] selects hash_chain_4(contributions[:k]).
// The running state advances once per group of three contributions; a length
// that ends inside a group is one extra zero-padded call from the group's
// start, so every selectable value is the 4-input fold SPP publishes.
func hashPrefix4(api frontend.API, contributions, oneHot []frontend.Variable) frontend.Variable {
	// 1. Select the head alone for a one-element prefix.
	head := contributions[0]
	selected := api.Mul(oneHot[0], head)

	// 2. Hash every prefix length inside each group from the group's head.
	for start := 1; start < len(contributions); start += 3 {
		end := min(start+3, len(contributions))
		for stop := start + 1; stop <= end; stop++ {
			group := []frontend.Variable{head, 0, 0, 0}
			copy(group[1:], contributions[start:stop])
			hash := gadget.PoseidonHash(api, group)
			selected = api.Add(selected, api.Mul(oneHot[stop-1], hash))
			if stop == end {
				head = hash
			}
		}
	}
	return selected
}

// extendHashPrefix adds only the selected prefix to a committed head with the
// binary chain. oneHot[0] selects the unchanged head. The policy hash keeps
// this fold because the ring program and SDKs recompute it with
// create_hash_chain_from_slice; only the SPP private tx hash uses hashPrefix4.
func extendHashPrefix(api frontend.API, head frontend.Variable, values, oneHot []frontend.Variable) frontend.Variable {
	// 1. Select the unchanged head for an empty extension.
	chain := head
	selected := api.Mul(oneHot[0], chain)

	// 2. Hash each extension and select the committed prefix.
	for k, value := range values {
		chain = gadget.PoseidonHash(api, []frontend.Variable{chain, value})
		selected = api.Add(selected, api.Mul(oneHot[k+1], chain))
	}
	return selected
}

// assertOneHot forces one count choice before prefix hashing and slot
// selection.
func assertOneHot(api frontend.API, oneHot []frontend.Variable) {
	// 1. Restrict each count selector to a bit.
	sum := frontend.Variable(0)
	for _, bit := range oneHot {
		api.AssertIsBoolean(bit)
		sum = api.Add(sum, bit)
	}

	// 2. Require exactly one selected count.
	api.AssertIsEqual(sum, 1)
}

// suffixSums derives prefix flags for hashing and evaluation from a checked
// one-hot count.
// Position k is set when the selected index is at least k.
func suffixSums(api frontend.API, oneHot []frontend.Variable) []frontend.Variable {
	out := make([]frontend.Variable, len(oneHot))
	sum := frontend.Variable(0)
	for k := len(oneHot) - 1; k >= 0; k-- {
		sum = api.Add(sum, oneHot[k])
		out[k] = sum
	}
	return out
}
