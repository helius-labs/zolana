package gadget

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// Poseidon2 over BN254, width 2: the nullifier tree hash. Written as
// abstractor gadgets with two-operand ops so the Lean extraction names each
// round once and every gate is `∃g, g = op a b`; the gnark std gadget merges
// round keys into three-operand adds, which the extractor cannot render.
// Round keys are gadget arguments, the matrices are in the bodies (a gadget
// def is deduplicated by name and array lengths, so everything that varies
// between calls must be an argument). The function is gnark-crypto's
// `Permutation` and `Compress` for the same parameters.

var poseidon2Params = poseidon2.NewParameters(NullifierTreeHashWidth, NullifierTreeHashFullRounds, NullifierTreeHashPartialRounds)

// Poseidon2Compress returns `perm(left, right)[1] + right`.
type Poseidon2Compress struct {
	Left  frontend.Variable
	Right frontend.Variable
}

func (g Poseidon2Compress) DefineGadget(api frontend.API) interface{} {
	state := abstractor.Call1(api, Poseidon2Permutation{State: []frontend.Variable{g.Left, g.Right}})
	return api.Add(state[1], g.Right)
}

// Poseidon2Permutation is the width-2 permutation: external linear layer,
// then full rounds, partial rounds and full rounds.
type Poseidon2Permutation struct {
	State []frontend.Variable
}

func (g Poseidon2Permutation) DefineGadget(api frontend.API) interface{} {
	if len(g.State) != NullifierTreeHashWidth {
		panic("poseidon2: width 2 only")
	}
	keys := poseidon2Params.RoundKeys
	half := NullifierTreeHashFullRounds / 2
	state := poseidon2External(api, g.State)
	for i := 0; i < half; i++ {
		state = abstractor.Call1(api, Poseidon2ExternalRound{State: state, Keys: roundKeyVars(keys[i])})
	}
	for i := half; i < half+NullifierTreeHashPartialRounds; i++ {
		state = abstractor.Call1(api, Poseidon2InternalRound{State: state, Key: roundKeyVar(keys[i][0])})
	}
	for i := half + NullifierTreeHashPartialRounds; i < NullifierTreeHashFullRounds+NullifierTreeHashPartialRounds; i++ {
		state = abstractor.Call1(api, Poseidon2ExternalRound{State: state, Keys: roundKeyVars(keys[i])})
	}
	return state
}

// Poseidon2ExternalRound is one full round: round keys, x^5 on both lanes,
// external matrix circ(2, 1).
type Poseidon2ExternalRound struct {
	State []frontend.Variable
	Keys  []frontend.Variable
}

func (g Poseidon2ExternalRound) DefineGadget(api frontend.API) interface{} {
	a := exp5(api, api.Add(g.State[0], g.Keys[0]))
	b := exp5(api, api.Add(g.State[1], g.Keys[1]))
	return poseidon2External(api, []frontend.Variable{a, b})
}

// Poseidon2InternalRound is one partial round: round key and x^5 on lane 0,
// internal matrix [[2, 1], [1, 3]].
type Poseidon2InternalRound struct {
	State []frontend.Variable
	Key   frontend.Variable
}

func (g Poseidon2InternalRound) DefineGadget(api frontend.API) interface{} {
	a := exp5(api, api.Add(g.State[0], g.Key))
	b := g.State[1]
	sum := api.Add(a, b)
	return []frontend.Variable{api.Add(a, sum), api.Add(api.Add(b, b), sum)}
}

// poseidon2External is the external matrix circ(2, 1): [2a + b, a + 2b].
func poseidon2External(api frontend.API, state []frontend.Variable) []frontend.Variable {
	sum := api.Add(state[0], state[1])
	return []frontend.Variable{api.Add(state[0], sum), api.Add(state[1], sum)}
}

func roundKeyVars(keys []fr.Element) []frontend.Variable {
	out := make([]frontend.Variable, len(keys))
	for i := range keys {
		out[i] = roundKeyVar(keys[i])
	}
	return out
}

func roundKeyVar(key fr.Element) frontend.Variable {
	return frontend.Variable(key.BigInt(new(big.Int)))
}
