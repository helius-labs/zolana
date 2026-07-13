package gadget

import (
	"fmt"
	"math/big"
	_ "unsafe" // for go:linkname

	"github.com/consensys/gnark/frontend"
	"github.com/iden3/go-iden3-crypto/ff"
	_ "github.com/iden3/go-iden3-crypto/poseidon" // linked symbol target
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// PoseidonHash / PoseidonHashWithState are the in-circuit gnark BN254 HADES Poseidon used by
// `light_hasher::Poseidon`. Round constants and the optimized partial-round
// sparse layer come from `github.com/iden3/go-iden3-crypto/poseidon` via
// `go:linkname` so we don't vendor 24K lines of constants and the in-circuit
// hash matches `light_hasher::Poseidon` byte-for-byte.
//
// Spec: x^5 S-box, FULL_ROUNDS=8, PARTIAL_ROUNDS per width per iden3 NROUNDSP.
// State widths t in {3, 5, 8, 13} are the only ones the live circuits use.
//
// Constraint count (R1CS):
//
//	nInputs=2  -> 241 constraints
//	nInputs=4  -> 298 constraints
//	nInputs=7  -> 382 constraints
//	nInputs=12 -> 505 constraints

// constants mirrors the unexported `constants` struct in iden3's poseidon
// package. Field layout MUST match iden3's exactly so //go:linkname
// resolves to a usable pointer.
type constants struct {
	c [][]*ff.Element
	s [][]*ff.Element
	m [][][]*ff.Element
	p [][][]*ff.Element
}

//go:linkname iden3C github.com/iden3/go-iden3-crypto/poseidon.c
var iden3C *constants

const nRoundsF = 8

// nRoundsP[t-2] is the partial-round count for state width t.
// Mirrors iden3's poseidon.NROUNDSP.
var nRoundsP = []int{56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68}

// PoseidonHash computes the BN254 HADES Poseidon hash with
// initState = 0. inputs must have length in [1, len(nRoundsP)] (1..16).
// State width t = len(inputs)+1.
func PoseidonHash(api frontend.API, inputs []frontend.Variable) frontend.Variable {
	return PoseidonHashWithState(api, inputs, frontend.Variable(0))
}

// PoseidonHashWithState is the same as PoseidonHash but allows a non-zero
// capacity element.
func PoseidonHashWithState(api frontend.API, inputs []frontend.Variable, initState frontend.Variable) frontend.Variable {
	return abstractor.Call(api, Poseidon{Inputs: inputs, InitState: initState})
}

// The permutation is split into per-layer abstractor gadgets so the Lean
// extraction names each layer once instead of inlining ~250 gates at every
// call site. abstractor.Call is a passthrough to DefineGadget on a real
// builder and the op sequence inside is unchanged, so the R1CS (and hence
// every frozen proving key) is identical to the pre-gadget implementation.
// Round constants that vary per round (ARK, sparse S rows) are gadget
// arguments; the per-width M and P matrices are baked into the gadget bodies
// (a gadget def is deduplicated by name, so everything that varies between
// calls must be an argument).

// Poseidon is the full HADES permutation, returning state[0].
type Poseidon struct {
	Inputs    []frontend.Variable
	InitState frontend.Variable
}

func (g Poseidon) DefineGadget(api frontend.API) interface{} {
	t := len(g.Inputs) + 1
	if len(g.Inputs) == 0 || len(g.Inputs) > len(nRoundsP) {
		panic(fmt.Sprintf("poseidon: invalid input length %d (max %d)", len(g.Inputs), len(nRoundsP)))
	}
	if iden3C == nil {
		panic("poseidon: iden3 constants not linked (go:linkname failed)")
	}

	C := elemsToBigInt(iden3C.c[t-2])
	S := elemsToBigInt(iden3C.s[t-2])
	rp := nRoundsP[t-2]

	state := make([]frontend.Variable, t)
	state[0] = g.InitState
	for i, in := range g.Inputs {
		state[i+1] = in
	}

	// Initial ARK: state[i] += C[i]
	for i := 0; i < t; i++ {
		state[i] = api.Add(state[i], C[i])
	}

	// First half full rounds: nRoundsF/2 - 1 iterations of (x^5, ARK, mix-with-M)
	for i := 0; i < nRoundsF/2-1; i++ {
		state = abstractor.Call1(api, PoseidonFullRound{State: state, Ark: constVars(C[(i+1)*t : (i+2)*t])})
	}

	// Last full round before partial rounds: x^5, ARK, then mix with P (sparse setup)
	state = abstractor.Call1(api, PoseidonFullRoundP{State: state, Ark: constVars(C[(nRoundsF/2)*t : (nRoundsF/2+1)*t])})

	// Partial rounds (rp iterations): only state[0] gets x^5 + ARK,
	// then a sparse linear layer using S.
	for r := 0; r < rp; r++ {
		state = abstractor.Call1(api, PoseidonPartialRound{
			State: state,
			Ark:   frontend.Variable(C[(nRoundsF/2+1)*t+r]),
			S:     constVars(S[(2*t-1)*r : (2*t-1)*(r+1)]),
		})
	}

	// Second half full rounds: nRoundsF/2 - 1 iterations of (x^5, ARK, mix-with-M)
	for i := 0; i < nRoundsF/2-1; i++ {
		state = abstractor.Call1(api, PoseidonFullRound{State: state, Ark: constVars(C[(nRoundsF/2+1)*t+rp+i*t : (nRoundsF/2+1)*t+rp+(i+1)*t])})
	}

	// Final round: x^5 then mix-with-M (no ARK), per iden3/poseidon.go:136-137.
	state = abstractor.Call1(api, PoseidonFinalRound{State: state})

	return state[0]
}

// PoseidonFullRound is one full round mixed with M: x^5 on every element,
// ARK, then the dense MDS matrix.
type PoseidonFullRound struct {
	State []frontend.Variable
	Ark   []frontend.Variable
}

func (g PoseidonFullRound) DefineGadget(api frontend.API) interface{} {
	t := len(g.State)
	M := elems2DToBigInt(iden3C.m[t-2])
	state := append([]frontend.Variable{}, g.State...)
	for j := 0; j < t; j++ {
		state[j] = exp5(api, state[j])
	}
	for j := 0; j < t; j++ {
		state[j] = api.Add(state[j], g.Ark[j])
	}
	return mix(api, state, M)
}

// PoseidonFullRoundP is the last full round before the partial rounds; it
// mixes with the sparse-setup matrix P instead of M.
type PoseidonFullRoundP struct {
	State []frontend.Variable
	Ark   []frontend.Variable
}

func (g PoseidonFullRoundP) DefineGadget(api frontend.API) interface{} {
	t := len(g.State)
	P := elems2DToBigInt(iden3C.p[t-2])
	state := append([]frontend.Variable{}, g.State...)
	for j := 0; j < t; j++ {
		state[j] = exp5(api, state[j])
	}
	for j := 0; j < t; j++ {
		state[j] = api.Add(state[j], g.Ark[j])
	}
	return mix(api, state, P)
}

// PoseidonPartialRound is one partial round: x^5 + ARK on state[0] only,
// then the sparse linear layer using this round's S row (length 2t-1).
type PoseidonPartialRound struct {
	State []frontend.Variable
	Ark   frontend.Variable
	S     []frontend.Variable
}

func (g PoseidonPartialRound) DefineGadget(api frontend.API) interface{} {
	t := len(g.State)
	state := append([]frontend.Variable{}, g.State...)
	state[0] = exp5(api, state[0])
	state[0] = api.Add(state[0], g.Ark)

	// newState[0] = sum_{j=0..t-1} S[j] * state[j]
	var newState0 frontend.Variable = frontend.Variable(0)
	for j := 0; j < t; j++ {
		newState0 = api.Add(newState0, api.Mul(g.S[j], state[j]))
	}

	// for k in 1..t-1: state[k] += state[0] * S[t + k - 1]
	for k := 1; k < t; k++ {
		state[k] = api.Add(state[k], api.Mul(state[0], g.S[t+k-1]))
	}
	state[0] = newState0
	return state
}

// PoseidonFinalRound is the last round: x^5 then mix-with-M, no ARK.
type PoseidonFinalRound struct {
	State []frontend.Variable
}

func (g PoseidonFinalRound) DefineGadget(api frontend.API) interface{} {
	t := len(g.State)
	M := elems2DToBigInt(iden3C.m[t-2])
	state := append([]frontend.Variable{}, g.State...)
	for j := 0; j < t; j++ {
		state[j] = exp5(api, state[j])
	}
	return mix(api, state, M)
}

func constVars(xs []*big.Int) []frontend.Variable {
	out := make([]frontend.Variable, len(xs))
	for i, x := range xs {
		out[i] = frontend.Variable(x)
	}
	return out
}

// exp5 computes x^5 in 3 multiplications.
func exp5(api frontend.API, x frontend.Variable) frontend.Variable {
	x2 := api.Mul(x, x)
	x4 := api.Mul(x2, x2)
	return api.Mul(x4, x)
}

// mix computes newState[i] = sum_{j} m[j][i] * state[j], matching iden3's
// column-major convention (poseidon.go:48-62).
func mix(api frontend.API, state []frontend.Variable, m [][]*big.Int) []frontend.Variable {
	t := len(state)
	newState := make([]frontend.Variable, t)
	for i := 0; i < t; i++ {
		var sum frontend.Variable = frontend.Variable(0)
		for j := 0; j < t; j++ {
			sum = api.Add(sum, api.Mul(m[j][i], state[j]))
		}
		newState[i] = sum
	}
	return newState
}

func elemsToBigInt(elems []*ff.Element) []*big.Int {
	out := make([]*big.Int, len(elems))
	for i, e := range elems {
		out[i] = new(big.Int)
		e.ToBigIntRegular(out[i])
	}
	return out
}

func elems2DToBigInt(elems [][]*ff.Element) [][]*big.Int {
	out := make([][]*big.Int, len(elems))
	for i, row := range elems {
		out[i] = elemsToBigInt(row)
	}
	return out
}
