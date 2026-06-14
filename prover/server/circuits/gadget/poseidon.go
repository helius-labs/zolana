package gadget

import (
	"fmt"
	"math/big"
	_ "unsafe" // for go:linkname

	"github.com/consensys/gnark/frontend"
	"github.com/iden3/go-iden3-crypto/ff"
	_ "github.com/iden3/go-iden3-crypto/poseidon" // linked symbol target
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
	t := len(inputs) + 1
	if len(inputs) == 0 || len(inputs) > len(nRoundsP) {
		panic(fmt.Sprintf("poseidon: invalid input length %d (max %d)", len(inputs), len(nRoundsP)))
	}
	if iden3C == nil {
		panic("poseidon: iden3 constants not linked (go:linkname failed)")
	}

	C := elemsToBigInt(iden3C.c[t-2])
	S := elemsToBigInt(iden3C.s[t-2])
	M := elems2DToBigInt(iden3C.m[t-2])
	P := elems2DToBigInt(iden3C.p[t-2])
	rp := nRoundsP[t-2]

	state := make([]frontend.Variable, t)
	state[0] = initState
	for i, in := range inputs {
		state[i+1] = in
	}

	// Initial ARK: state[i] += C[i]
	for i := 0; i < t; i++ {
		state[i] = api.Add(state[i], C[i])
	}

	// First half full rounds: nRoundsF/2 - 1 iterations of (x^5, ARK, mix-with-M)
	for i := 0; i < nRoundsF/2-1; i++ {
		for j := 0; j < t; j++ {
			state[j] = exp5(api, state[j])
		}
		for j := 0; j < t; j++ {
			state[j] = api.Add(state[j], C[(i+1)*t+j])
		}
		state = mix(api, state, M)
	}

	// Last full round before partial rounds: x^5, ARK, then mix with P (sparse setup)
	for j := 0; j < t; j++ {
		state[j] = exp5(api, state[j])
	}
	for j := 0; j < t; j++ {
		state[j] = api.Add(state[j], C[(nRoundsF/2)*t+j])
	}
	state = mix(api, state, P)

	// Partial rounds (rp iterations): only state[0] gets x^5 + ARK,
	// then a sparse linear layer using S.
	for r := 0; r < rp; r++ {
		state[0] = exp5(api, state[0])
		state[0] = api.Add(state[0], C[(nRoundsF/2+1)*t+r])

		// newState[0] = sum_{j=0..t-1} S[(2t-1)*r + j] * state[j]
		var newState0 frontend.Variable = frontend.Variable(0)
		for j := 0; j < t; j++ {
			newState0 = api.Add(newState0, api.Mul(S[(2*t-1)*r+j], state[j]))
		}

		// for k in 1..t-1: state[k] += state[0] * S[(2t-1)*r + t + k - 1]
		for k := 1; k < t; k++ {
			state[k] = api.Add(state[k], api.Mul(state[0], S[(2*t-1)*r+t+k-1]))
		}
		state[0] = newState0
	}

	// Second half full rounds: nRoundsF/2 - 1 iterations of (x^5, ARK, mix-with-M)
	for i := 0; i < nRoundsF/2-1; i++ {
		for j := 0; j < t; j++ {
			state[j] = exp5(api, state[j])
		}
		for j := 0; j < t; j++ {
			state[j] = api.Add(state[j], C[(nRoundsF/2+1)*t+rp+i*t+j])
		}
		state = mix(api, state, M)
	}

	// Final round: x^5 then mix-with-M (no ARK), per iden3/poseidon.go:136-137.
	for j := 0; j < t; j++ {
		state[j] = exp5(api, state[j])
	}
	state = mix(api, state, M)

	return state[0]
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
