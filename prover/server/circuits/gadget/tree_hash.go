package gadget

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// Poseidon2 over BN254, width 2, 6 full and 50 partial rounds: the
// gnark-crypto defaults, round keys derived from the parameter string.
const (
	TreeHashWidth         = 2
	TreeHashFullRounds    = 6
	TreeHashPartialRounds = 50
)

// TreeHash is the 2-to-1 hash of every Merkle node and indexed leaf:
// Poseidon2 compression, `perm(left, right)[1] + right`.
func TreeHash(api frontend.API, left, right frontend.Variable) frontend.Variable {
	h, err := poseidon2.NewPoseidon2FromParameters(api, TreeHashWidth, TreeHashFullRounds, TreeHashPartialRounds)
	if err != nil {
		panic(err)
	}
	return h.Compress(left, right)
}
