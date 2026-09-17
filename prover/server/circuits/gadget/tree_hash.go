package gadget

import (
	"github.com/consensys/gnark/frontend"
	"github.com/reilabs/gnark-lean-extractor/v3/abstractor"
)

// Poseidon2 over BN254, width 2, 6 full and 50 partial rounds: the
// gnark-crypto defaults, round keys derived from the parameter string.
const (
	NullifierTreeHashWidth         = 2
	NullifierTreeHashFullRounds    = 6
	NullifierTreeHashPartialRounds = 50
)

// NullifierTreeHash is the 2-to-1 hash of the nullifier tree, its nodes and
// its indexed leaves: Poseidon2 compression, `perm(left, right)[1] + right`.
// The state tree keeps Poseidon because the program appends to it on chain
// through the Poseidon syscall; the nullifier tree is only ever hashed in
// circuits and off chain.
func NullifierTreeHash(api frontend.API, left, right frontend.Variable) frontend.Variable {
	return abstractor.Call(api, Poseidon2Compress{Left: left, Right: right})
}
