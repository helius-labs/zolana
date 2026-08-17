package gadget

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
)

// PoseidonFieldHasher adapts PoseidonHash to gnark's hash.FieldHasher, which is
// what std/signature/eddsa takes for its hRAM. Buffering every written element
// and hashing them in one permutation keeps hRAM identical to the host's
// Poseidon over the same values; a Merkle-Damgard chain of two-input
// permutations would not.
//
// gnark's eddsa writes R.X, R.Y, A.X, A.Y and the message, then calls Sum once,
// so a signature costs a single width-6 permutation. eddsa never calls Reset,
// so use one hasher per verification or reset explicitly between them.
type PoseidonFieldHasher struct {
	api  frontend.API
	data []frontend.Variable
}

var _ hash.FieldHasher = (*PoseidonFieldHasher)(nil)

func NewPoseidonFieldHasher(api frontend.API) *PoseidonFieldHasher {
	return &PoseidonFieldHasher{api: api}
}

func (h *PoseidonFieldHasher) Write(data ...frontend.Variable) {
	h.data = append(h.data, data...)
}

func (h *PoseidonFieldHasher) Reset() {
	h.data = h.data[:0]
}

// Sum hashes everything written since the last Reset. Summing an empty state
// panics rather than returning the zero element: an unwritten hasher is a
// construction bug, and silently hashing to a constant would make a signature
// verify against an attacker-known hRAM.
func (h *PoseidonFieldHasher) Sum() frontend.Variable {
	if len(h.data) == 0 {
		panic("poseidon field hasher: Sum before Write")
	}
	return PoseidonHash(h.api, h.data)
}
