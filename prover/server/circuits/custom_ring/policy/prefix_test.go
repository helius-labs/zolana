package policy

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"zolana/prover/prover-test/spp/protocol"
	"zolana/prover/prover-test/spp/spptest"
)

type hashPrefix4Circuit struct {
	Contributions []frontend.Variable
	OneHot        []frontend.Variable
	Expected      frontend.Variable `gnark:",public"`
}

func (c *hashPrefix4Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(hashPrefix4(api, c.Contributions, c.OneHot), c.Expected)
	return nil
}

func hashPrefix4Assignment(width, length int, contributions []*big.Int, expected *big.Int) *hashPrefix4Circuit {
	assignment := &hashPrefix4Circuit{
		Contributions: make([]frontend.Variable, width),
		OneHot:        make([]frontend.Variable, width),
		Expected:      expected,
	}
	for i := range width {
		assignment.Contributions[i] = contributions[i]
		assignment.OneHot[i] = 0
	}
	assignment.OneHot[length-1] = 1
	return assignment
}

// TestHashPrefix4MatchesHashChain4 pins every selectable input and output
// count to the SPP fold the policy proof must reproduce, and shows the binary
// chain no longer satisfies it once a second element is selected.
func TestHashPrefix4MatchesHashChain4(t *testing.T) {
	for _, width := range []int{NInputs, NOutputs} {
		contributions := make([]*big.Int, width)
		for i := range contributions {
			contributions[i] = big.NewInt(int64(1000 + i))
		}
		contributions[2] = big.NewInt(0)
		for length := 1; length <= width; length++ {
			t.Run(fmt.Sprintf("width_%d_length_%d", width, length), func(t *testing.T) {
				circuit := &hashPrefix4Circuit{
					Contributions: make([]frontend.Variable, width),
					OneHot:        make([]frontend.Variable, width),
				}
				expected := spptest.MustHashChain4(t, contributions[:length])
				if err := test.IsSolved(
					circuit,
					hashPrefix4Assignment(width, length, contributions, expected),
					ecc.BN254.ScalarField(),
				); err != nil {
					t.Fatalf("hashPrefix4 differs from hash_chain_4 at length %d: %v", length, err)
				}

				if length == 1 {
					return
				}
				binary := spptest.MustHashChain(t, contributions[:length])
				if binary.Cmp(expected) == 0 {
					t.Fatalf("binary chain equals hash_chain_4 at length %d", length)
				}
				if err := test.IsSolved(
					circuit,
					hashPrefix4Assignment(width, length, contributions, binary),
					ecc.BN254.ScalarField(),
				); err == nil {
					t.Fatalf("binary chain satisfied hashPrefix4 at length %d", length)
				}
			})
		}
	}
}

// TestHashPrefix4RejectsLongerPrefix shows the one-hot selects exactly the
// requested length: a hash over one more contribution is not accepted.
func TestHashPrefix4RejectsLongerPrefix(t *testing.T) {
	contributions := make([]*big.Int, NInputs)
	for i := range contributions {
		contributions[i] = big.NewInt(int64(7 + i))
	}
	circuit := &hashPrefix4Circuit{
		Contributions: make([]frontend.Variable, NInputs),
		OneHot:        make([]frontend.Variable, NInputs),
	}
	for length := 1; length < NInputs; length++ {
		longer, err := protocol.HashChain4(contributions[:length+1])
		if err != nil {
			t.Fatal(err)
		}
		if err := test.IsSolved(
			circuit,
			hashPrefix4Assignment(NInputs, length, contributions, longer),
			ecc.BN254.ScalarField(),
		); err == nil {
			t.Fatalf("length %d accepted the hash of %d contributions", length, length+1)
		}
	}
}
