package directspend_test

import (
	"fmt"
	"math/big"
	"math/rand/v2"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/permutation/poseidon2"
	"github.com/consensys/gnark/test"

	"zolana/prover/circuits/gadget"
)

type intervalCircuit struct{ Lo, Hi, Value frontend.Variable }

func (c *intervalCircuit) Define(api frontend.API) error {
	gadget.AssertIsLessFullField(api, c.Lo, c.Hi)
	delta := api.Sub(c.Value, c.Lo)
	api.AssertIsDifferent(delta, 0)
	gadget.AssertIsLessFullField(api, delta, api.Sub(c.Hi, c.Lo))
	return nil
}

func TestIntervalBounds(t *testing.T) {
	p := ecc.BN254.ScalarField()
	values := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(3), new(big.Int).Rsh(new(big.Int).Set(p), 1), new(big.Int).Sub(p, big.NewInt(2)), new(big.Int).Sub(p, big.NewInt(1))}
	for _, lo := range values {
		for _, hi := range values {
			for _, value := range values {
				err := test.IsSolved(&intervalCircuit{}, &intervalCircuit{Lo: lo, Hi: hi, Value: value}, p)
				valid := lo.Cmp(value) < 0 && value.Cmp(hi) < 0
				if (err == nil) != valid {
					t.Fatalf("incorrect interval result for %s < %s < %s: %v", lo, value, hi, err)
				}
			}
		}
	}
}

func TestMerkleUnionBudget(t *testing.T) {
	for _, occupiedBits := range []uint{20, 32} {
		for _, n := range []int{36, 144, 512} {
			for _, clustered := range []bool{false, true} {
				indices := make(map[uint64]struct{}, n)
				rng := rand.New(rand.NewPCG(7, 19))
				for len(indices) < n {
					index := uint64(len(indices))
					if !clustered {
						index = rng.Uint64N(uint64(1) << occupiedBits)
					}
					indices[index] = struct{}{}
				}
				t.Logf("TREE_BUDGET notes=%d occupied_bits=%d clustered=%t state_hashes=%d independent_state_hashes=%d nf_hashes=%d independent_nf_hashes=%d", n, occupiedBits, clustered, unionHashes(indices, 32), n*32, unionHashes(indices, 40), n*40)
			}
		}
	}
}

func unionHashes(indices map[uint64]struct{}, height int) int {
	current, hashes := indices, 0
	for level := 0; level < height; level++ {
		parents := make(map[uint64]struct{}, len(current))
		for index := range current {
			parents[index>>1] = struct{}{}
		}
		hashes += len(parents)
		current = parents
	}
	return hashes
}

type hashBudgetCircuit struct {
	Inputs    []frontend.Variable
	Output    frontend.Variable `gnark:",public"`
	Poseidon2 bool              `gnark:"-"`
}

func (c *hashBudgetCircuit) Define(api frontend.API) error {
	var result frontend.Variable
	if c.Poseidon2 {
		h, err := poseidon2.NewPoseidon2(api)
		if err != nil {
			return err
		}
		result = h.Compress(c.Inputs[0], c.Inputs[1])
	} else {
		result = gadget.PoseidonHash(api, c.Inputs)
	}
	api.AssertIsEqual(result, c.Output)
	return nil
}

func TestHashBudget(t *testing.T) {
	for _, arity := range []int{2, 4, 8, 16} {
		c := &hashBudgetCircuit{Inputs: make([]frontend.Variable, arity)}
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("HASH_BUDGET hash=poseidon arity=%d constraints=%d", arity, cs.GetNbConstraints())
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &hashBudgetCircuit{Inputs: make([]frontend.Variable, 2), Poseidon2: true}, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	t.Log(fmt.Sprintf("HASH_BUDGET hash=poseidon2 arity=2 constraints=%d", cs.GetNbConstraints()))
}
