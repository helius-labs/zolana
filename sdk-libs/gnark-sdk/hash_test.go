package gnarksdk_test

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"zolana/gnarksdk"
	"zolana/prover/prover-test/spp/protocol"
)

type poseidonCircuit struct {
	Inputs   []frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *poseidonCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(gnarksdk.Poseidon(api, c.Inputs...), c.Expected)
	return nil
}

// testdata/poseidon.json holds light_poseidon 0.4.0
// Poseidon::<ark_bn254::Fr>::new_circom(n) hashes for n = 1..12: zeros, ones,
// consecutive values, p - 1, and mixed large values, five per arity.
func TestPoseidonMatchesLightPoseidon(t *testing.T) {
	encoded, err := os.ReadFile("testdata/poseidon.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Arity  int
		Inputs []string
		Hash   string
	}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 5*gnarksdk.MaxPoseidonInputs {
		t.Fatalf("expected %d vectors, got %d", 5*gnarksdk.MaxPoseidonInputs, len(vectors))
	}
	for arity := 1; arity <= gnarksdk.MaxPoseidonInputs; arity++ {
		t.Run(fmt.Sprint(arity), func(t *testing.T) {
			cs := compile(t, &poseidonCircuit{Inputs: make([]frontend.Variable, arity)})
			for _, vector := range vectors {
				if vector.Arity != arity {
					continue
				}
				hash, ok := new(big.Int).SetString(vector.Hash, 10)
				if !ok {
					t.Fatalf("invalid vector hash %q", vector.Hash)
				}
				assignment := &poseidonCircuit{Inputs: make([]frontend.Variable, arity), Expected: hash}
				for i, input := range vector.Inputs {
					assignment.Inputs[i] = input
				}
				assertAccepted(t, cs, assignment)
				assignment.Expected = plusOne(hash)
				assertRejected(t, cs, assignment)
			}
		})
	}
}

func TestPoseidonRejectsUnsupportedArityAndField(t *testing.T) {
	for _, arity := range []int{0, gnarksdk.MaxPoseidonInputs + 1} {
		_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &poseidonCircuit{Inputs: make([]frontend.Variable, arity)})
		if err == nil {
			t.Fatalf("compiled a Poseidon of %d inputs", arity)
		}
	}
	_, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &poseidonCircuit{Inputs: make([]frontend.Variable, 2)})
	if err == nil {
		t.Fatal("compiled a Poseidon over a non-BN254 field")
	}
}

type hashBytesCircuit struct {
	Bytes    []frontend.Variable
	Expected frontend.Variable `gnark:",public"`
}

func (c *hashBytesCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(gnarksdk.HashBytes(api, c.Bytes), c.Expected)
	return nil
}

func TestHashBytesMatchesProtocol(t *testing.T) {
	for _, length := range []int{1, 31, 32, 33, 72} {
		t.Run(fmt.Sprint(length), func(t *testing.T) {
			bytes := make([]byte, length)
			assignment := &hashBytesCircuit{Bytes: make([]frontend.Variable, length)}
			for i := range bytes {
				bytes[i] = byte(255 - i)
				assignment.Bytes[i] = bytes[i]
			}
			hash := must(t)(protocol.HashBytes(bytes))
			assignment.Expected = hash
			cs := compile(t, &hashBytesCircuit{Bytes: make([]frontend.Variable, length)})
			assertAccepted(t, cs, assignment)
			assignment.Expected = plusOne(hash)
			assertRejected(t, cs, assignment)
		})
	}
}

type privateTxHashCircuit struct {
	Inputs            []frontend.Variable
	Outputs           []frontend.Variable
	ExternalDataHash  frontend.Variable
	PrivateTxBlinding frontend.Variable
	Expected          frontend.Variable `gnark:",public"`
}

func (c *privateTxHashCircuit) Define(api frontend.API) error {
	hash := gnarksdk.PrivateTxHash(api, c.Inputs, c.Outputs, c.ExternalDataHash, c.PrivateTxBlinding)
	api.AssertIsEqual(hash, c.Expected)
	return nil
}

func TestPrivateTxHashMatchesProtocol(t *testing.T) {
	for _, shape := range []struct{ inputs, outputs int }{{1, 1}, {2, 2}, {2, 3}, {5, 1}} {
		t.Run(fmt.Sprintf("%dx%d", shape.inputs, shape.outputs), func(t *testing.T) {
			inputs := make([]*big.Int, shape.inputs)
			addressNullifiers := make([]*big.Int, shape.inputs)
			outputs := make([]*big.Int, shape.outputs)
			assignment := &privateTxHashCircuit{
				Inputs:            make([]frontend.Variable, shape.inputs),
				Outputs:           make([]frontend.Variable, shape.outputs),
				ExternalDataHash:  17,
				PrivateTxBlinding: 19,
			}
			for i := range inputs {
				inputs[i] = big.NewInt(int64(100 + i))
				addressNullifiers[i] = new(big.Int)
				assignment.Inputs[i] = inputs[i]
			}
			// The last input is a padding slot, which contributes 0.
			inputs[shape.inputs-1] = new(big.Int)
			assignment.Inputs[shape.inputs-1] = 0
			for i := range outputs {
				outputs[i] = big.NewInt(int64(200 + i))
				assignment.Outputs[i] = outputs[i]
			}
			hash := must(t)(protocol.PrivateTxHash(inputs, outputs, addressNullifiers, big.NewInt(17), big.NewInt(19)))
			assignment.Expected = hash
			cs := compile(t, &privateTxHashCircuit{
				Inputs:  make([]frontend.Variable, shape.inputs),
				Outputs: make([]frontend.Variable, shape.outputs),
			})
			assertAccepted(t, cs, assignment)
			assignment.Expected = plusOne(hash)
			assertRejected(t, cs, assignment)
		})
	}
}
