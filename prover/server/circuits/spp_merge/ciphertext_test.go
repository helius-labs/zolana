package merge_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	merge "github.com/helius-labs/zolana/prover/server/circuits/spp_merge"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

// ciphertextTail is the salt followed by the ciphertext, the last elements of
// the public-input-hash preimage on both rails.
const ciphertextTail = 1 + mergeshared.MergeOutputCiphertextLen

type ciphertextRail struct {
	name    string
	fixture func(t *testing.T) *mergeWitnessFixture
	circuit func(f *mergeWitnessFixture) (frontend.Circuit, frontend.Circuit)
}

var ciphertextRails = []ciphertextRail{
	{
		name: "default",
		fixture: func(t *testing.T) *mergeWitnessFixture {
			return buildMergeFixture(t, mergeFixtureOptions{rail: defaultFixtureRail})
		},
		circuit: func(f *mergeWitnessFixture) (frontend.Circuit, frontend.Circuit) {
			return merge.NewMergeCircuit(len(f.inputs)), f.defaultCircuit()
		},
	},
	{
		name: "ring",
		fixture: func(t *testing.T) *mergeWitnessFixture {
			return buildMergeFixture(t, mergeFixtureOptions{
				rail:           ringFixtureRail,
				ringProgramID:  big.NewInt(0xC0FFEE),
				inputRingData:  []*big.Int{big.NewInt(0xD0), big.NewInt(0xD0)},
				outputRingData: big.NewInt(0xD0),
			})
		},
		circuit: func(f *mergeWitnessFixture) (frontend.Circuit, frontend.Circuit) {
			return merge.NewMergeRingCircuit(len(f.inputs)), f.ringCircuit()
		},
	},
}

// withPreimageTail replaces the salt and ciphertext at the end of the
// public-input-hash preimage and rehashes it.
func (f *mergeWitnessFixture) withPreimageTail(t *testing.T, salt *big.Int, ciphertext []*big.Int) {
	t.Helper()
	preimage := append([]*big.Int{}, f.publicInputPreimage[:len(f.publicInputPreimage)-ciphertextTail]...)
	preimage = append(preimage, salt)
	preimage = append(preimage, ciphertext...)
	f.publicInputPreimage = preimage
	f.publicInputHash = hashChain4(t, preimage)
}

func TestMergeCiphertextIsTheLastPublicInputs(t *testing.T) {
	for _, rail := range ciphertextRails {
		t.Run(rail.name, func(t *testing.T) {
			f := rail.fixture(t)
			tail := f.publicInputPreimage[len(f.publicInputPreimage)-ciphertextTail:]
			if tail[0].Cmp(fixtureCiphertextSalt) != 0 {
				t.Fatalf("salt position: got %v", tail[0])
			}
			for i, element := range f.outputCiphertext {
				if tail[1+i].Cmp(element) != 0 {
					t.Fatalf("ciphertext element %d out of place", i)
				}
			}
			empty, assignment := rail.circuit(f)
			if err := test.IsSolved(empty, assignment, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("host ciphertext rejected: %v", err)
			}
		})
	}
}

func TestMergeCircuitRejectsTamperedCiphertext(t *testing.T) {
	for _, rail := range ciphertextRails {
		for element := range mergeshared.MergeOutputCiphertextLen {
			f := rail.fixture(t)
			tampered := append([]*big.Int{}, f.outputCiphertext...)
			tampered[element] = new(big.Int).Add(tampered[element], big.NewInt(1))
			f.withPreimageTail(t, fixtureCiphertextSalt, tampered)
			empty, assignment := rail.circuit(f)
			if err := test.IsSolved(empty, assignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatalf("%s: tampered ciphertext element %d solved", rail.name, element)
			}
		}
	}
}

// The salt is a public input: a proof over one salt does not verify under
// another, and a different salt yields different pads.
func TestMergeCircuitBindsTheSalt(t *testing.T) {
	otherSalt := new(big.Int).Add(fixtureCiphertextSalt, big.NewInt(1))
	for _, rail := range ciphertextRails {
		t.Run(rail.name, func(t *testing.T) {
			f := rail.fixture(t)
			f.public.OutputCiphertextSalt = otherSalt
			empty, assignment := rail.circuit(f)
			if err := test.IsSolved(empty, assignment, ecc.BN254.ScalarField()); err == nil {
				t.Fatal("a ciphertext under one salt solved under another")
			}

			f = rail.fixture(t)
			mint := fixtureMint
			amount := big.NewInt(5 + 7)
			nullifierSecret := f.userNullifierSecret
			firstNullifier := f.public.Nullifiers[0].(*big.Int)
			resalted, err := protocol.MergeOutputCiphertext(nullifierSecret, firstNullifier, otherSalt, amount, mint)
			if err != nil {
				t.Fatal(err)
			}
			for i := range resalted {
				if resalted[i].Cmp(f.outputCiphertext[i]) == 0 {
					t.Fatalf("element %d repeated across salts", i)
				}
			}
			f.public.OutputCiphertextSalt = otherSalt
			f.withPreimageTail(t, otherSalt, resalted)
			empty, assignment = rail.circuit(f)
			if err := test.IsSolved(empty, assignment, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("the same merge under a fresh salt: %v", err)
			}
		})
	}
}
