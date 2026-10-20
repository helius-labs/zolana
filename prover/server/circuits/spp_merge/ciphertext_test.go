package merge_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	merge "github.com/helius-labs/zolana/prover/server/circuits/spp_merge"
	mergeshared "github.com/helius-labs/zolana/prover/server/circuits/spp_merge/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
)

// ciphertextTail is the salt followed by the ciphertext, the last elements of
// the default rail's public-input-hash preimage. The ring rail binds neither
// (see ring_test.go).
const ciphertextTail = 1 + mergeshared.MergeOutputCiphertextLen

func defaultCiphertextFixture(t *testing.T) *mergeWitnessFixture {
	return buildMergeFixture(t, mergeFixtureOptions{rail: defaultFixtureRail})
}

func solveDefault(f *mergeWitnessFixture) error {
	return test.IsSolved(merge.NewMergeCircuit(len(f.inputs)), f.defaultCircuit(), ecc.BN254.ScalarField())
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
	f := defaultCiphertextFixture(t)
	tail := f.publicInputPreimage[len(f.publicInputPreimage)-ciphertextTail:]
	if tail[0].Cmp(fixtureCiphertextSalt) != 0 {
		t.Fatalf("salt position: got %v", tail[0])
	}
	for i, element := range f.outputCiphertext {
		if tail[1+i].Cmp(element) != 0 {
			t.Fatalf("ciphertext element %d out of place", i)
		}
	}
	if err := solveDefault(f); err != nil {
		t.Fatalf("host ciphertext rejected: %v", err)
	}
}

func TestMergeCircuitRejectsTamperedCiphertext(t *testing.T) {
	for element := range mergeshared.MergeOutputCiphertextLen {
		f := defaultCiphertextFixture(t)
		tampered := append([]*big.Int{}, f.outputCiphertext...)
		tampered[element] = new(big.Int).Add(tampered[element], big.NewInt(1))
		f.withPreimageTail(t, fixtureCiphertextSalt, tampered)
		if err := solveDefault(f); err == nil {
			t.Fatalf("tampered ciphertext element %d solved", element)
		}
	}
}

// The salt is a public input: a proof over one salt does not verify under
// another, and a different salt yields different pads.
func TestMergeCircuitBindsTheSalt(t *testing.T) {
	otherSalt := new(big.Int).Add(fixtureCiphertextSalt, big.NewInt(1))

	f := defaultCiphertextFixture(t)
	f.outputCiphertextSalt = otherSalt
	if err := solveDefault(f); err == nil {
		t.Fatal("a ciphertext under one salt solved under another")
	}

	f = defaultCiphertextFixture(t)
	amount := big.NewInt(5 + 7)
	firstNullifier := f.public.Nullifiers[0].(*big.Int)
	resalted, err := protocol.MergeOutputCiphertext(
		f.userNullifierSecret, firstNullifier, otherSalt, amount, fixtureMint,
	)
	if err != nil {
		t.Fatal(err)
	}
	for i := range resalted {
		if resalted[i].Cmp(f.outputCiphertext[i]) == 0 {
			t.Fatalf("element %d repeated across salts", i)
		}
	}
	f.outputCiphertextSalt = otherSalt
	f.withPreimageTail(t, otherSalt, resalted)
	if err := solveDefault(f); err != nil {
		t.Fatalf("the same merge under a fresh salt: %v", err)
	}
}
