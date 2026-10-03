package merge_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	merge "zolana/prover/circuits/spp_merge"
	mergeshared "zolana/prover/circuits/spp_merge/shared"
)

// A merger that knows the owner's nullifier secret could otherwise publish an
// output the owner cannot rebuild, for example by planting an input the owner
// never learns about. The masked amount pins the published value to the real
// sum, so these witnesses carry a consistent public input hash and must still
// fail on the masked-amount constraint alone.

func TestMergeRejectsWrongMaskedAmount(t *testing.T) {
	f := buildMergeFixture(t, mergeFixtureOptions{})
	if err := test.IsSolved(merge.NewMergeCircuit(defaultFixtureInputs), f.defaultCircuit(), ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("baseline witness does not solve: %v", err)
	}
	f.public.MaskedAmount = new(big.Int).Add(f.public.MaskedAmount.(*big.Int), big.NewInt(1))
	refreshDefaultPublicInputHash(t, f)
	if err := test.IsSolved(merge.NewMergeCircuit(defaultFixtureInputs), f.defaultCircuit(), ecc.BN254.ScalarField()); err == nil {
		t.Fatal("accepted a masked amount that does not encode the output amount")
	}
}

func TestMergeRejectsUnmaskedAmount(t *testing.T) {
	f := buildMergeFixture(t, mergeFixtureOptions{})
	sum := new(big.Int)
	for _, input := range f.inputs {
		sum.Add(sum, input.Amount.(*big.Int))
	}
	f.public.MaskedAmount = sum
	refreshDefaultPublicInputHash(t, f)
	if err := test.IsSolved(merge.NewMergeCircuit(defaultFixtureInputs), f.defaultCircuit(), ecc.BN254.ScalarField()); err == nil {
		t.Fatal("accepted the plain output amount in place of the masked amount")
	}
}

// The mint is masked chunk by chunk, so each chunk is pinned on its own.
func TestMergeRejectsWrongMaskedMint(t *testing.T) {
	for chunk := range mergeshared.MintChunkCount {
		f := buildMergeFixture(t, mergeFixtureOptions{})
		f.public.MaskedMint[chunk] = new(big.Int).Add(f.public.MaskedMint[chunk].(*big.Int), big.NewInt(1))
		refreshDefaultPublicInputHash(t, f)
		if err := test.IsSolved(merge.NewMergeCircuit(defaultFixtureInputs), f.defaultCircuit(), ecc.BN254.ScalarField()); err == nil {
			t.Fatalf("accepted masked mint chunk %d that does not encode the mint", chunk)
		}
	}
}

func TestMergeRejectsUnmaskedMint(t *testing.T) {
	f := buildMergeFixture(t, mergeFixtureOptions{})
	for chunk, value := range f.mintChunks {
		f.public.MaskedMint[chunk] = value
	}
	refreshDefaultPublicInputHash(t, f)
	if err := test.IsSolved(merge.NewMergeCircuit(defaultFixtureInputs), f.defaultCircuit(), ecc.BN254.ScalarField()); err == nil {
		t.Fatal("accepted the plain mint chunks in place of the masked mint")
	}
}

// Each mask is seeded by its own published nonce, so republishing the same
// masked values under another nonce does not solve.
func TestMergeRejectsAnotherMaskNonce(t *testing.T) {
	for _, nonce := range []string{"amount", "mint"} {
		f := buildMergeFixture(t, mergeFixtureOptions{})
		switch nonce {
		case "amount":
			f.public.AmountMaskNonce = new(big.Int).Add(f.public.AmountMaskNonce.(*big.Int), big.NewInt(1))
		case "mint":
			f.public.MintMaskNonce = new(big.Int).Add(f.public.MintMaskNonce.(*big.Int), big.NewInt(1))
		}
		refreshDefaultPublicInputHash(t, f)
		if err := test.IsSolved(merge.NewMergeCircuit(defaultFixtureInputs), f.defaultCircuit(), ecc.BN254.ScalarField()); err == nil {
			t.Fatalf("accepted masked values under a %s nonce that did not produce them", nonce)
		}
	}
}

func TestMergeRingRejectsWrongMaskedAmount(t *testing.T) {
	f := buildMergeFixture(t, mergeFixtureOptions{
		rail:           ringFixtureRail,
		ringProgramID:  big.NewInt(0x5A0E),
		inputRingData:  []*big.Int{big.NewInt(0xD0), big.NewInt(0xD1)},
		outputRingData: big.NewInt(0xD2),
	})
	if err := test.IsSolved(merge.NewMergeRingCircuit(defaultFixtureInputs), f.ringCircuit(), ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("baseline ring witness does not solve: %v", err)
	}
	f.public.MaskedAmount = new(big.Int).Add(f.public.MaskedAmount.(*big.Int), big.NewInt(1))
	refreshRingPublicInputHash(t, f)
	if err := test.IsSolved(merge.NewMergeRingCircuit(defaultFixtureInputs), f.ringCircuit(), ecc.BN254.ScalarField()); err == nil {
		t.Fatal("accepted a ring masked amount that does not encode the output amount")
	}
}
