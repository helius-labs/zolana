package merge_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	merge "zolana/prover/circuits/spp_merge"
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
