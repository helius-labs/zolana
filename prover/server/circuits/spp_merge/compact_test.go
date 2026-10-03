package merge_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	merge "zolana/prover/circuits/spp_merge"
)

// padFixtureCompact publishes 0 for every dummy slot of the fixture: compact
// padding, which SPP leaves out of the instruction (spec: Compact padding).
// The caller refreshes the public input hash for its rail.
func padFixtureCompact(fixture *mergeWitnessFixture) {
	for slot := 2; slot < len(fixture.public.Nullifiers); slot++ {
		fixture.public.Nullifiers[slot] = big.NewInt(0)
	}
}

func TestMergeCompactPaddingSolves(t *testing.T) {
	assert := test.NewAssert(t)
	for _, width := range []int{defaultFixtureInputs, 36} {
		fixture := buildMergeFixture(t, mergeFixtureOptions{inputCount: width})
		padFixtureCompact(fixture)
		refreshDefaultPublicInputHash(t, fixture)
		assert.SolvingSucceeded(merge.NewMergeCircuit(width), fixture.defaultCircuit(), test.WithCurves(ecc.BN254))
	}
}

func TestMergeRingCompactPaddingSolves(t *testing.T) {
	assert := test.NewAssert(t)
	fixture := buildMergeFixture(t, mergeFixtureOptions{
		rail:           ringFixtureRail,
		ringProgramID:  big.NewInt(0x5a),
		inputRingData:  []*big.Int{big.NewInt(0xD0), big.NewInt(0xD1)},
		outputRingData: big.NewInt(0xD2),
	})
	padFixtureCompact(fixture)
	refreshRingPublicInputHash(t, fixture)
	assert.SolvingSucceeded(merge.NewMergeRingCircuit(defaultFixtureInputs), fixture.ringCircuit(), test.WithCurves(ecc.BN254))
}

// Compact padding inserts no nullifier, so the tree-capacity gate does not
// apply to it.
func TestMergeCompactPaddingSolvesWhenDummyInputsDisallowed(t *testing.T) {
	assert := test.NewAssert(t)
	fixture := buildMergeFixture(t, mergeFixtureOptions{allowDummyInputs: big.NewInt(0)})
	padFixtureCompact(fixture)
	refreshDefaultPublicInputHash(t, fixture)
	assert.SolvingSucceeded(merge.NewMergeCircuit(defaultFixtureInputs), fixture.defaultCircuit(), test.WithCurves(ecc.BN254))
}

// A real input that publishes nullifier 0 would skip its nullifier insertion.
func TestMergeRejectsZeroNullifierOnRealSlot(t *testing.T) {
	assert := test.NewAssert(t)
	fixture := buildMergeFixture(t, mergeFixtureOptions{})
	fixture.public.Nullifiers[1] = big.NewInt(0)
	refreshDefaultPublicInputHash(t, fixture)
	assert.SolvingFailed(merge.NewMergeCircuit(defaultFixtureInputs), fixture.defaultCircuit(), test.WithCurves(ecc.BN254))
}
