package shared_test

import (
	"testing"

	. "zolana/prover/circuits/spp_transaction/shared"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type publishedOutputOwnerCircuit struct {
	Output    UtxoCircuitFields
	Actual    frontend.Variable
	Published frontend.Variable
}

func (c *publishedOutputOwnerCircuit) Define(api frontend.API) error {
	return AssertPublishedOutputOwners(
		api,
		[]UtxoCircuitFields{c.Output},
		[]frontend.Variable{c.Actual},
		[]frontend.Variable{c.Published},
	)
}

func outputOwnerAssignment(ringProgramID, actual, published int) *publishedOutputOwnerCircuit {
	return &publishedOutputOwnerCircuit{
		Output:    outputFields(UtxoDomain, ringProgramID),
		Actual:    actual,
		Published: published,
	}
}

func outputFields(domain, ringProgramID int) UtxoCircuitFields {
	return UtxoCircuitFields{
		Domain:        domain,
		Owner:         0,
		Asset:         0,
		Amount:        0,
		Blinding:      0,
		DataHash:      0,
		RingDataHash:  0,
		RingProgramID: ringProgramID,
	}
}

type maskedDummyTagCircuit struct {
	Real             UtxoCircuitFields
	Dummy            UtxoCircuitFields
	RealPublished    frontend.Variable
	DummyPublished   frontend.Variable
	PublicIdentities [2]frontend.Variable
}

func (c *maskedDummyTagCircuit) Define(api frontend.API) error {
	return AssertMaskedDummyOutputTags(
		api,
		[]UtxoCircuitFields{c.Real, c.Dummy},
		[]frontend.Variable{c.RealPublished, c.DummyPublished},
		Signers(c.PublicIdentities[:]),
	)
}

// One real output in ring realRingProgramID publishing realPublished, one dummy
// publishing dummyPublished, and a public identity list holding 5 plus zero
// padding.
func maskedDummyTagAssignment(realRingProgramID, realPublished, dummyPublished int) *maskedDummyTagCircuit {
	return &maskedDummyTagCircuit{
		Real:             outputFields(UtxoDomain, realRingProgramID),
		Dummy:            outputFields(DummyDomain, 0),
		RealPublished:    realPublished,
		DummyPublished:   dummyPublished,
		PublicIdentities: [2]frontend.Variable{5, 0},
	}
}

// A dummy's non-zero published tag may only repeat a value the transaction
// already publishes: a listed public identity or a real output's published
// owner. A policy-ring recipient publishes zero, so their identity is not
// nameable, and neither is an outsider. Zero always passes.
func TestMaskedDummyOutputTagsRepeatOnlyPublishedIdentities(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &maskedDummyTagCircuit{}

	assert.SolvingSucceeded(circuit, maskedDummyTagAssignment(0, 7, 0), test.WithCurves(ecc.BN254))
	assert.SolvingSucceeded(circuit, maskedDummyTagAssignment(0, 7, 5), test.WithCurves(ecc.BN254))
	assert.SolvingSucceeded(circuit, maskedDummyTagAssignment(0, 7, 7), test.WithCurves(ecc.BN254))
	assert.SolvingFailed(circuit, maskedDummyTagAssignment(0, 7, 9), test.WithCurves(ecc.BN254))
	assert.SolvingSucceeded(circuit, maskedDummyTagAssignment(3, 0, 0), test.WithCurves(ecc.BN254))
	assert.SolvingFailed(circuit, maskedDummyTagAssignment(3, 0, 7), test.WithCurves(ecc.BN254))
}

func TestPublishedOutputOwnersSeparateDefaultAndPolicyRings(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := &publishedOutputOwnerCircuit{}

	assert.SolvingSucceeded(
		circuit,
		outputOwnerAssignment(0, 7, 7),
		test.WithCurves(ecc.BN254),
	)
	assert.SolvingFailed(
		circuit,
		outputOwnerAssignment(0, 7, 0),
		test.WithCurves(ecc.BN254),
	)
	assert.SolvingSucceeded(
		circuit,
		outputOwnerAssignment(9, 7, 0),
		test.WithCurves(ecc.BN254),
	)
	assert.SolvingFailed(
		circuit,
		outputOwnerAssignment(9, 7, 7),
		test.WithCurves(ecc.BN254),
	)
}
