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

func outputOwnerAssignment(zoneProgramID, actual, published int) *publishedOutputOwnerCircuit {
	return &publishedOutputOwnerCircuit{
		Output: UtxoCircuitFields{
			Domain:        UtxoDomain,
			Owner:         0,
			Asset:         0,
			Amount:        0,
			Blinding:      0,
			DataHash:      0,
			ZoneDataHash:  0,
			ZoneProgramID: zoneProgramID,
		},
		Actual:    actual,
		Published: published,
	}
}

func TestPublishedOutputOwnersSeparateDefaultAndPolicyZones(t *testing.T) {
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
