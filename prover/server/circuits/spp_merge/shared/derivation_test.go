package shared

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type derivationCircuit struct {
	Secret           frontend.Variable
	Tag              frontend.Variable
	ExpectedBlinding frontend.Variable
	ExpectedDummy    frontend.Variable
}

func (c *derivationCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.ExpectedBlinding, MergeOutputBlinding(api, c.Secret, c.Tag))
	api.AssertIsEqual(c.ExpectedDummy, MergeDummyNullifier(api, c.Secret, c.Tag, 3))
	return nil
}

// TestRecoveryDerivationsMatchRustVectors pins the in-circuit recovery
// derivations against the host-side canonical implementation in
// sdk-libs/transaction/src/instructions/merge.rs
// (tests/cases/merge_derivation.rs:recovery_derivations_match_circuit_vectors).
func TestRecoveryDerivationsMatchRustVectors(t *testing.T) {
	mustBig := func(hexStr string) *big.Int {
		v, ok := new(big.Int).SetString(hexStr, 16)
		if !ok {
			t.Fatalf("bad hex: %s", hexStr)
		}
		return v
	}

	witness := derivationCircuit{
		Secret:           big.NewInt(42),
		Tag:              big.NewInt(7),
		ExpectedBlinding: mustBig("2f6bd14769ab9af9cdede9526bb87e83ee9ba49a41f8e2b7158b50433f541897"),
		ExpectedDummy:    mustBig("1498da905bec363e5c1ae40faee4aca4e3ee990a9e030599797bcbda18cff914"),
	}
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&derivationCircuit{}, &witness, test.WithCurves(ecc.BN254))

	witness.ExpectedBlinding = mustBig("1498da905bec363e5c1ae40faee4aca4e3ee990a9e030599797bcbda18cff914")
	assert.SolvingFailed(&derivationCircuit{}, &witness, test.WithCurves(ecc.BN254))
}

// TestRecoveryDomainsAreTheAsciiTags pins the tag byte values; drift here
// silently breaks wallet recovery.
func TestRecoveryDomainsAreTheAsciiTags(t *testing.T) {
	if MergeOutputBlindingDomainV1 != 0x544d4f42 { // "TMOB"
		t.Fatalf("MergeOutputBlindingDomainV1 = %#x", MergeOutputBlindingDomainV1)
	}
	if MergeDummyNullifierDomain != 0x544d444e { // "TMDN"
		t.Fatalf("MergeDummyNullifierDomain = %#x", MergeDummyNullifierDomain)
	}
}
