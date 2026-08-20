package shared

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type outputBlindingDerivationCircuit struct {
	FirstNullifier frontend.Variable
	Seed           frontend.Variable
	Expected       frontend.Variable
}

func (c *outputBlindingDerivationCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Expected, DeriveOutputBlinding(api, c.FirstNullifier, c.Seed, 3))
	return nil
}

func TestOutputBlindingDerivationMatchesRustVector(t *testing.T) {
	expected, ok := new(big.Int).SetString(
		"06261540e857febb5f8d59eb742ad3d4d8200ff38ccbf2ea16cd1e0a9085e881",
		16,
	)
	if !ok {
		t.Fatal("parse expected output blinding")
	}
	assignment := outputBlindingDerivationCircuit{
		FirstNullifier: 7,
		Seed:           42,
		Expected:       expected,
	}
	test.NewAssert(t).SolvingSucceeded(
		&outputBlindingDerivationCircuit{},
		&assignment,
		test.WithCurves(ecc.BN254),
	)
}

func TestOutputBlindingDomainIsAsciiTag(t *testing.T) {
	if OutputBlindingDomainV1 != 0x54584f42 {
		t.Fatalf("OutputBlindingDomainV1 = %#x", OutputBlindingDomainV1)
	}
}
