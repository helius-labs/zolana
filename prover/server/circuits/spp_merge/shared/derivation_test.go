package shared

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type derivationCircuit struct {
	Secret             frontend.Variable
	Tag                frontend.Variable
	AmountNonce        frontend.Variable
	MintNonce          frontend.Variable
	ExpectedBlinding   frontend.Variable
	ExpectedDummy      frontend.Variable
	ExpectedAmountMask frontend.Variable
	ExpectedMintMask   frontend.Variable
}

func (c *derivationCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.ExpectedBlinding, MergeOutputBlinding(api, c.Secret, c.Tag))
	api.AssertIsEqual(c.ExpectedDummy, MergeDummyNullifier(api, c.Secret, c.Tag, 3))
	api.AssertIsEqual(c.ExpectedAmountMask, MergeAmountMask(api, c.Secret, c.Tag, c.AmountNonce))
	api.AssertIsEqual(c.ExpectedMintMask, MergeMintMask(api, c.Secret, c.Tag, c.MintNonce, 1))
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

	// The nonces are the ones SPP derives from the mask seed 0x11 * 31
	// (test-vectors/key_derivation.json merge_recovery).
	witness := derivationCircuit{
		Secret:             big.NewInt(42),
		Tag:                big.NewInt(7),
		AmountNonce:        mustBig("00e843d6fa3d658423d5e2f61fac0e6eba7f38852034c93694d6f2cd4d3fc800"),
		MintNonce:          mustBig("005035f49a053ad3ac886b2147a0d785abdb3283fb48f0ad1998f8b90e134a3f"),
		ExpectedBlinding:   mustBig("2f6bd14769ab9af9cdede9526bb87e83ee9ba49a41f8e2b7158b50433f541897"),
		ExpectedDummy:      mustBig("1498da905bec363e5c1ae40faee4aca4e3ee990a9e030599797bcbda18cff914"),
		ExpectedAmountMask: mustBig("2032b66dd037d718b31de5503679f2eb818876cc3010e647e23174ed061e3abd"),
		ExpectedMintMask:   mustBig("2fe5bbb0e2417e0d3e14d759a37b62cd1dedd08337148a69d517127525597ae2"),
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
	if MergeAmountMaskDomain != 0x544d414d { // "TMAM"
		t.Fatalf("MergeAmountMaskDomain = %#x", MergeAmountMaskDomain)
	}
	if MergeMintMaskDomain != 0x544d4d41 { // "TMMA"
		t.Fatalf("MergeMintMaskDomain = %#x", MergeMintMaskDomain)
	}
}
