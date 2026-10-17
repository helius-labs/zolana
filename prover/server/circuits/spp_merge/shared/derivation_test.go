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

type outputCiphertextCircuit struct {
	Secret             frontend.Variable
	FirstNullifier     frontend.Variable
	Salt               frontend.Variable
	Amount             frontend.Variable
	MintChunks         [2]frontend.Variable
	ExpectedKey        frontend.Variable
	ExpectedCiphertext [MergeOutputCiphertextLen]frontend.Variable
}

func (c *outputCiphertextCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.ExpectedKey, MergeOutputKey(api, c.Secret, c.FirstNullifier))
	ciphertext := MergeOutputCiphertext(api, c.Secret, c.FirstNullifier, c.Salt, c.Amount, c.MintChunks)
	for i, element := range ciphertext {
		api.AssertIsEqual(c.ExpectedCiphertext[i], element)
	}
	return nil
}

// TestOutputCiphertextMatchesSharedVectors pins the in-circuit key and
// ciphertext against test-vectors/key_derivation.json merge_recovery, which the
// Rust and TypeScript clients assert too.
func TestOutputCiphertextMatchesSharedVectors(t *testing.T) {
	mustBig := func(hexStr string) *big.Int {
		v, ok := new(big.Int).SetString(hexStr, 16)
		if !ok {
			t.Fatalf("bad hex: %s", hexStr)
		}
		return v
	}
	witness := outputCiphertextCircuit{
		Secret:         big.NewInt(0x2a),
		FirstNullifier: big.NewInt(0x07),
		Salt:           mustBig("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"),
		Amount:         big.NewInt(1_000_000_007),
		MintChunks: [2]frontend.Variable{
			mustBig("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
			big.NewInt(0x20),
		},
		ExpectedKey: mustBig("13dbaaca7265b36159c9ef318512003a522cb6059c6bb56f31cbd01badb669cb"),
		ExpectedCiphertext: [MergeOutputCiphertextLen]frontend.Variable{
			mustBig("02136684d623aad22f89c2b43f1f39bba344008ab9f3db882f71ab6ab34335f0"),
			mustBig("08237cf2cb0566d514c2fd6ac26300de33fe04a4acd13359f5ffeaf9abfb8d3f"),
			mustBig("2886c92820876f5e681d0990d63bd76bdce8ac3921409c56a8559b42805a03f0"),
		},
	}
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&outputCiphertextCircuit{}, &witness, test.WithCurves(ecc.BN254))

	witness.Salt = mustBig("a0a1a2a3a4a5a6a7a8a9aaabacadaeb0")
	assert.SolvingFailed(&outputCiphertextCircuit{}, &witness, test.WithCurves(ecc.BN254))
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
	if MergeOutputKeyDomain != 0x544d4f4b { // "TMOK"
		t.Fatalf("MergeOutputKeyDomain = %#x", MergeOutputKeyDomain)
	}
	if MergeOutputCiphertextDomain != 0x544d4f43 { // "TMOC"
		t.Fatalf("MergeOutputCiphertextDomain = %#x", MergeOutputCiphertextDomain)
	}
}
