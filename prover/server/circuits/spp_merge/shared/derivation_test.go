package shared

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type mergeRecoveryVector struct {
	NullifierSecret string   `json:"nullifier_secret"`
	FirstNullifier  string   `json:"first_nullifier"`
	OutputBlinding  string   `json:"output_blinding"`
	DummySlotIndex  int      `json:"dummy_slot_index"`
	DummyNullifier  string   `json:"dummy_nullifier"`
	OutputKey       string   `json:"output_key"`
	Salt            string   `json:"output_ciphertext_salt"`
	Amount          uint64   `json:"output_amount"`
	Mint            string   `json:"output_mint"`
	Ciphertext      []string `json:"output_ciphertext"`
}

func recoveryVector(t *testing.T) mergeRecoveryVector {
	t.Helper()
	data, err := os.ReadFile("../../../../../test-vectors/key_derivation.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		MergeRecovery mergeRecoveryVector `json:"merge_recovery"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors.MergeRecovery
}

func vectorField(t *testing.T, value string) *big.Int {
	t.Helper()
	field, ok := new(big.Int).SetString(value, 16)
	if !ok {
		t.Fatalf("invalid vector field: %q", value)
	}
	return field
}

type derivationCircuit struct {
	Slot             int `gnark:"-"`
	Secret           frontend.Variable
	Tag              frontend.Variable
	ExpectedBlinding frontend.Variable
	ExpectedDummy    frontend.Variable
}

func (c *derivationCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.ExpectedBlinding, MergeOutputBlinding(api, c.Secret, c.Tag))
	api.AssertIsEqual(c.ExpectedDummy, MergeDummyNullifier(api, c.Secret, c.Tag, c.Slot))
	return nil
}

// The circuit reads the same recovery vector as the Rust and TypeScript SDKs.
func TestRecoveryDerivationsMatchRustVectors(t *testing.T) {
	vector := recoveryVector(t)
	witness := derivationCircuit{
		Slot:             vector.DummySlotIndex,
		Secret:           vectorField(t, vector.NullifierSecret),
		Tag:              vectorField(t, vector.FirstNullifier),
		ExpectedBlinding: vectorField(t, vector.OutputBlinding),
		ExpectedDummy:    vectorField(t, vector.DummyNullifier),
	}
	circuit := &derivationCircuit{Slot: vector.DummySlotIndex}
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(circuit, &witness, test.WithCurves(ecc.BN254))
	witness.ExpectedBlinding = new(big.Int).Add(vectorField(t, vector.OutputBlinding), big.NewInt(1))
	assert.SolvingFailed(circuit, &witness, test.WithCurves(ecc.BN254))
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
	vector := recoveryVector(t)
	mint, err := hex.DecodeString(vector.Mint)
	if err != nil || len(mint) != 32 {
		t.Fatalf("invalid vector mint: %q", vector.Mint)
	}
	if len(vector.Ciphertext) != MergeOutputCiphertextLen {
		t.Fatal("invalid vector ciphertext width")
	}
	witness := outputCiphertextCircuit{
		Secret:         vectorField(t, vector.NullifierSecret),
		FirstNullifier: vectorField(t, vector.FirstNullifier),
		Salt:           vectorField(t, vector.Salt),
		Amount:         new(big.Int).SetUint64(vector.Amount),
		MintChunks:     [2]frontend.Variable{new(big.Int).SetBytes(mint[:31]), new(big.Int).SetBytes(mint[31:])},
		ExpectedKey:    vectorField(t, vector.OutputKey),
	}
	for index, element := range vector.Ciphertext {
		witness.ExpectedCiphertext[index] = vectorField(t, element)
	}
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&outputCiphertextCircuit{}, &witness, test.WithCurves(ecc.BN254))
	witness.Salt = new(big.Int).Add(vectorField(t, vector.Salt), big.NewInt(1))
	assert.SolvingFailed(&outputCiphertextCircuit{}, &witness, test.WithCurves(ecc.BN254))
}

type mintChunkCircuit struct {
	MintChunks [2]frontend.Variable
}

func (c *mintChunkCircuit) Define(api frontend.API) error {
	_ = MergeOutputCiphertext(api, 1, 2, 3, 4, c.MintChunks)
	return nil
}

func TestMergeOutputRejectsUndecodableMintChunks(t *testing.T) {
	maximumHead := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 248), big.NewInt(1))
	valid := mintChunkCircuit{MintChunks: [2]frontend.Variable{maximumHead, 255}}
	if err := test.IsSolved(&mintChunkCircuit{}, &valid, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("rejected canonical mint chunks: %v", err)
	}
	for _, invalid := range [][2]frontend.Variable{
		{new(big.Int).Lsh(big.NewInt(1), 248), 0},
		{0, 256},
	} {
		witness := mintChunkCircuit{MintChunks: invalid}
		if err := test.IsSolved(&mintChunkCircuit{}, &witness, ecc.BN254.ScalarField()); err == nil {
			t.Fatalf("accepted undecodable mint chunks: %v", invalid)
		}
	}
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
