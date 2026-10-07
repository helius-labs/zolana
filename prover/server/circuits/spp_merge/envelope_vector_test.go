package merge_test

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	mergeshared "zolana/prover/circuits/spp_merge/shared"
	ve "zolana/prover/circuits/verifiable-encryption"
	"zolana/prover/prover-test/hosttest"
	"zolana/prover/prover-test/poseidon"
)

type mergeEnvelopeVector struct {
	RecipientSecret       string `json:"recipient_secret"`
	EphemeralSecret       string `json:"ephemeral_secret"`
	Amount                uint64 `json:"amount"`
	Mint                  string `json:"mint"`
	RecipientCompressed   string `json:"recipient_compressed"`
	RecipientUncompressed string `json:"recipient_uncompressed"`
	EphemeralPk           string `json:"ephemeral_pk"`
	SharedSecret          string `json:"shared_secret"`
	Ciphertext            string `json:"ciphertext"`
	OutputBlinding        string `json:"output_blinding"`
}

type envelopeVectorCheck struct {
	name string
	got  []byte
	want []byte
}

type mergeEnvelopeVectorCircuit struct {
	EphemeralSk    [ve.ScalarBytes]frontend.Variable
	RecipientPk    [ve.UncompressedPointBytes]frontend.Variable
	Amount         frontend.Variable
	MintChunks     [mergeshared.MintChunkCount]frontend.Variable
	RecipientLo    frontend.Variable                                   `gnark:",public"`
	RecipientHi    frontend.Variable                                   `gnark:",public"`
	EphemeralLo    frontend.Variable                                   `gnark:",public"`
	EphemeralHi    frontend.Variable                                   `gnark:",public"`
	SharedSecret   frontend.Variable                                   `gnark:",public"`
	OutputBlinding frontend.Variable                                   `gnark:",public"`
	Ciphertext     [mergeshared.MergeCiphertextBytes]frontend.Variable `gnark:",public"`
}

func (c *mergeEnvelopeVectorCircuit) Define(api frontend.API) error {
	sealed := ve.Envelope{
		SecretTag:   mergeshared.MergeSecretTag,
		KdfInfo:     mergeshared.MergeKdfInfo,
		EphemeralSk: c.EphemeralSk,
		RecipientPk: c.RecipientPk,
		Plaintext:   mergeshared.MergePlaintext(api, c.Amount, c.MintChunks),
	}.Seal(api)
	api.AssertIsEqual(sealed.RecipientLo, c.RecipientLo)
	api.AssertIsEqual(sealed.RecipientHi, c.RecipientHi)
	api.AssertIsEqual(sealed.EphemeralLo, c.EphemeralLo)
	api.AssertIsEqual(sealed.EphemeralHi, c.EphemeralHi)
	api.AssertIsEqual(sealed.SharedSecret, c.SharedSecret)
	api.AssertIsEqual(mergeshared.MergeDerivedBlinding(api, sealed.SharedSecret), c.OutputBlinding)
	for i, b := range sealed.Ciphertext {
		api.AssertIsEqual(b, c.Ciphertext[i])
	}
	return nil
}

func readMergeEnvelopeVector(t *testing.T) mergeEnvelopeVector {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate envelope_vector_test.go")
	}
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../test-vectors/key_derivation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		MergeEnvelope *mergeEnvelopeVector `json:"merge_envelope"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	if file.MergeEnvelope == nil {
		t.Fatal("key_derivation.json has no merge_envelope section")
	}
	return *file.MergeEnvelope
}

func decodeVectorHex(t *testing.T, name, value string, length int) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(decoded) != length {
		t.Fatalf("%s: %d bytes, want %d", name, len(decoded), length)
	}
	return decoded
}

func vectorKey(t *testing.T, name, value string) *ecdh.PrivateKey {
	t.Helper()
	key, err := ecdh.P256().NewPrivateKey(decodeVectorHex(t, name, value, ve.ScalarBytes))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return key
}

func TestMergeEnvelopeMatchesRustVector(t *testing.T) {
	vector := readMergeEnvelopeVector(t)
	keys := hosttest.Keys{
		RecipientSecret: vectorKey(t, "recipient_secret", vector.RecipientSecret),
		EphemeralSecret: vectorKey(t, "ephemeral_secret", vector.EphemeralSecret),
	}
	mint := decodeVectorHex(t, "mint", vector.Mint, mergeshared.MintHeadChunkBytes+mergeshared.MintTailChunkBytes)
	recipientUncompressed := keys.RecipientUncompressed()
	recipientCompressed := hosttest.CompressP256(recipientUncompressed[:])
	ephemeralCompressed := hosttest.CompressP256(keys.EphemeralSecret.PublicKey().Bytes())

	checks := []envelopeVectorCheck{
		{"recipient_uncompressed", recipientUncompressed[:], decodeVectorHex(t, "recipient_uncompressed", vector.RecipientUncompressed, ve.UncompressedPointBytes)},
		{"recipient_compressed", recipientCompressed[:], decodeVectorHex(t, "recipient_compressed", vector.RecipientCompressed, 33)},
		{"ephemeral_pk", ephemeralCompressed[:], decodeVectorHex(t, "ephemeral_pk", vector.EphemeralPk, 33)},
	}

	plaintext := binary.BigEndian.AppendUint64(nil, vector.Amount)
	plaintext = append(plaintext, mint...)
	ciphertext, sharedSecret := keys.Seal(mergeshared.MergeSecretTag, mergeshared.MergeKdfInfo, plaintext)
	outputBlinding, err := poseidon.Hash([]*big.Int{big.NewInt(mergeshared.MergeDerivedBlindingDomain), sharedSecret})
	if err != nil {
		t.Fatal(err)
	}
	var sharedBytes, blindingBytes [32]byte
	sharedSecret.FillBytes(sharedBytes[:])
	outputBlinding.FillBytes(blindingBytes[:])
	checks = append(checks,
		envelopeVectorCheck{"ciphertext", ciphertext, decodeVectorHex(t, "ciphertext", vector.Ciphertext, mergeshared.MergeCiphertextBytes)},
		envelopeVectorCheck{"shared_secret", sharedBytes[:], decodeVectorHex(t, "shared_secret", vector.SharedSecret, 32)},
		envelopeVectorCheck{"output_blinding", blindingBytes[:], decodeVectorHex(t, "output_blinding", vector.OutputBlinding, 32)},
	)
	for _, check := range checks {
		if !bytes.Equal(check.got, check.want) {
			t.Fatalf("%s: host %x, rust %x", check.name, check.got, check.want)
		}
	}

	recipientLo, recipientHi := keys.RecipientPacked()
	ephemeralLo, ephemeralHi := keys.EphemeralPacked()
	assignment := &mergeEnvelopeVectorCircuit{
		Amount: new(big.Int).SetUint64(vector.Amount),
		MintChunks: [mergeshared.MintChunkCount]frontend.Variable{
			new(big.Int).SetBytes(mint[:mergeshared.MintHeadChunkBytes]),
			new(big.Int).SetBytes(mint[mergeshared.MintHeadChunkBytes:]),
		},
		RecipientLo:    recipientLo,
		RecipientHi:    recipientHi,
		EphemeralLo:    ephemeralLo,
		EphemeralHi:    ephemeralHi,
		SharedSecret:   sharedSecret,
		OutputBlinding: outputBlinding,
	}
	for i, b := range keys.EphemeralScalar() {
		assignment.EphemeralSk[i] = b
	}
	for i, b := range recipientUncompressed {
		assignment.RecipientPk[i] = b
	}
	for i, b := range decodeVectorHex(t, "ciphertext", vector.Ciphertext, mergeshared.MergeCiphertextBytes) {
		assignment.Ciphertext[i] = b
	}
	if err := test.IsSolved(&mergeEnvelopeVectorCircuit{}, assignment, ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("circuit rejects the Rust envelope vector: %v", err)
	}
}
