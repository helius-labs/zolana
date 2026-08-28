package custom_ring

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"zolana/prover/prover/common"
)

func TestCustomRingProofVerifies(t *testing.T) {
	params := &CustomRingParameters{
		PublicInputHash: value([]byte{
			24, 191, 117, 99, 166, 70, 117, 193, 16, 174, 125, 64, 139, 151, 60, 152,
			0, 90, 250, 198, 208, 107, 138, 225, 119, 244, 67, 93, 126, 110, 2, 11,
		}),
		PrivateTxHash: big.NewInt(0xabcdef),
		TxViewingSk: [32]byte{
			1, 16, 19, 18, 21, 20, 23, 22, 25, 24, 27, 26, 29, 28, 31, 30,
			1, 0, 3, 2, 5, 4, 7, 6, 9, 8, 11, 10, 13, 12, 15, 14,
		},
		EphSk: [32]byte{
			1, 35, 32, 33, 38, 39, 36, 37, 42, 43, 40, 41, 46, 47, 44, 45,
			50, 51, 48, 49, 54, 55, 52, 53, 58, 59, 56, 57, 62, 63, 60, 61,
		},
		AuditorPk: [65]byte{
			4, 157, 197, 27, 89, 0, 107, 19, 241, 67, 148, 77, 78, 67, 45, 183,
			192, 50, 36, 28, 235, 54, 152, 166, 204, 12, 218, 186, 223, 41, 183, 29,
			236, 32, 85, 73, 70, 17, 145, 94, 125, 188, 165, 106, 176, 45, 249, 243,
			183, 5, 16, 233, 35, 226, 146, 82, 68, 228, 56, 188, 140, 235, 240, 230, 53,
		},
	}

	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path unavailable")
	}
	keyPath := filepath.Join(filepath.Dir(source), "..", "..", "proving-keys", common.CustomRingKeyFile)
	if _, err := os.Stat(keyPath); err != nil {
		t.Skip("custom ring proving key is not available")
	}
	loaded, err := common.ReadSystemFromFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	loadedSystem, ok := loaded.(*common.RingProofSystem)
	if !ok {
		t.Fatalf("unexpected proof system %T", loaded)
	}
	var verifier bytes.Buffer
	if _, err := loadedSystem.VerifyingKey.WriteRawTo(&verifier); err != nil {
		t.Fatal(err)
	}
	verifierHash := sha256.Sum256(verifier.Bytes())
	if hex.EncodeToString(verifierHash[:]) != "94624b9d0191d3fabee4635ae780d6d53fc090c0ae59296cfa045f023132e167" {
		t.Fatal("custom ring verifier does not match the program")
	}
	proof, err := ProveCustomRing(loadedSystem, params)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := params.CreateWitness()
	if err != nil {
		t.Fatal(err)
	}
	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof.Proof, loadedSystem.VerifyingKey, witness); err != nil {
		t.Fatal(err)
	}
}

func value(bytes []byte) *big.Int {
	return new(big.Int).SetBytes(bytes)
}
