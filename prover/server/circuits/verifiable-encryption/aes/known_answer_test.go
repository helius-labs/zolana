package aes

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCTREncryptMatchesGCMKnownAnswers(t *testing.T) {
	for _, row := range []struct {
		name       string
		key        string
		nonce      string
		plaintext  string
		ciphertext string
	}{
		{
			"GCM test case 14",
			"0000000000000000000000000000000000000000000000000000000000000000",
			"000000000000000000000000",
			"00000000000000000000000000000000",
			"cea7403d4d606b6e074ec5d3baf39d18",
		},
		{
			"GCM test case 15",
			"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			"cafebabefacedbaddecaf888",
			"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
			"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
		},
		{
			"GCM test case 16",
			"feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
			"cafebabefacedbaddecaf888",
			"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			"522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
		},
	} {
		t.Run(row.name, func(t *testing.T) {
			plaintext := mustHex(t, row.plaintext)
			assignment := &pathCtrCircuit{Plaintext: toVariables(plaintext), Ciphertext: toVariables(mustHex(t, row.ciphertext))}
			copy(assignment.Key[:], toVariables(mustHex(t, row.key)))
			copy(assignment.Nonce[:], toVariables(mustHex(t, row.nonce)))
			witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if err := compilePath(t, len(plaintext)).IsSolved(witness); err != nil {
				t.Fatalf("known answer rejected: %v", err)
			}
		})
	}
}
