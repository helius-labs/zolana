package squadskeyencryption_test

import (
	"testing"

	. "zolana/prover/circuits/squads/key_encryption"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// TestKeyEncryptionCircuitCompiles is a smoke test for the common shape: one
// recovery key plus one auditor key. The circuit runs emulated-P256 scalar
// multiplication (sk·G, the ephemeral key, and one ECDH per key), so it is large.
func TestKeyEncryptionCircuitCompiles(t *testing.T) {
	circuit := NewKeyEncryptionCircuit(2)
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300)); err != nil {
		t.Fatalf("compile squads_key_encryption circuit (2 keys): %v", err)
	}
}

// TestKeyEncryptionCircuitCompilesSingleKey confirms the auditor-only shape (one
// recipient key) compiles.
func TestKeyEncryptionCircuitCompilesSingleKey(t *testing.T) {
	circuit := NewKeyEncryptionCircuit(1)
	if _, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300)); err != nil {
		t.Fatalf("compile squads_key_encryption circuit (1 key): %v", err)
	}
}
