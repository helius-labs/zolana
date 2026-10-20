package ed25519

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	aesgadget "github.com/helius-labs/zolana/prover/server/circuits/crypto/aes"
)

type cryptoProofCircuit struct {
	Authorization verifyCircuit
	Key           [32]frontend.Variable
	Nonce         [12]frontend.Variable `gnark:",public"`
	Plaintext     [17]frontend.Variable
	Ciphertext    [17]frontend.Variable `gnark:",public"`
}

func (c *cryptoProofCircuit) Define(api frontend.API) error {
	Verify(api, Inputs{PublicKey: c.Authorization.PublicKey, Signature: c.Authorization.Signature, Message: c.Authorization.Message})
	out := aesgadget.NewCipher(api, c.Key).CTREncrypt(c.Nonce, c.Plaintext[:])
	for i := range out {
		api.AssertIsEqual(out[i], c.Ciphertext[i])
	}
	return nil
}

func cryptoProofAssignment(t *testing.T) *cryptoProofCircuit {
	t.Helper()
	c := &cryptoProofCircuit{Authorization: *witnessFor(make([]byte, 32))}
	var key [32]byte
	var iv [16]byte
	plain := make([]byte, 17)
	for i := range key {
		key[i] = byte(i*17 + 1)
		c.Key[i] = key[i]
	}
	for i := range c.Nonce {
		iv[i] = byte(i*7 + 3)
		c.Nonce[i] = iv[i]
	}
	iv[15] = 2
	for i := range plain {
		plain[i] = byte(i*13 + 5)
		c.Plaintext[i] = plain[i]
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCTR(block, iv[:]).XORKeyStream(plain, plain)
	for i := range plain {
		c.Ciphertext[i] = plain[i]
	}
	return c
}

// A new process must reconstruct all commitment and hint registrations from
// imports. Public-input tampering must fail after the serialized proof reload.
func TestCryptoProofFreshProcess(t *testing.T) {
	const env = "ZOLANA_GADGET_PROOF_FIXTURE"
	if dir := os.Getenv(env); dir != "" {
		verifySerializedCryptoProof(t, dir)
		return
	}
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &cryptoProofCircuit{Authorization: verifyCircuit{Message: make([]frontend.Variable, 32)}})
	if err != nil {
		t.Fatal(err)
	}
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		t.Fatal(err)
	}
	w, err := frontend.NewWitness(cryptoProofAssignment(t), ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for name, value := range map[string]io.WriterTo{"circuit": cs, "proving-key": pk, "verifying-key": vk, "witness": w} {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := value.WriteTo(f)
		closeErr := f.Close()
		if writeErr != nil {
			t.Fatal(writeErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCryptoProofFreshProcess$", "-test.v")
	cmd.Env = append(os.Environ(), env+"="+dir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fresh-process prove/verify: %v\n%s", err, out)
	}
}

func verifySerializedCryptoProof(t *testing.T, dir string) {
	t.Helper()
	cs := groth16.NewCS(ecc.BN254)
	pk, vk := groth16.NewProvingKey(ecc.BN254), groth16.NewVerifyingKey(ecc.BN254)
	full, err := witness.New(ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]io.ReaderFrom{"circuit": cs, "proving-key": pk, "verifying-key": vk, "witness": full} {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := value.ReadFrom(f)
		closeErr := f.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if closeErr != nil {
			t.Fatal(closeErr)
		}
	}
	proof, err := groth16.Prove(cs, pk, full)
	if err != nil {
		t.Fatal(err)
	}
	var encoded bytes.Buffer
	if _, err := proof.WriteTo(&encoded); err != nil {
		t.Fatal(err)
	}
	proof = groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(&encoded); err != nil {
		t.Fatal(err)
	}
	public, err := full.Public()
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof, vk, public); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*cryptoProofCircuit){
		func(c *cryptoProofCircuit) { c.Authorization.Message[0] = 1 },
		func(c *cryptoProofCircuit) { c.Authorization.PublicKey[0] = c.Authorization.PublicKey[0].(byte) ^ 1 },
		func(c *cryptoProofCircuit) { c.Ciphertext[16] = c.Ciphertext[16].(byte) ^ 1 },
	} {
		c := cryptoProofAssignment(t)
		mutate(c)
		changed, err := frontend.NewWitness(c, ecc.BN254.ScalarField(), frontend.PublicOnly())
		if err != nil {
			t.Fatal(err)
		}
		if groth16.Verify(proof, vk, changed) == nil {
			t.Fatal("altered public statement accepted")
		}
	}
}
