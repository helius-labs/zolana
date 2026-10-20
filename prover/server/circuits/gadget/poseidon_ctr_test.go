package gadget

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/helius-labs/zolana/prover/server/prover-test/poseidon"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

const testPoseidonCtrDomain uint32 = 0x54504354 // "TPCT"

type poseidonCtrCircuit struct {
	Key       frontend.Variable
	Nonce     frontend.Variable `gnark:",public"`
	Plaintext []frontend.Variable
	Published []frontend.Variable `gnark:",public"`
}

func (c *poseidonCtrCircuit) Define(api frontend.API) error {
	ctr := PoseidonCtr{Domain: testPoseidonCtrDomain, Key: c.Key, Nonce: c.Nonce}
	return assertEncrypted(api, ctr, c.Plaintext, c.Published)
}

// assertEncrypted constrains every published element to ctr.Encrypt(plaintext).
func assertEncrypted(api frontend.API, ctr PoseidonCtr, plaintext, published []frontend.Variable) error {
	if len(plaintext) != len(published) {
		return fmt.Errorf("poseidon ctr: %d plaintext elements, %d published", len(plaintext), len(published))
	}
	for i, ciphertext := range ctr.Encrypt(api, plaintext) {
		api.AssertIsEqual(published[i], ciphertext)
	}
	return nil
}

func hostPoseidonCtr(key, nonce *big.Int, plaintext []*big.Int) ([]*big.Int, error) {
	ciphertext := make([]*big.Int, len(plaintext))
	for i, element := range plaintext {
		pad, err := poseidon.Hash([]*big.Int{
			big.NewInt(int64(testPoseidonCtrDomain)), key, nonce, big.NewInt(int64(i)),
		})
		if err != nil {
			return nil, err
		}
		ciphertext[i] = new(big.Int).Mod(new(big.Int).Add(element, pad), ecc.BN254.ScalarField())
	}
	return ciphertext, nil
}

func poseidonCtrAssignment(key, nonce *big.Int, plaintext, published []*big.Int) *poseidonCtrCircuit {
	assignment := &poseidonCtrCircuit{
		Key:       key,
		Nonce:     nonce,
		Plaintext: make([]frontend.Variable, len(plaintext)),
		Published: make([]frontend.Variable, len(published)),
	}
	for i, element := range plaintext {
		assignment.Plaintext[i] = element
	}
	for i, element := range published {
		assignment.Published[i] = element
	}
	return assignment
}

func TestPoseidonCtrMatchesHost(t *testing.T) {
	key := big.NewInt(0x5ec2e7)
	nonce := big.NewInt(0x4e04ce)
	plaintext := []*big.Int{big.NewInt(1_000_000), big.NewInt(7), new(big.Int).Sub(ecc.BN254.ScalarField(), big.NewInt(1))}
	published, err := hostPoseidonCtr(key, nonce, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	circuit := &poseidonCtrCircuit{Plaintext: make([]frontend.Variable, len(plaintext)), Published: make([]frontend.Variable, len(plaintext))}
	if err := test.IsSolved(circuit, poseidonCtrAssignment(key, nonce, plaintext, published), ecc.BN254.ScalarField()); err != nil {
		t.Fatalf("circuit differs from host: %v", err)
	}
}

func TestPoseidonCtrRejectsAnotherNonceAndASwappedIndex(t *testing.T) {
	key := big.NewInt(0x5ec2e7)
	nonce := big.NewInt(0x4e04ce)
	plaintext := []*big.Int{big.NewInt(3), big.NewInt(5)}
	published, err := hostPoseidonCtr(key, nonce, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	circuit := &poseidonCtrCircuit{Plaintext: make([]frontend.Variable, len(plaintext)), Published: make([]frontend.Variable, len(plaintext))}

	otherNonce := big.NewInt(0x4e04cf)
	if err := test.IsSolved(circuit, poseidonCtrAssignment(key, otherNonce, plaintext, published), ecc.BN254.ScalarField()); err == nil {
		t.Fatal("a ciphertext decrypted under another nonce")
	}

	swapped := []*big.Int{published[1], published[0]}
	swappedPlaintext := []*big.Int{plaintext[1], plaintext[0]}
	if err := test.IsSolved(circuit, poseidonCtrAssignment(key, nonce, swappedPlaintext, swapped), ecc.BN254.ScalarField()); err == nil {
		t.Fatal("pads did not depend on the index")
	}
}

type mismatchedPoseidonCtrCircuit struct {
	Key, Nonce frontend.Variable
	Plaintext  [2]frontend.Variable
	Published  [1]frontend.Variable
}

func (c *mismatchedPoseidonCtrCircuit) Define(api frontend.API) error {
	ctr := PoseidonCtr{Domain: testPoseidonCtrDomain, Key: c.Key, Nonce: c.Nonce}
	return assertEncrypted(api, ctr, c.Plaintext[:], c.Published[:])
}

func TestPoseidonCtrRejectsALengthMismatchAtCompileTime(t *testing.T) {
	if err := test.IsSolved(&mismatchedPoseidonCtrCircuit{}, &mismatchedPoseidonCtrCircuit{Key: 1, Nonce: 2, Plaintext: [2]frontend.Variable{3, 4}, Published: [1]frontend.Variable{5}}, ecc.BN254.ScalarField()); err == nil {
		t.Fatal("a length mismatch compiled")
	}
}
